/*
 *
 * Copyright (c) 2026 SearchLight Ltd, New Zealand.
 * All rights reserved.
 *
 * This file is part of OpenLI.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * OpenLI is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * OpenLI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * This code has been written with the assistance of Sonnet 4.5, but with
 * extensive curation and modification to suit the OpenLI software
 * framework.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <yaml.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include "logger.h"
#include "util.h"
#include "yaml_modifier.h"

#define OPENLI_YAML_MAX_LINE 1024
#define OPENLI_YAML_MAX_KEY_LENGTH 512
#define OPENLI_YAML_MAX_PATH_DEPTH 10

#define WRITE_QUOTED_VALUE(fout, value) \
    fprintf(fout, " \"%s\"\n", value);

#define WRITE_UNQUOTED_VALUE(fout, value) \
    fprintf(fout, " %s\n", value);


typedef struct {
    char path[OPENLI_YAML_MAX_PATH_DEPTH][OPENLI_YAML_MAX_KEY_LENGTH];
    int depth;
    int indents[OPENLI_YAML_MAX_PATH_DEPTH];
    bool in_array[OPENLI_YAML_MAX_PATH_DEPTH];
    int array_index[OPENLI_YAML_MAX_PATH_DEPTH];
} openli_yaml_context_t;

typedef struct {
    char key_path[OPENLI_YAML_MAX_KEY_LENGTH];
    int indent;
    uint32_t filepos;
    uint32_t tentative_pos;
    bool is_string;
    bool just_marked;
} openli_yaml_array_append_t;

typedef struct {
    char parent_path[OPENLI_YAML_MAX_KEY_LENGTH];
    char key[OPENLI_YAML_MAX_KEY_LENGTH];
    int indent;
    long filepos;
} openli_yaml_key_insert_t;

typedef struct {
    char *path;
    int indent;
    long last_child_pos;
} openli_yaml_section_t;

static void write_indent(FILE *fout, int depth) {
    int i;
    for (i = 0; i < depth; i++) {
        fputs("  ", fout);
    }
}

static void parse_key_path(const char *key_path, char *parent, char *key) {
    const char *last_dot = strrchr(key_path, '.');

    if (last_dot) {
        size_t plen = last_dot - key_path;
        snprintf(parent, plen + 1, "%s", key_path);
        parent[plen] = '\0';
        strcpy(key, last_dot + 1);
    } else {
        parent[0] = '\0';
        strcpy(key, key_path);
    }
}

static void pop_context_as_needed(openli_yaml_context_t *ctx, int indent,
        bool is_array_item) {
    while (ctx->depth > 0) {
        if (indent < ctx->indents[ctx->depth - 1]) {
            ctx->depth --;
        } else if (indent == ctx->indents[ctx->depth - 1]) {
            if (is_array_item && ctx->in_array[ctx->depth - 1]) {
                break;
            }
            ctx->depth--;
        } else {
            break;
        }
    }
}

static bool parse_array_syntax(const char *path, char *base, int *index,
        char *remainder) {
    const char *bracket = strchr(path, '[');
    size_t base_len;
    const char *close, *index_str;
    char *endptr;

    if (!bracket) {
        return false;
    }
    base_len = bracket - path;
    snprintf(base, base_len + 1, "%s", path);
    base[base_len] = '\0';

    close = strchr(bracket, ']');
    if (!close) {
        logger(LOG_INFO, "OpenLI: bad configuration key when trying to update file on disk: %s", path);
        return false;
    }
    index_str = bracket + 1;
    while (isspace((unsigned char)*index_str)) {
        index_str ++;
    }
    if (index_str >= close) {
        logger(LOG_INFO, "OpenLI: empty array index when parsing configuration key: %s", path);
        return false;
    }

    *index = (int)strtoul(index_str, &endptr, 10);
    if (endptr == index_str) {
        logger(LOG_INFO, "OpenLI: invalid array index when parsing configuration key: %s", path);
        return false;
    }

    while (endptr < close && isspace((unsigned char)*endptr)) {
        endptr ++;
    }

    if (endptr != close) {
        logger(LOG_INFO, "OpenLI: invalid characters in array index when parsing configuration key: %s", path);
        return false;
    }

    if (*(close + 1) == '.') {
        strcpy(remainder, close + 2);
    } else if (*(close + 1) == '\0') {
        remainder[0] = '\0';
    } else {
        logger(LOG_INFO, "OpenLI: invalid syntax after ']' in configuration key: %s", path);
        return false;
    }
    return true;
}

static inline int get_indent(const char *line) {
    int indent = 0;
    while (line[indent] == ' ') {
        indent ++;
    }
    return indent;
}

static bool is_array_item(const char *line) {
    const char *p = ltrim((char *)line);
    if (strlen(p) < 2) {
        return false;
    }
    if (p[0] == '-' && p[1] == ' ') {
        return true;
    }
    if (p[0] == '-' && p[1] == '\0') {
        return true;
    }
    return false;
}

static bool extract_key(const char *line, char *key_buf, size_t buf_size) {
    const char *p, *colon;
    size_t key_len;

    p = ltrim((char *)line);
    if (*p == '#' || *p == '\0' || *p == '-') {
        return false;
    }

    colon = strchr(p, ':');
    if (!colon) {
        return false;
    }
    key_len = colon - p;
    if (key_len >= buf_size) {
        return false;
    }
    snprintf(key_buf, key_len + 1, "%s", p);
    key_buf[key_len] = '\0';
    rtrim(key_buf);
    return true;
}

static void get_value_from_line(const char *line, char *value, size_t size) {
    const char *colon = strchr(line, ':');
    const char *p;
    size_t i = 0;

    if (!colon) {
        value[0] = '\0';
        return;
    }
    p = colon + 1;
    while (isspace((unsigned char)*p)) {
        p++;
    }

    if (*p == '"' || *p == '\'') {
        char quote = *p;
        p++;
        while (*p && *p != quote && i < size - 1) {
            value[i] = *p;
            i++; p++;
        }
        value[i] = '\0';
    } else {
        snprintf(value, size, "%s", p);
        rtrim(value);
    }
}

static void get_scalar_line_value(const char *line, char *value, size_t size) {
    const char *p = ltrim((char *)line);
    size_t i = 0;

    if (p[0] == '-') {
        p++;
        while (isspace((unsigned char)*p)) {
            p++;
        }
    }

    if (*p == '"' || *p == '\'') {
        char quote = *p;
        p++;
        while (*p && *p != quote && i < size - 1) {
            value[i] = *p;
            i++; p++;
        }
        value[i] = '\0';
    } else {
        while (*p && *p != '#' && *p != '\n' && *p != '\r' && i < size - 1) {
            value[i] = *p;
            i++; p++;
        }
        value[i] = '\0';
        rtrim(value);
    }
}

static bool has_value(const char *line) {
    const char *colon, *p;

    colon = strchr(line, ':');
    if (!colon) {
        return false;
    }
    p = colon + 1;
    while (isspace((unsigned char)*p)) {
        p++;
    }
    if (*p == '\0' || *p == '#') {
        return false;
    }
    return true;
}

static void build_path(openli_yaml_context_t *ctx, char *path_buf,
        size_t buf_size, bool include_leaf) {
    int i;

    path_buf[0] = '\0';
    for (i = 0; i < ctx->depth; i++) {
        if (i > 0) {
            strncat(path_buf, ".", buf_size - strlen(path_buf) - 1);
        }
        strncat(path_buf, ctx->path[i], buf_size - strlen(path_buf) - 1);
        if (ctx->in_array[i] && ctx->array_index[i] >= 0) {
            if (include_leaf || i < ctx->depth - 1) {
                char idx[32];
                snprintf(idx, 32, "[%d]", ctx->array_index[i]);
                strncat(path_buf, idx, buf_size - strlen(path_buf) - 1);
            }
        }
    }
}

static void update_context(openli_yaml_context_t *ctx, const char *line,
        char *key, uint8_t is_array) {

    int indent = get_indent(line);

    if (!has_value(line) || is_array) {
        if (ctx->depth < OPENLI_YAML_MAX_PATH_DEPTH) {
            snprintf(ctx->path[ctx->depth], OPENLI_YAML_MAX_KEY_LENGTH, "%s",
                    key);
            ctx->indents[ctx->depth] = indent;
            ctx->in_array[ctx->depth] = is_array;
            ctx->array_index[ctx->depth] = is_array ? -1 : 0;
            ctx->depth ++;
        }
    }
}

static bool path_matches(const char *current_path, const char *key,
        const char *target_path) {

    char full_path[OPENLI_YAML_MAX_KEY_LENGTH * 2];
    if (current_path[0] != '\0') {
        snprintf(full_path, sizeof(full_path), "%s.%s", current_path, key);
    } else {
        snprintf(full_path, sizeof(full_path), "%s", key);
    }
    return (strcmp(full_path, target_path) == 0);
}

static void check_for_appendable_array_end(const char *line,
        long current_out_pos,
        openli_yaml_array_append_t *append_arrays, size_t append_count) {

    size_t i;

    for (i = 0; i < append_count; i++) {
        char *trimmed;
        if (append_arrays[i].filepos != 0) {
            continue;
        }
        if (append_arrays[i].just_marked) {
            append_arrays[i].just_marked = false;
            continue;
        }

        if (is_array_item(line)) {
            append_arrays[i].tentative_pos = 0;
            continue;
        }
        trimmed = ltrim((char *)line);
        if (trimmed[0] == '\0' || trimmed[0] == '#') {
            // possible end point for the sequence, but can't be sure yet
            // until we see what is coming up next because this might be
            // a comment or blank line belonging to the current sequence
            if (get_indent(line) <= append_arrays[i].indent &&
                    append_arrays[i].tentative_pos == 0) {
                append_arrays[i].tentative_pos = current_out_pos;
            }
            continue;
        }
        if (get_indent(line) <= append_arrays[i].indent) {
            if (append_arrays[i].tentative_pos != 0) {
                // rewind to the oldest blank line / comment
                append_arrays[i].filepos = append_arrays[i].tentative_pos;
            } else {
                append_arrays[i].filepos = current_out_pos;
            }
        } else {
            // still inside the current item
            append_arrays[i].tentative_pos = 0;
        }
    }
}

static void append_array_object(FILE *fout, openli_yaml_config_update_t *update,
        int base_indent) {

    size_t i, j;
    openli_yaml_config_object_field_t field;

    for (i = 0; i < update->array_objects_count; i++) {
        fprintf(fout, "%*s- ", base_indent, "");
        if (update->array_objects[i].field_count == 0) {
            fprintf(fout, "\n");
            continue;
        }

        // first field must be in line with the dash
        field = update->array_objects[i].fields[0];
        fprintf(fout, "%s:", field.key);
        if (field.is_string) {
            WRITE_QUOTED_VALUE(fout, field.value);
        } else {
            WRITE_UNQUOTED_VALUE(fout, field.value);
        }

        // remaining fields need the extra indentation
        for (j = 1; j < update->array_objects[i].field_count; j++) {
            field = update->array_objects[i].fields[j];
            fprintf(fout, "%*s%s:", base_indent + 2, "", field.key);
            if (field.is_string) {
                WRITE_QUOTED_VALUE(fout, field.value);
            } else {
                WRITE_UNQUOTED_VALUE(fout, field.value);
            }
        }
    }

}

static void calculate_key_insertions(openli_yaml_config_update_t *updates,
        size_t update_count, openli_yaml_key_insert_t *insert_keys,
        size_t *insert_count, openli_yaml_section_t *sections,
        size_t section_count, bool *found, long file_end_pos) {

    size_t i, j;
    int target_indent = 0;
    char parent_path[OPENLI_YAML_MAX_KEY_LENGTH - 1];
    char key_name[OPENLI_YAML_MAX_KEY_LENGTH - 1];
    long insert_pos = -1;

    for (i = 0; i < update_count; i++) {
        if (found[i]) {
            continue;
        }
        if (!updates[i].create_if_missing) {
            continue;
        }
        if (updates[i].type != UPDATE_SCALAR &&
                updates[i].type != UPDATE_ARRAY_ALL &&
                updates[i].type != UPDATE_ARRAY_APPEND) {
            continue;
        }

        parse_key_path(updates[i].key_path, parent_path, key_name);
        if (parent_path[0] == '\0') {
            // top level, append to the end of the file
            insert_pos = file_end_pos;
            target_indent = 0;
        } else {
            for (j = 0; j < section_count; j++) {
                if (strcmp(sections[j].path, parent_path) == 0) {
                    insert_pos = sections[j].last_child_pos;
                    target_indent = sections[j].indent + 2;
                    break;
                }
            }
            if (insert_pos < 0) {
                // couldn't find the matching section?
                continue;
            }
        }

        snprintf(insert_keys[*insert_count].parent_path,
                OPENLI_YAML_MAX_KEY_LENGTH, "%s", parent_path);
        snprintf(insert_keys[*insert_count].key, OPENLI_YAML_MAX_KEY_LENGTH,
                "%s", key_name);
        insert_keys[*insert_count].indent = target_indent;
        insert_keys[*insert_count].filepos = insert_pos;
        (*insert_count)++;
        found[i] = true;
    }
}

static void write_new_key(FILE *fout, const char *key, int base_indent,
        openli_yaml_config_update_t *update) {
    size_t k;

    if (update->type == UPDATE_SCALAR) {
        fprintf(fout, "%*s%s:", base_indent, "", key);
        if (update->is_string) {
            WRITE_QUOTED_VALUE(fout, update->value);
        } else {
            WRITE_UNQUOTED_VALUE(fout, update->value);
        }
    } else if (update->type == UPDATE_ARRAY_ALL ||
            (update->type == UPDATE_ARRAY_APPEND &&
             update->array_objects_count == 0)) {
        fprintf(fout, "%*s%s:\n", base_indent, "", key);
        for (k = 0; k < update->array_count; k++) {
            fprintf(fout, "%*s-", base_indent + 2, "");

            if (update->is_string) {
                WRITE_QUOTED_VALUE(fout, update->array_values[k]);
            } else {
                WRITE_UNQUOTED_VALUE(fout, update->array_values[k]);
            }
        }
    } else if (update->type == UPDATE_ARRAY_APPEND) {
        fprintf(fout, "%*s%s:\n", base_indent, "", key);
        append_array_object(fout, update, base_indent);
    }
}

static int apply_key_insertions(const char *tmpfile,
        openli_yaml_key_insert_t *insert_keys, size_t insert_count,
        openli_yaml_config_update_t *updates, size_t update_count) {

    FILE *temp_in, *temp_out;
    char line[OPENLI_YAML_MAX_LINE];
    char tmpfile2[768];
    long current_pos = 0;
    size_t i, j;
    int base_indent;
    char parent[OPENLI_YAML_MAX_KEY_LENGTH];
    char key[OPENLI_YAML_MAX_KEY_LENGTH];
    size_t ins_remaining;

    if (insert_count == 0) {
        return 0;
    }

    /* This is a bit clunky and ugly, but it should hopefully do the job.
     *
     * Our main goal here is essentially go through our "draft" modified
     * config (which already has all of the non-inserting updates applied)
     * and now insert the new keys at the locations we found when we walked
     * through the first time around.
     */
    temp_in = fopen(tmpfile, "r");
    if (!temp_in) {
        logger(LOG_INFO,
                "OpenLI: unable to reopen draft file for updated configuration: %s",
                strerror(errno));
        return -1;
    }
    snprintf(tmpfile2, 768, "%s2", tmpfile);
    temp_out = fopen(tmpfile2, "w");
    if (!temp_out) {
        logger(LOG_INFO,
                "OpenLI: unable to create secondary temp file for generating updated configuration: %s",
                strerror(errno));
        fclose(temp_in);
        return -1;
    }

    ins_remaining = insert_count;
    while (fgets(line, OPENLI_YAML_MAX_LINE, temp_in)) {
        for (i = 0; i < insert_count; i++) {
            if (insert_keys[i].filepos <= 0) {
                continue;
            }
            if (current_pos != insert_keys[i].filepos) {
                continue;
            }
            for (j = 0; j < update_count; j++) {
                parse_key_path(updates[j].key_path, parent, key);
                if (strcmp(insert_keys[i].parent_path, parent) != 0) {
                    continue;
                }
                if (strcmp(insert_keys[i].key, key) != 0) {
                    continue;
                }
                base_indent = insert_keys[i].indent;
                write_new_key(temp_out, key, base_indent, &(updates[j]));
                break;
            }
            insert_keys[i].filepos = -1;
            ins_remaining --;
        }
        fputs(line, temp_out);
        current_pos = ftell(temp_in);
    }

    fclose(temp_in);
    fclose(temp_out);

    if (ins_remaining > 0) {
        // handle the leftover insertions that must go at the end of the file
        temp_out = fopen(tmpfile2, "a");
        if (!temp_out) {
            logger(LOG_INFO,
                    "OpenLI: unable to create secondary temp file for generating updated configuration: %s",
                    strerror(errno));
            remove(tmpfile);
            remove(tmpfile2);
            return -1;
        }

        for (i = 0; i < insert_count; i++) {
            if (insert_keys[i].filepos <= 0) {
                continue;
            }
            for (j = 0; j < update_count; j++) {
                parse_key_path(updates[j].key_path, parent, key);
                if (strcmp(insert_keys[i].parent_path, parent) != 0) {
                    continue;
                }
                if (strcmp(insert_keys[i].key, key) != 0) {
                    continue;
                }
                base_indent = insert_keys[i].indent;
                write_new_key(temp_out, key, base_indent, &(updates[j]));
                insert_keys[i].filepos = -1;
            }
        }
        fclose(temp_out);
    }

    remove(tmpfile);
    rename(tmpfile2, tmpfile);
    return 0;

}

static int _apply_array_appends(openli_yaml_array_append_t *append_arrays,
        size_t append_count, openli_yaml_config_update_t *updates,
        size_t update_count, FILE *fout, long current_pos, bool *found) {

    size_t i, j, k;
    char *val;
    int base_indent;

    for (i = 0; i < append_count; i++) {
        if (append_arrays[i].filepos <= 0) {
            continue;
        }
        if (current_pos != (long)append_arrays[i].filepos) {
            continue;
        }
        for (j = 0; j < update_count; j++) {
            if (updates[j].type != UPDATE_ARRAY_APPEND) {
                continue;
            }
            if (strcmp(updates[j].key_path, append_arrays[i].key_path)) {
                continue;
            }
            base_indent = append_arrays[i].indent + 2;
            if (updates[j].array_objects_count == 0) {
                // just appending simple values
                for (k = 0; k < updates[j].array_count; k++) {
                    val = updates[j].array_values[k];
                    fprintf(fout, "%*s-", base_indent, "");
                    if (updates[j].is_string) {
                        WRITE_QUOTED_VALUE(fout, val);
                    } else {
                        WRITE_UNQUOTED_VALUE(fout, val);
                    }
                }
            } else {
                append_array_object(fout, &(updates[j]), base_indent);
            }
            found[j] = true;
            break;
        }
        append_arrays[i].filepos = -1;  // mark as completed
    }
    return 0;
}

static int apply_array_appends(const char *tmpfile,
        openli_yaml_array_append_t *append_arrays, size_t append_count,
        openli_yaml_config_update_t *updates, size_t update_count,
        bool *found) {

    FILE *temp_in, *temp_out;
    char line[OPENLI_YAML_MAX_LINE];
    char tmpfile2[768];
    long current_pos = 0;

    if (append_count == 0) {
        return 0;
    }

    /* This is a bit clunky and ugly, but it should hopefully do the job.
     *
     * Our main goal here is essentially go through our "draft" modified
     * config (which already has all of the non-appending updates applied)
     * and now insert the appends at the locations we found when we walked
     * through the first time around.
     */
    temp_in = fopen(tmpfile, "r");
    if (!temp_in) {
        logger(LOG_INFO,
                "OpenLI: unable to reopen draft file for updated configuration: %s",
                strerror(errno));
        return -1;
    }
    snprintf(tmpfile2, 768, "%s2", tmpfile);
    temp_out = fopen(tmpfile2, "w");
    if (!temp_out) {
        logger(LOG_INFO,
                "OpenLI: unable to create secondary temp file for generating updated configuration: %s",
                strerror(errno));
        fclose(temp_in);
        return -1;
    }

    while (fgets(line, OPENLI_YAML_MAX_LINE, temp_in)) {
        _apply_array_appends(append_arrays, append_count, updates, update_count,
                temp_out, current_pos, found);

        fputs(line, temp_out);
        current_pos = ftell(temp_in);
    }

    // handle any appends that occur at the end of the file
    _apply_array_appends(append_arrays, append_count, updates, update_count,
            temp_out, current_pos, found);

    fclose(temp_in);
    fclose(temp_out);

    remove(tmpfile);
    rename(tmpfile2, tmpfile);
    return 0;
}

static bool handle_array_object_field_update(openli_yaml_context_t *ctx,
        const char *line, const char *current_path, const char *item_key,
        openli_yaml_config_update_t *update, FILE *fout) {

    char base[OPENLI_YAML_MAX_KEY_LENGTH];
    char remainder[OPENLI_YAML_MAX_KEY_LENGTH];
    int target_index;
    char target_path[OPENLI_YAML_MAX_KEY_LENGTH * 2 + 16];
    char full_path[OPENLI_YAML_MAX_KEY_LENGTH * 3];
    const char *item_start, *colon;

    if (!parse_array_syntax(update->key_path, base, &target_index, remainder)) {
        return false;
    }

    if (remainder[0] == '\0') {
        return false;
    }

    snprintf(target_path, sizeof(target_path), "%s[%d].%s", base,
            target_index, remainder);
    snprintf(full_path, sizeof(full_path), "%s.%s", current_path, item_key);

    if (strcmp(full_path, target_path) != 0) {
        return false;
    }
    item_start = strchr(line, '-') + 1;
    colon = strchr(item_start, ':');
    if (!colon) {
        return false;
    }
    write_indent(fout, ctx->depth);
    fprintf(fout, "- %s:", item_key);
    if (update->is_string) {
        WRITE_QUOTED_VALUE(fout, update->value);
    } else {
        WRITE_UNQUOTED_VALUE(fout, update->value);
    }
    return true;
}

static bool handle_simple_array_item_update(openli_yaml_context_t *ctx,
        const char *current_path, openli_yaml_config_update_t *update,
        FILE *fout) {

    char base[OPENLI_YAML_MAX_KEY_LENGTH];
    char remainder[OPENLI_YAML_MAX_KEY_LENGTH];
    int target_index;
    char target_path[OPENLI_YAML_MAX_KEY_LENGTH * 2 + 16];

    if (!parse_array_syntax(update->key_path, base, &target_index, remainder)) {
        return false;
    }

    if (remainder[0] != '\0') {
        return false;
    }

    snprintf(target_path, sizeof(target_path), "%s[%d]", base, target_index);

    if (strcmp(current_path, target_path) != 0) {
        return false;
    }
    write_indent(fout, ctx->depth);
    fprintf(fout, "-");
    if (update->is_string) {
        WRITE_QUOTED_VALUE(fout, update->value);
    } else {
        WRITE_UNQUOTED_VALUE(fout, update->value);
    }
    return true;
}

static bool handle_array_replacement(openli_yaml_context_t *ctx,
        const char *line, const char *current_path,
        const char *key, openli_yaml_config_update_t *update, FILE *fout,
        bool *in_replaced_array, int *replaced_array_indent) {

    int indent;
    size_t j;

    if (!path_matches(current_path, key, update->key_path)) {
        return false;
    }

    indent = get_indent(line);
    write_indent(fout, ctx->depth);
    fprintf(fout, "%s:\n", key);

    for (j = 0; j < update->array_count; j++) {
        write_indent(fout, ctx->depth + 1);
        fprintf(fout, "-");
        if (update->is_string) {
            WRITE_QUOTED_VALUE(fout, update->array_values[j]);
        } else {
            WRITE_UNQUOTED_VALUE(fout, update->array_values[j]);
        }
    }
    *in_replaced_array = true;
    *replaced_array_indent = indent;
    return true;
}

static bool handle_array_append_marking(const char *current_path,
        const char *key, int indent, openli_yaml_config_update_t *update,
        openli_yaml_array_append_t *append_arrays,
        size_t *append_count) {

    if (!path_matches(current_path, key, update->key_path)) {
        return false;
    }

    snprintf(append_arrays[*append_count].key_path,
            OPENLI_YAML_MAX_KEY_LENGTH, "%s", update->key_path);
    append_arrays[*append_count].indent = indent;
    append_arrays[*append_count].is_string = update->is_string;
    append_arrays[*append_count].just_marked = true;
    append_arrays[*append_count].filepos = 0;
    append_arrays[*append_count].tentative_pos = 0;
    (*append_count)++;
    return true;
}

static bool handle_scalar_update(openli_yaml_context_t *ctx,
        const char *line, const char *current_path,
        const char *key, openli_yaml_config_update_t *update, FILE *fout) {

    const char *colon;

    if (!path_matches(current_path, key, update->key_path)) {
        return false;
    }

    colon = strchr(line, ':');
    if (!colon) {
        return false;
    }

    write_indent(fout, ctx->depth);
    fprintf(fout, "%s:", key);
    if (update->is_string) {
        WRITE_QUOTED_VALUE(fout, update->value);
    } else {
        WRITE_UNQUOTED_VALUE(fout, update->value);
    }
    return true;
}

static bool update_regular_keyitem(openli_yaml_context_t *ctx,
        openli_yaml_config_update_t *updates, size_t update_count,
        char *line, FILE *fout, bool *found, char *key,
        bool *in_replaced_array, int *replaced_array_indent,
        openli_yaml_array_append_t *append_arrays,
        size_t *append_count) {

    size_t i;
    bool ret = false;
    char current_path[OPENLI_YAML_MAX_KEY_LENGTH * 2];

    build_path(ctx, current_path, sizeof(current_path), true);

    for (i = 0; i < update_count; i++) {
        if (ret == true) {
            break;
        }
        if (found[i]) {
            continue;
        }
        switch(updates[i].type) {
            case UPDATE_ARRAY_ALL:
                if (handle_array_replacement(ctx, line, current_path, key,
                        &updates[i], fout, in_replaced_array,
                        replaced_array_indent)) {
                    found[i] = true;
                    ret = true;
                }
                break;
            case UPDATE_ARRAY_APPEND:
                if (handle_array_append_marking(current_path, key,
                        ctx->depth * 2,
                        &updates[i], append_arrays, append_count)) {
                    // don't set ret to true, just marking this for later
                    found[i] = true;
                }
                break;
            case UPDATE_SCALAR:
            case UPDATE_ARRAY_INDEX:
                if (handle_scalar_update(ctx, line, current_path, key,
                        &updates[i], fout)) {
                    found[i] = true;
                    ret = true;
                }
                break;
            case UPDATE_ARRAY_REMOVE:
            case UPDATE_ARRAY_REMOVE_SCALAR:
                break;
        }
    }
    return ret;
}


static bool update_array_item(openli_yaml_context_t *ctx,
        openli_yaml_config_update_t *updates, size_t update_count,
        char *line, FILE *fout, bool *found) {

    const char *item_start = strchr(line, '-') + 1;
    char item_key[OPENLI_YAML_MAX_KEY_LENGTH] = "";
    size_t i;
    bool ret = false;
    char current_path[OPENLI_YAML_MAX_KEY_LENGTH * 2];

    build_path(ctx, current_path, sizeof(current_path), true);
    if (extract_key(item_start, item_key, OPENLI_YAML_MAX_KEY_LENGTH)) {
        // deal with individual array element updates
        for (i = 0; i < update_count; i++) {
            if (found[i]) {
                continue;
            }
            if (updates[i].type != UPDATE_ARRAY_INDEX) {
                continue;
            }
            if (handle_array_object_field_update(ctx, line, current_path,
                    item_key, &(updates[i]), fout)) {
                found[i] = true;
                ret = true;
                break;
            }
        }
    } else {
        // standalone array item without key
        for (i = 0; i < update_count; i++) {
            if (found[i]) {
                continue;
            }
            if (updates[i].type != UPDATE_ARRAY_INDEX) {
                continue;
            }
            if (handle_simple_array_item_update(ctx, current_path,
                    &(updates[i]), fout)) {
                found[i] = true;
                ret = true;
                break;
            }
        }
    }
    return ret;
}

static bool validate_yaml(const char *filename) {
    yaml_parser_t parser;
    yaml_event_t event;
    bool valid = true;
    FILE *f = fopen(filename, "r");

    if (!f) return false;

    if (!yaml_parser_initialize(&parser)) {
        fclose(f);
        return false;
    }

    yaml_parser_set_input_file(&parser, f);

    do {
        if (!yaml_parser_parse(&parser, &event)) {
            logger(LOG_INFO, "Failed to generate valid YAML after updating configuration: %s", parser.problem);
            valid = false;
            break;
        }

        if (event.type == YAML_STREAM_END_EVENT) {
            yaml_event_delete(&event);
            break;
        }

        yaml_event_delete(&event);
    } while (1);

    yaml_parser_delete(&parser);
    fclose(f);

    return valid;
}

static void update_section_positions(openli_yaml_section_t *sections,
        size_t section_count, const char *current_path, FILE *fout) {

    size_t i;
    size_t sec_len;

    for (i = 0; i < section_count; i++) {
        sec_len = strlen(sections[i].path);
        if (strncmp(current_path, sections[i].path, sec_len) == 0) {
            if (current_path[sec_len] == '.') {
                sections[i].last_child_pos = ftell(fout);
            } else if (current_path[sec_len] == '\0') {
                sections[i].last_child_pos = ftell(fout);
            }
        }
    }

}

static void track_new_observed_section(const char *current_path, int indent,
        openli_yaml_section_t *sections, size_t *section_count,
        const char *key) {

    size_t i, psize;
    char *full_path = NULL;

    if (*section_count >= OPENLI_YAML_MAX_PATH_DEPTH) {
        return;
    }

    for (i = 0; i < (*section_count); i++) {
        if (strcmp(sections[i].path, current_path) == 0) {
            return;
        }
    }

    psize = strlen(key) + strlen(current_path) + 2;
    full_path = malloc(psize);

    if (current_path[0] == '\0') {
        snprintf(full_path, psize, "%s", key);
    } else {
        snprintf(full_path, psize, "%s.%s", current_path, key);
    }

    sections[*section_count].path = full_path;
    sections[*section_count].indent = indent;
    sections[*section_count].last_child_pos = 0;
    (*section_count)++;

}

static bool check_for_removal_match(FILE *fin, const char *first_line,
        openli_yaml_context_t *ctx, openli_yaml_config_update_t *updates,
        size_t update_count, bool *found) {

    char current_path[OPENLI_YAML_MAX_KEY_LENGTH * 2];
    size_t i, j;
    long start_pos;
    char line[OPENLI_YAML_MAX_LINE];
    int init_indent = get_indent(first_line);
    bool matched = false, all_satisfied = true;
    const char *item_start;
    char key[OPENLI_YAML_MAX_KEY_LENGTH];
    bool *satisfied = NULL;
    char val[OPENLI_YAML_MAX_LINE];
    openli_yaml_config_object_t *obj;

    build_path(ctx, current_path, sizeof(current_path), false);
    for (i = 0; i < update_count; i++) {
        if (updates[i].type != UPDATE_ARRAY_REMOVE &&
                updates[i].type != UPDATE_ARRAY_REMOVE_SCALAR) {
            continue;
        }
        if (strcmp(current_path, updates[i].key_path) != 0) {
            continue;
        }

        if (updates[i].type == UPDATE_ARRAY_REMOVE_SCALAR) {
            get_scalar_line_value(first_line, val, sizeof(val));
            if (strcmp(val, updates[i].value) == 0) {
                found[i] = true;
                matched = true;
                break;
            }
            continue;
        }

        // Possible match for removing an entire object
        start_pos = ftell(fin);
        item_start = strchr(first_line, '-') + 1;
        satisfied = calloc(updates[i].array_objects[0].field_count,
                sizeof(bool));
        obj = &(updates[i].array_objects[0]);

        // Check the first line
        if (extract_key(item_start, key, sizeof(key))) {
            for (j = 0; j < obj->field_count; j++) {
                if (strcmp(key, obj->fields[j].key) != 0) {
                    continue;
                }
                if (!has_value(item_start)) {
                    continue;
                }
                get_value_from_line(item_start, val, sizeof(val));
                if (strcmp(val, obj->fields[j].value) == 0) {
                    satisfied[j] = true;
                }
            }
        }

        // Check the rest of the lines that define this object
        while (fgets(line, sizeof(line), fin)) {
            int indent = get_indent(line);
            if (indent > init_indent || (indent == init_indent &&
                        !is_array_item(line))) {
                if (!extract_key(line, key, sizeof(key))) {
                    continue;
                }
                for (j = 0; j < obj->field_count; j++) {
                    if (strcmp(key, obj->fields[j].key) != 0) {
                        continue;
                    }
                    get_value_from_line(line, val, sizeof(val));
                    if (strcmp(val, obj->fields[j].value) == 0) {
                        satisfied[j] = true;
                    }
                }
            } else {
                break;
            }
        }

        // Reset the read pointer back to where we started
        fseek(fin, start_pos, SEEK_SET);
        for (j = 0; j < obj->field_count; j++) {
            if (!satisfied[j]) {
                all_satisfied = false;
                break;
            }
        }
        free(satisfied);
        if (all_satisfied) {
            found[i] = true;
            matched = true;
            break;
        }
    }
    return matched;
}

int apply_yaml_config_updates(const char *filename,
        openli_yaml_config_pending_updates_t *updates) {

    FILE *fin = fopen(filename, "r");
    FILE *fout = NULL;
    char tmpfile[512];
    char line[OPENLI_YAML_MAX_LINE];
    openli_yaml_context_t ctx;
    long file_end_pos;
    bool *found;
    bool in_replaced_array = false;
    bool in_removed_item = false;
    int removed_item_indent = 0;
    int replaced_array_indent = 0;
    openli_yaml_array_append_t *append_arrays;
    openli_yaml_key_insert_t *insert_keys;
    openli_yaml_section_t *sections;
    size_t append_count = 0;
    size_t insert_count = 0;
    size_t section_count = 0;
    size_t i;
    struct stat st;

    memset(&ctx, 0, sizeof(openli_yaml_context_t));

    if (stat(filename, &st) != 0) {
        logger(LOG_INFO, "Failed to stat configuration file '%s' prior to updating: %s", filename, strerror(errno));
        return -1;
    }

    if (!fin) {
        logger(LOG_INFO, "Failed to open configuration file for updating: %s",
                strerror(errno));
        return -1;
    }

    snprintf(tmpfile, 512, "%s.tmp", filename);
    fout = fopen(tmpfile, "w");
    if (!fout) {
        logger(LOG_INFO,
                "Failed to open temporary configuration file for updating: %s",
                strerror(errno));
        return -1;
    }

    found = calloc(updates->update_count, sizeof(bool));
    append_arrays = calloc(updates->update_count,
            sizeof(openli_yaml_array_append_t));
    sections = calloc(OPENLI_YAML_MAX_PATH_DEPTH,
            sizeof(openli_yaml_section_t));
    insert_keys = calloc(updates->update_count,
            sizeof(openli_yaml_key_insert_t));

    while (fgets(line, OPENLI_YAML_MAX_LINE, fin)) {
        bool line_updated = false;
        char key[OPENLI_YAML_MAX_KEY_LENGTH];
        int indent = get_indent(line);
        long current_out_pos = ftell(fout);

        if (ltrim(line)[0] != '#' && ltrim(line)[0] != '\0') {
            pop_context_as_needed(&ctx, indent, is_array_item(line));
            if (is_array_item(line)) {
                if (ctx.depth > 0 && ctx.in_array[ctx.depth - 1]) {
                    ctx.array_index[ctx.depth - 1]++;
                }
            }
        }

        if (append_count > 0) {
            // check if an array has ended that we need to append to
            check_for_appendable_array_end(line, current_out_pos,
                    append_arrays, append_count);
        }

        if (in_removed_item) {
            // check if an object we are removing has ended
            if (indent > removed_item_indent ||
                    (indent == removed_item_indent && !is_array_item(line))) {
                continue;
            } else {
                in_removed_item = false;
            }
        }

        if (is_array_item(line) && ltrim(line)[0] != '#' &&
                ltrim(line)[0] != '\0') {
            // check if this array object should be removed
            if (check_for_removal_match(fin, line, &ctx, updates->updates,
                    updates->update_count, found)) {
                in_removed_item = true;
                removed_item_indent = indent;
                continue;
            }
        }

        if (in_replaced_array) {
            if (indent > replaced_array_indent || is_array_item(line)) {
                // skip because this is part of an array we're going to
                // replace
                continue;
            } else {
                // array has ended
                in_replaced_array = false;
            }
        }

        // preserve comments and empty lines
        if (ltrim(line)[0] == '#' || ltrim(line)[0] == '\0') {
            if (ltrim(line)[0] != '\0') {
                write_indent(fout, ctx.depth);
                fputs(ltrim(line), fout);
            } else {
                fprintf(fout, "\n");
            }
            line_updated = true;
        }

        if (is_array_item(line)) {
            line_updated = update_array_item(&ctx, updates->updates,
                    updates->update_count, line, fout, found);
        } else if (extract_key(line, key, OPENLI_YAML_MAX_KEY_LENGTH)) {
            char current_path[OPENLI_YAML_MAX_KEY_LENGTH * 2];
            build_path(&ctx, current_path, sizeof(current_path), true);

            if (!has_value(line)) {
                // this is a section
                track_new_observed_section(current_path, ctx.depth * 2,
                        sections,  &section_count, key);
            }

            update_section_positions(sections, section_count, current_path,
                    fout);

            line_updated = update_regular_keyitem(&ctx, updates->updates,
                    updates->update_count,
                    line, fout, found, key, &in_replaced_array,
                    &replaced_array_indent, append_arrays, &append_count);

        }

        if (!line_updated && !in_replaced_array) {
            if (ltrim(line)[0] != '\0') {
                // unchanged line, just write it back out
                write_indent(fout, ctx.depth);
                fputs(ltrim(line), fout);
                line_updated = true;

            } else {
                fprintf(fout, "\n");
                line_updated = true;
            }
        }

        if (is_array_item(line)) {
            if (!in_replaced_array) {
                if (ctx.depth < OPENLI_YAML_MAX_PATH_DEPTH) {
                    snprintf(ctx.path[ctx.depth], OPENLI_YAML_MAX_KEY_LENGTH,
                            "%s", "");
                    ctx.indents[ctx.depth] = indent;
                    ctx.in_array[ctx.depth] = false;
                    ctx.array_index[ctx.depth] = 0;
                    ctx.depth ++;
                }
            }
        } else if (extract_key(line, key, OPENLI_YAML_MAX_KEY_LENGTH)) {
            if (!line_updated || !has_value(line)) {
                bool next_is_array = false;
                long pos;
                char next_line[OPENLI_YAML_MAX_LINE];

                pos = ftell(fin);
                if (fgets(next_line, OPENLI_YAML_MAX_LINE, fin)) {
                    next_is_array = is_array_item(next_line);
                    fseek(fin, pos, SEEK_SET);
                }
                update_context(&ctx, line, key, next_is_array);
            }
        }
    }

    fclose(fin);
    file_end_pos = ftell(fout);
    fclose(fout);

    for (i = 0; i < append_count; i++) {
        if (append_arrays[i].filepos == 0) {
            if (append_arrays[i].tentative_pos != 0) {
                append_arrays[i].filepos = append_arrays[i].tentative_pos;
            } else {
                append_arrays[i].filepos = (uint32_t)file_end_pos;
            }
        }
    }

    calculate_key_insertions(updates->updates, updates->update_count,
            insert_keys,
            &insert_count, sections, section_count, found, file_end_pos);

    if (apply_key_insertions(tmpfile, insert_keys, insert_count,
            updates->updates, updates->update_count) < 0) {
        free(found);
        free(sections);
        free(insert_keys);
        free(append_arrays);
        remove(tmpfile);
        return -1;
    }

    if (apply_array_appends(tmpfile, append_arrays, append_count,
            updates->updates, updates->update_count, found) < 0) {
        free(found);
        free(sections);
        free(insert_keys);
        free(append_arrays);
        remove(tmpfile);
        return -1;
    }

    // check that we managed to perform all of the requested updates -- if not,
    // at least log a warning
    for (i = 0; i < updates->update_count; i++) {
        if (!found[i]) {
            logger(LOG_INFO,
                    "OpenLI: unable to update configuration for key '%s' as it was not already present in the config file and we were not instructed to add it",
                    updates->updates[i].key_path);
        }
    }

    for (i = 0; i < section_count; i++) {
        if (sections[i].path) {
            free(sections[i].path);
        }
    }

    free(found);
    free(sections);
    free(insert_keys);
    free(append_arrays);

    if (!validate_yaml(tmpfile)) {
        logger(LOG_INFO,
                "OpenLI: generated invalid YAML to replace configuration file '%s' -- changes will NOT persist", filename);
        //remove(tmpfile);
        return 0;
    }

    /* Try to preserve ownership and permissions from the original file */
    if (chown(tmpfile, st.st_uid, st.st_gid) != 0) {
        if (errno != EPERM) {
            logger(LOG_INFO,
                    "OpenLI: error while setting ownership on replacement configuration file: %s",
                    strerror(errno));
        }
        // EPERM is expected if we're not root and we didn't own the original,
        // no need to complain
    }

    if (chmod(tmpfile, st.st_mode) != 0) {
        logger(LOG_INFO,
                "OpenLI: error while restoring permissions on replacement configuration file: %s",
                strerror(errno));
        // Allow to carry on?
    }

    if (remove(filename) != 0) {
        logger(LOG_INFO,
                "OpenLI: unable to remove original configuration file '%s' to apply update -- changes will NOT persist", filename);
        return 0;
    }

    if (rename(tmpfile, filename) != 0) {
        logger(LOG_INFO,
                "OpenLI: failed to replace original configuration file '%s' with an updated one -- you can find the updated YAML at '%s'",
                filename, tmpfile);
        return 0;
    }

    return 1;
}

static void destroy_array_object(openli_yaml_config_object_t *obj) {
    size_t i;
    openli_yaml_config_object_field_t *f;

    if (!obj->fields) {
        return;
    }
    for (i = 0; i < obj->field_count; i++) {
        f = &(obj->fields[i]);
        if (f->key) {
            free(f->key);
        }
        if (f->value) {
            free(f->value);
        }
    }
    free(obj->fields);
    obj->field_count = 0;
}

void clean_openli_yaml_config_updates(
        openli_yaml_config_pending_updates_t *updates) {

    size_t i, j;
    if (!updates) {
        return;
    }

    if (updates->updates == NULL) {
        return;
    }

    for (i = 0; i < updates->update_count; i++) {
        if (updates->updates[i].array_objects) {
            for (j = 0; j < updates->updates[i].array_objects_count; j++) {
                destroy_array_object(&(updates->updates[i].array_objects[j]));
            }
            free(updates->updates[i].array_objects);
            updates->updates[i].array_objects = NULL;
        }
    }
    updates->update_count = 0;
    //free(updates->updates);
}

void generate_scalar_openli_yaml_config_update(
        openli_yaml_config_update_t *update, const char *key_path,
        const char *value, bool is_string, bool create) {

    memset(update, 0, sizeof(openli_yaml_config_update_t));

    snprintf(update->key_path, OPENLI_YAML_MAX_KEY_LENGTH, "%s", key_path);
    snprintf(update->value, OPENLI_YAML_MAX_LINE, "%s", value);

    update->is_string = is_string;
    update->type = UPDATE_SCALAR;
    update->create_if_missing = create;

}

void generate_array_scalar_openli_yaml_config_update(
        openli_yaml_config_update_t *update, const char *key_path,
        const char *value, bool is_string, int array_index) {

    memset(update, 0, sizeof(openli_yaml_config_update_t));

    snprintf(update->key_path, OPENLI_YAML_MAX_KEY_LENGTH, "%s", key_path);
    snprintf(update->value, OPENLI_YAML_MAX_LINE, "%s", value);
    update->is_string = is_string;
    update->type = UPDATE_ARRAY_INDEX;
    update->array_index = array_index;
    // create not supported for this operation, either replace the entire
    // array entry or append a new one instead
    update->create_if_missing = false;
}

void generate_array_simple_append_openli_yaml_config_update(
        openli_yaml_config_update_t *update, const char *key_path,
        const char **values, bool is_string, size_t value_count,
        bool create) {

    memset(update, 0, sizeof(openli_yaml_config_update_t));

    snprintf(update->key_path, OPENLI_YAML_MAX_KEY_LENGTH, "%s", key_path);
    update->is_string = is_string;
    update->type = UPDATE_ARRAY_APPEND;
    update->array_values = (char **)values;
    update->array_count = value_count;
    update->create_if_missing = create;
}

void generate_array_object_append_openli_yaml_config_update(
        openli_yaml_config_update_t *update, const char *key_path,
        openli_yaml_config_object_t *objects, size_t obj_count, bool create) {

    size_t i, j;

    memset(update, 0, sizeof(openli_yaml_config_update_t));
    snprintf(update->key_path, OPENLI_YAML_MAX_KEY_LENGTH, "%s", key_path);
    update->type = UPDATE_ARRAY_APPEND;
    update->array_objects = calloc(obj_count,
            sizeof(openli_yaml_config_object_t));
    update->array_objects_count = obj_count;
    update->create_if_missing = create;

    for (i = 0; i < update->array_objects_count; i++) {
        update->array_objects[i].field_count = objects[i].field_count;
        update->array_objects[i].fields = calloc(objects[i].field_count,
                sizeof(openli_yaml_config_object_field_t));
        for (j = 0; j < objects[i].field_count; j++) {
            update->array_objects[i].fields[j].key = strdup(
                    objects[i].fields[j].key);
            update->array_objects[i].fields[j].value = strdup(
                    objects[i].fields[j].value);
            update->array_objects[i].fields[j].is_string =
                    objects[i].fields[j].is_string;
        }
    }
}

void generate_array_replace_openli_yaml_config_update(
        openli_yaml_config_update_t *update, const char *key_path,
        const char **values, bool is_string, size_t value_count,
        bool create) {

    memset(update, 0, sizeof(openli_yaml_config_update_t));

    snprintf(update->key_path, OPENLI_YAML_MAX_KEY_LENGTH, "%s", key_path);
    update->is_string = is_string;
    update->type = UPDATE_ARRAY_ALL;
    update->array_values = (char **)values;
    update->array_count = value_count;
    update->create_if_missing = create;
}

void generate_array_remove_object_openli_yaml_config_update(
        openli_yaml_config_update_t *update, const char *key_path,
        openli_yaml_config_object_t *criteria) {

    size_t i;

    memset(update, 0, sizeof(openli_yaml_config_update_t));
    snprintf(update->key_path, OPENLI_YAML_MAX_KEY_LENGTH, "%s", key_path);
    update->type = UPDATE_ARRAY_REMOVE;
    update->array_objects = calloc(1, sizeof(openli_yaml_config_object_t));
    update->array_objects_count = 1;

    update->array_objects[0].field_count = criteria->field_count;
    update->array_objects[0].fields = calloc(criteria->field_count,
            sizeof(openli_yaml_config_object_t));
    for (i = 0; i < criteria->field_count; i++) {
        update->array_objects[0].fields[i].key =
                strdup(criteria->fields[i].key);
        update->array_objects[0].fields[i].value =
                strdup(criteria->fields[i].value);
        update->array_objects[0].fields[i].is_string =
                criteria->fields[i].is_string;
    }
}

void generate_array_remove_scalar_openli_yaml_config_update(
        openli_yaml_config_update_t *update, const char *key_path,
        const char *value, bool is_string) {

    memset(update, 0, sizeof(openli_yaml_config_update_t));
    snprintf(update->key_path, OPENLI_YAML_MAX_KEY_LENGTH, "%s", key_path);
    snprintf(update->value, OPENLI_YAML_MAX_LINE, "%s", value);
    update->is_string = is_string;
    update->type = UPDATE_ARRAY_REMOVE_SCALAR;
}

size_t prepare_new_openli_yaml_config_update(
        openli_yaml_config_pending_updates_t *update_array) {

    // assuming we have the lock for the config update array...

    if (update_array->update_count < update_array->array_size) {
        // next expected slot is available, go ahead
        return update_array->update_count;
    }

    // otherwise the array is full, time to extend it
    update_array->updates = realloc(update_array->updates,
            sizeof(openli_yaml_config_update_t) *
                    (update_array->array_size + 16));
    update_array->array_size += 16;
    return update_array->update_count;
}
