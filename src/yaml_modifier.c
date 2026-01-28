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

#include "logger.h"
#include "util.h"

#define MAX_LINE 1024
#define MAX_KEY_LENGTH 512
#define MAX_PATH_DEPTH 10

#define WRITE_QUOTED_VALUE(fout, value) \
    fprintf(fout, " \"%s\"\n", value);

#define WRITE_UNQUOTED_VALUE(fout, value) \
    fprintf(fout, " %s\n", value);

typedef enum {
    UPDATE_SCALAR,
    UPDATE_ARRAY_INDEX,
    UPDATE_ARRAY_ALL,
    UPDATE_ARRAY_APPEND,
} openli_yaml_update_type_t;

typedef struct {
    char key_path[MAX_KEY_LENGTH];
    char value[MAX_LINE];
    bool is_string;
    openli_yaml_update_type_t type;
    int array_index;
    char **array_values;
    size_t array_count;

    struct {
        char **keys;
        char **values;
        bool *is_string;
        size_t count;
    } *array_objects;
    size_t array_objects_count;
} openli_yaml_config_update_t;

typedef struct {
    char path[MAX_PATH_DEPTH][MAX_KEY_LENGTH];
    int depth;
    int indents[MAX_PATH_DEPTH];
    bool in_array[MAX_PATH_DEPTH];
    int array_index[MAX_PATH_DEPTH];
} openli_yaml_context_t;

typedef struct {
    char key_path[MAX_KEY_LENGTH];
    int indent;
    uint32_t filepos;
    bool is_string;
} openli_yaml_array_append_t;

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
    strncpy(base, path, base_len);
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
    strncpy(key_buf, p, key_len);
    key_buf[key_len] = '\0';
    rtrim(key_buf);
    return true;
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
        size_t buf_size) {
    int i;

    path_buf[0] = '\0';
    for (i = 0; i < ctx->depth; i++) {
        if (i > 0) {
            strncat(path_buf, ".", buf_size - strlen(path_buf) - 1);
        }
        strncat(path_buf, ctx->path[i], buf_size - strlen(path_buf) - 1);
        if (ctx->in_array[i] && ctx->array_index[i] >= 0) {
            char idx[32];
            snprintf(idx, 32, "[%d]", ctx->array_index[i]);
            strncat(path_buf, idx, buf_size - strlen(path_buf) - 1);
        }
    }
}

static void update_context(openli_yaml_context_t *ctx, const char *line,
        char *key, uint8_t is_array) {

    int indent = get_indent(line);
    while (ctx->depth > 0 && indent <= ctx->indents[ctx->depth - 1]) {
        ctx->depth --;
    }

    if (ctx->depth > 0 && is_array_item(line) && ctx->in_array[ctx->depth - 1])
    {
        ctx->array_index[ctx->depth - 1]++;
    }

    if (!has_value(line) || is_array) {
        if (ctx->depth < MAX_PATH_DEPTH) {
            strncpy(ctx->path[ctx->depth], key, MAX_KEY_LENGTH - 1);
            ctx->indents[ctx->depth] = indent;
            ctx->in_array[ctx->depth] = is_array;
            ctx->array_index[ctx->depth] = is_array ? -1 : 0;
            ctx->depth ++;
        }
    }
}

static bool path_matches(const char *current_path, const char *key,
        const char *target_path) {

    char full_path[MAX_KEY_LENGTH * 2];
    if (current_path[0] != '\0') {
        snprintf(full_path, sizeof(full_path), "%s.%s", current_path, key);
    } else {
        strncpy(full_path, key, sizeof(full_path) -1);
    }
    return (strcmp(full_path, target_path) == 0);
}

static void check_for_appendable_array_end(openli_yaml_context_t *ctx,
        const char *line, FILE *fout, openli_yaml_array_append_t *append_arrays,
        size_t append_count) {

    size_t i;
    char current_path[MAX_KEY_LENGTH * 2];

    build_path(ctx, current_path, sizeof(current_path));

    for (i = 0; i < append_count; i++) {
        char *trimmed;
        if (append_arrays[i].filepos != 0) {
            continue;
        }
        if (is_array_item(line)) {
            continue;
        }
        if (get_indent(line) > append_arrays[i].indent) {
            continue;
        }
        trimmed = ltrim((char *)line);
        if (trimmed[0] == '\0' || trimmed[0] == '#') {
            continue;
        }
        // array must be over, save our current position to write the
        // appendages to later on.
        append_arrays[i].filepos = ftell(fout) - strlen(line);
    }
}

static void append_array_object(FILE *fout, openli_yaml_config_update_t *update,
        int base_indent) {

    size_t i, j;
    for (i = 0; i < update->array_objects_count; i++) {
        fprintf(fout, "%*s- ", base_indent, "");
        if (update->array_objects[i].count == 0) {
            fprintf(fout, "\n");
            continue;
        }

        // first field must be in line with the dash
        fprintf(fout, "%s:", update->array_objects[i].keys[0]);
        if (update->array_objects[i].is_string[0]) {
            WRITE_QUOTED_VALUE(fout, update->array_objects[i].values[0]);
        } else {
            WRITE_UNQUOTED_VALUE(fout, update->array_objects[i].values[0]);
        }

        // remaining fields need the extra indentation
        for (j = 1; j < update->array_objects[i].count; j++) {
            fprintf(fout, "%*s%s:", base_indent + 2, "",
                    update->array_objects[i].keys[j]);
            if (update->array_objects[i].is_string[j]) {
                WRITE_QUOTED_VALUE(fout, update->array_objects[i].values[j]);
            } else {
                WRITE_UNQUOTED_VALUE(fout, update->array_objects[i].values[j]);
            }
        }
    }

}

static int apply_array_appends(const char *tmpfile,
        openli_yaml_array_append_t *append_arrays, size_t append_count,
        openli_yaml_config_update_t *updates, size_t update_count) {

    FILE *temp_in, *temp_out;
    char line[MAX_LINE];
    char tmpfile2[768];
    long current_pos = 0;
    size_t i, j, k;
    int base_indent;
    char *val;

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

    while (fgets(line, MAX_LINE, temp_in)) {
        for (i = 0; i < append_count; i++) {
            if (append_arrays[i].filepos <= 0) {
                continue;
            }
            if (current_pos != append_arrays[i].filepos) {
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
                        fprintf(temp_out, "%*s-", base_indent, "");
                        if (updates[j].is_string) {
                            WRITE_QUOTED_VALUE(temp_out, val);
                        } else {
                            WRITE_UNQUOTED_VALUE(temp_out, val);
                        }
                    }
                } else {
                    append_array_object(temp_out, &(updates[j]), base_indent);
                }
                break;
            }
            append_arrays[i].filepos = -1;  // mark as completed
        }
        fputs(line, temp_out);
        current_pos = ftell(temp_in);
    }

    fclose(temp_in);
    fclose(temp_out);

    remove(tmpfile);
    rename(tmpfile2, tmpfile);
    return 0;
}

static bool handle_array_replacement(const char *line, const char *current_path,
        const char *key, openli_yaml_config_update_t *update, FILE *fout,
        bool *in_replaced_array, int *replaced_array_indent) {

    int indent;
    const char *colon;
    size_t j;

    if (!path_matches(current_path, key, update->key_path)) {
        return false;
    }

    indent = get_indent(line);
    colon = strchr(line, ':');
    fwrite(line, 1, colon - line + 1, fout);
    fprintf(fout, "\n");

    for (j = 0; j < update->array_count; j++) {
        fprintf(fout, "%*s-", indent + 2, "");
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

    strncpy(append_arrays[*append_count].key_path, update->key_path,
            MAX_KEY_LENGTH - 1);
    append_arrays[*append_count].indent = indent;
    append_arrays[*append_count].is_string = update->is_string;
    (*append_count)++;
    return true;
}

static bool handle_scalar_update(const char *line, const char *current_path,
        const char *key, openli_yaml_config_update_t *update, FILE *fout) {

    const char *colon;

    if (!path_matches(current_path, key, update->key_path)) {
        return false;
    }

    colon = strchr(line, ':');
    if (!colon) {
        return false;
    }

    fwrite(line, 1, colon - line + 1, fout);
    if (update->is_string) {
        WRITE_QUOTED_VALUE(fout, update->value);
    } else {
        WRITE_UNQUOTED_VALUE(fout, update->value);
    }
    return true;
}

static bool update_regular_keyitem(openli_yaml_context_t *ctx,
        openli_yaml_config_update_t *updates, size_t update_count,
        char *line, int indent, FILE *fout, bool *found, char *key,
        bool *in_replaced_array, int *replaced_array_indent,
        openli_yaml_array_append_t *append_arrays,
        size_t *append_count) {

    size_t i;
    bool ret = false;
    char current_path[MAX_KEY_LENGTH * 2];

    build_path(ctx, current_path, sizeof(current_path));

    for (i = 0; i < update_count; i++) {
        if (ret == true) {
            break;
        }
        if (found[i]) {
            continue;
        }
        switch(updates[i].type) {
            case UPDATE_ARRAY_ALL:
                if (handle_array_replacement(line, current_path, key,
                        &updates[i], fout, in_replaced_array,
                        replaced_array_indent)) {
                    found[i] = true;
                    ret = true;
                }
                break;
            case UPDATE_ARRAY_APPEND:
                if (handle_array_append_marking(current_path, key, indent,
                        &updates[i], append_arrays, append_count)) {
                    found[i] = true;
                    // don't set ret to true, just marking this for later
                }
                break;
            case UPDATE_SCALAR:
                if (handle_scalar_update(line, current_path, key,
                        &updates[i], fout)) {
                    found[i] = true;
                    ret = true;
                }
                break;
            case UPDATE_ARRAY_INDEX:
                break;
        }
    }
    return ret;
}


static bool update_array_item(openli_yaml_context_t *ctx,
        openli_yaml_config_update_t *updates, size_t update_count,
        char *line, FILE *fout, bool *found) {

    const char *item_start = strchr(line, '-') + 1;
    char item_key[MAX_KEY_LENGTH] = "";
    size_t i;
    char base[MAX_KEY_LENGTH];
    char remainder[MAX_KEY_LENGTH];
    int target_index;
    char target_path[MAX_KEY_LENGTH * 2 + 20];
    char full_path[MAX_KEY_LENGTH * 3];
    const char *colon;
    bool ret = false;
    char current_path[MAX_KEY_LENGTH * 2];

    build_path(ctx, current_path, sizeof(current_path));
    if (extract_key(item_start, item_key, MAX_KEY_LENGTH)) {
        // deal with individual array element updates
        for (i = 0; i < update_count; i++) {
            if (found[i]) {
                continue;
            }
            if (updates[i].type != UPDATE_ARRAY_INDEX) {
                continue;
            }
            if (parse_array_syntax(updates[i].key_path, base, &target_index,
                    remainder) == false) {
                continue;
            }
            snprintf(target_path, MAX_KEY_LENGTH * 2 + 20, "%s[%d].%s",
                    base, target_index, remainder);
            snprintf(full_path, MAX_KEY_LENGTH * 3, "%s.%s", current_path, item_key);

            if (strcmp(full_path, target_path) != 0) {
                continue;
            }
            // found a match, time to update
            colon = strchr(item_start, ':');
            if (colon) {
                fwrite(line, 1, colon - line + 1, fout);
                if (updates[i].is_string) {
                    WRITE_QUOTED_VALUE(fout, updates[i].value);
                } else {
                    WRITE_UNQUOTED_VALUE(fout, updates[i].value);
                }
                found[i] = true;
                ret = true;
                break;
            }
        }
        update_context(ctx, line, item_key, false);
    } else {
        // standalone array item without key
        for (i = 0; i < update_count; i++) {
            if (found[i]) {
                continue;
            }
            if (updates[i].type != UPDATE_ARRAY_INDEX) {
                continue;
            }
            if (parse_array_syntax(updates[i].key_path, base, &target_index,
                    remainder) == false) {
                continue;
            }
            if (remainder[0] != '\0') {
                continue;
            }
            snprintf(target_path, MAX_KEY_LENGTH * 2, "%s[%d]", base,
                    target_index);

            if (strcmp(full_path, target_path) != 0) {
                continue;
            }
            // write the indentation followed by the '-'
            fwrite(line, 1, item_start - line, fout);
            if (updates[i].is_string) {
                WRITE_QUOTED_VALUE(fout, updates[i].value);
            } else {
                WRITE_UNQUOTED_VALUE(fout, updates[i].value);
            }
            found[i] = true;
            ret = true;
            break;
        }
        update_context(ctx, line, item_key, false);
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

int apply_yaml_config_update(const char *filename,
        openli_yaml_config_update_t *updates, size_t update_count) {

    FILE *fin = fopen(filename, "r");
    FILE *fout = NULL;
    char tmpfile[512];
    char line[MAX_LINE];
    openli_yaml_context_t ctx;
    bool *found;
    bool in_replaced_array = false;
    int replaced_array_indent = 0;
    openli_yaml_array_append_t *append_arrays;
    size_t append_count = 0;
    size_t i;

    memset(&ctx, 0, sizeof(openli_yaml_context_t));

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

    found = calloc(update_count, sizeof(bool));
    append_arrays = calloc(update_count, sizeof(openli_yaml_array_append_t));

    while (fgets(line, MAX_LINE, fin)) {
        bool line_updated = false;
        char key[MAX_KEY_LENGTH];
        int indent = get_indent(line);

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
            fputs(line, fout);
            continue;
        }

        if (is_array_item(line)) {
            line_updated = update_array_item(&ctx, updates, update_count,
                    line, fout, found);
        } else if (extract_key(line, key, MAX_KEY_LENGTH)) {
            line_updated = update_regular_keyitem(&ctx, updates, update_count,
                    line, indent, fout, found, key, &in_replaced_array,
                    &replaced_array_indent, append_arrays, &append_count);

            if (line_updated == false || !has_value(line)) {
                bool next_is_array = false;
                long pos;
                char next_line[MAX_LINE];

                // peek to see if the next line will be an array
                pos = ftell(fin);
                if (fgets(next_line, MAX_LINE, fin)) {
                    next_is_array = is_array_item(next_line);
                    fseek(fin, pos, SEEK_SET);
                }
                update_context(&ctx, line, key, next_is_array);
            }
        }

        if (!line_updated && !in_replaced_array) {
            // unchanged line, just write it back out
            fputs(line, fout);
        }

        if (append_count > 0) {
            // check if an array has ended that we need to append to
            check_for_appendable_array_end(&ctx, line, fout, append_arrays,
                    append_count);
        }
    }

    fclose(fin);
    fclose(fout);

    if (apply_array_appends(tmpfile, append_arrays, append_count,
            updates, update_count) < 0) {
        free(found);
        free(append_arrays);
        remove(tmpfile);
        return -1;
    }

    // check that we managed to perform all of the requested updates -- if not,
    // at least log a warning
    for (i = 0; i < update_count; i++) {
        if (!found[i]) {
            logger(LOG_INFO,
                    "OpenLI: unable to update configuration for key '%s' as it was not already present in the config file",
                    updates[i].key_path);
        }
    }

    if (!validate_yaml(tmpfile)) {
        logger(LOG_INFO,
                "OpenLI: generated invalid YAML to replace configuration file '%s' -- changes will NOT persist", filename);
        remove(tmpfile);
        return 0;
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

void clean_openli_yaml_config_update(openli_yaml_config_update_t *update) {
    if (update->array_objects) {
        free(update->array_objects);
        update->array_objects = NULL;
    }
}

void generate_scalar_openli_yaml_config_update(
        openli_yaml_config_update_t *update, const char *key_path,
        const char *value, bool is_string) {

    memset(update, 0, sizeof(openli_yaml_config_update_t));

    strncpy(update->key_path, key_path, MAX_KEY_LENGTH - 1);
    strncpy(update->value, value, MAX_LINE - 1);
    update->is_string = is_string;
    update->type = UPDATE_SCALAR;

}

void generate_array_scalar_openli_yaml_config_update(
        openli_yaml_config_update_t *update, const char *key_path,
        const char *value, bool is_string, int array_index) {

    memset(update, 0, sizeof(openli_yaml_config_update_t));

    strncpy(update->key_path, key_path, MAX_KEY_LENGTH - 1);
    strncpy(update->value, value, MAX_LINE - 1);
    update->is_string = is_string;
    update->type = UPDATE_ARRAY_INDEX;
    update->array_index = array_index;
}

void generate_array_simple_append_openli_yaml_config_update(
        openli_yaml_config_update_t *update, const char *key_path,
        const char **values, bool is_string, size_t value_count) {

    memset(update, 0, sizeof(openli_yaml_config_update_t));

    strncpy(update->key_path, key_path, MAX_KEY_LENGTH - 1);
    update->is_string = is_string;
    update->type = UPDATE_ARRAY_APPEND;
    update->array_values = (char **)values;
    update->array_count = value_count;
}

void generate_array_object_append_openli_yaml_config_update(
        openli_yaml_config_update_t *update, const char *key_path,
        const char ***obj_keys, char ***obj_values, bool **obj_is_string,
        size_t *obj_field_counts, size_t obj_count) {

    size_t i;

    memset(update, 0, sizeof(openli_yaml_config_update_t));
    strncpy(update->key_path, key_path, MAX_KEY_LENGTH - 1);
    update->type = UPDATE_ARRAY_APPEND;
    update->array_objects = calloc(obj_count, sizeof(*(update->array_objects)));
    update->array_objects_count = obj_count;

    for (i = 0; i < obj_count; i++) {
        update->array_objects[i].keys = (char **)obj_keys[i];
        update->array_objects[i].values = obj_values[i];
        update->array_objects[i].is_string = obj_is_string[i];
        update->array_objects[i].count = obj_field_counts[i];
    }
}

void generate_array_replace_openli_yaml_config_update(
        openli_yaml_config_update_t *update, const char *key_path,
        const char **values, bool is_string, size_t value_count) {

    memset(update, 0, sizeof(openli_yaml_config_update_t));

    strncpy(update->key_path, key_path, MAX_KEY_LENGTH - 1);
    update->is_string = is_string;
    update->type = UPDATE_ARRAY_ALL;
    update->array_values = (char **)values;
    update->array_count = value_count;
}
