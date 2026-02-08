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
 *
 */
#ifndef OPENLI_YAML_MODIFIER_H_
#define OPENLI_YAML_MODIFIER_H_

#include <stdbool.h>
#include <yaml.h>
#include <stdint.h>

#define OPENLI_YAML_MAX_LINE 1024
#define OPENLI_YAML_MAX_KEY_LENGTH 512
#define OPENLI_YAML_MAX_PATH_DEPTH 10

typedef enum {
    UPDATE_SCALAR,
    UPDATE_ARRAY_INDEX,
    UPDATE_ARRAY_ALL,
    UPDATE_ARRAY_APPEND,
} openli_yaml_update_type_t;

typedef struct {
    char *key;
    char *value;
    bool is_string;
} openli_yaml_config_object_field_t;

typedef struct {
    openli_yaml_config_object_field_t *fields;
    size_t field_count;
} openli_yaml_config_object_t;

typedef struct {
    char key_path[OPENLI_YAML_MAX_KEY_LENGTH];
    char value[OPENLI_YAML_MAX_LINE];
    bool is_string;
    openli_yaml_update_type_t type;
    int array_index;
    char **array_values;
    size_t array_count;

    openli_yaml_config_object_t *array_objects;
    size_t array_objects_count;
    bool create_if_missing;
} openli_yaml_config_update_t;

typedef struct {
    openli_yaml_config_update_t *updates;
    size_t update_count;
    size_t array_size;
} openli_yaml_config_pending_updates_t;

#define UPDATE_SCALAR_CONFIG(pending, key, value, quote, create) \
    prepare_new_openli_yaml_config_update(pending); \
    generate_scalar_openli_yaml_config_update( \
            &((pending)->updates[pending->update_count]), \
            key, value, quote, create); \
    pending->update_count ++

#define GENERATE_CONFIG_BOOLEAN(value) \
    (value != 0 ? "yes" : "no")

size_t prepare_new_openli_yaml_config_update(
        openli_yaml_config_pending_updates_t *update_array);

int apply_yaml_config_updates(const char *filename,
        openli_yaml_config_pending_updates_t *updates);
void clean_openli_yaml_config_updates(
        openli_yaml_config_pending_updates_t *updates);

void generate_scalar_openli_yaml_config_update(
        openli_yaml_config_update_t *update, const char *key_path,
        const char *value, bool is_string, bool create);
void generate_array_scalar_openli_yaml_config_update(
        openli_yaml_config_update_t *update, const char *key_path,
        const char *value, bool is_string, int array_index);
void generate_array_simple_append_openli_yaml_config_update(
        openli_yaml_config_update_t *update, const char *key_path,
        const char **values, bool is_string, size_t value_count, bool create);
void generate_array_object_append_openli_yaml_config_update(
        openli_yaml_config_update_t *update, const char *key_path,
        openli_yaml_config_object_t *objects,
        size_t obj_count, bool create);
void generate_array_replace_openli_yaml_config_update(
        openli_yaml_config_update_t *update, const char *key_path,
        const char **values, bool is_string, size_t value_count, bool create);


#endif
