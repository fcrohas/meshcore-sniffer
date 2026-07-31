/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: tiny direct-to-buffer JSON writer, shared by
 * feed.c (Meshtastic serialization) and feed_meshcore_json.c (MeshCore
 * serialization). Split out of feed.c so the MeshCore JSON path can be
 * unit tested without linking the rest of feed.c's dependencies
 * (mqtt/zmq/cot/gpsd/geofence/options).
 */

#ifndef JW_H
#define JW_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    char  *buf;
    size_t cap;
    size_t len;
    bool   first_field;
} jw_t;

void jw_init(jw_t *j, char *buf, size_t cap);
void jw_putc(jw_t *j, char c);
void jw_puts(jw_t *j, const char *s);
void jw_printf(jw_t *j, const char *fmt, ...);
void jw_str_escaped(jw_t *j, const char *s);
void jw_field_name(jw_t *j, const char *name);
void jw_field_str(jw_t *j, const char *name, const char *value);
/* Emits "name":<raw_json> with raw_json copied verbatim (no string
 * escaping) -- for embedding an already-serialized JSON fragment
 * (array/object) produced by another module, e.g. meshcore_lpp.c's
 * telemetry records. No-op if raw_json is NULL/empty, same guard
 * convention as jw_field_str(). Caller is responsible for raw_json
 * being valid JSON. */
void jw_field_raw(jw_t *j, const char *name, const char *raw_json);
void jw_field_u32(jw_t *j, const char *name, uint32_t value);
void jw_field_u64(jw_t *j, const char *name, uint64_t value);
void jw_field_i32(jw_t *j, const char *name, int32_t value);
void jw_field_f32(jw_t *j, const char *name, float value);
void jw_field_f64(jw_t *j, const char *name, double value);
void jw_field_bool(jw_t *j, const char *name, bool value);
void jw_open(jw_t *j);
void jw_close(jw_t *j);
void jw_open_array(jw_t *j, const char *name);
void jw_close_array(jw_t *j);
void jw_array_sep(jw_t *j);

#endif /* JW_H */
