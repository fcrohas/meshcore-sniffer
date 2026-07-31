/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: tiny direct-to-buffer JSON writer (see jw.h).
 */

#include "jw.h"

#include <stdarg.h>
#include <stdio.h>

void jw_init(jw_t *j, char *buf, size_t cap) {
    j->buf = buf; j->cap = cap; j->len = 0; j->first_field = true;
}
void jw_putc(jw_t *j, char c) {
    if (j->len + 1 < j->cap) j->buf[j->len++] = c;
}
void jw_puts(jw_t *j, const char *s) {
    while (*s && j->len + 1 < j->cap) j->buf[j->len++] = *s++;
}
void jw_printf(jw_t *j, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(j->buf + j->len, j->cap - j->len, fmt, ap);
    va_end(ap);
    if (n > 0 && (size_t)n < j->cap - j->len) j->len += (size_t)n;
}
void jw_str_escaped(jw_t *j, const char *s) {
    jw_putc(j, '"');
    for (; *s; ++s) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { jw_putc(j, '\\'); jw_putc(j, (char)c); }
        else if (c == '\n')        { jw_puts(j, "\\n"); }
        else if (c == '\r')        { jw_puts(j, "\\r"); }
        else if (c == '\t')        { jw_puts(j, "\\t"); }
        else if (c < 0x20)         { jw_printf(j, "\\u%04x", c); }
        else                       { jw_putc(j, (char)c); }
    }
    jw_putc(j, '"');
}
void jw_field_name(jw_t *j, const char *name) {
    if (!j->first_field) jw_putc(j, ',');
    j->first_field = false;
    jw_str_escaped(j, name);
    jw_putc(j, ':');
}
void jw_field_str(jw_t *j, const char *name, const char *value) {
    if (!value) return;
    jw_field_name(j, name);
    jw_str_escaped(j, value);
}
void jw_field_raw(jw_t *j, const char *name, const char *raw_json) {
    if (!raw_json || !raw_json[0]) return;
    jw_field_name(j, name);
    jw_puts(j, raw_json);
}
void jw_field_u32(jw_t *j, const char *name, uint32_t value) {
    jw_field_name(j, name);
    jw_printf(j, "%u", value);
}
void jw_field_u64(jw_t *j, const char *name, uint64_t value) {
    jw_field_name(j, name);
    jw_printf(j, "%llu", (unsigned long long)value);
}
void jw_field_i32(jw_t *j, const char *name, int32_t value) {
    jw_field_name(j, name);
    jw_printf(j, "%d", value);
}
void jw_field_f32(jw_t *j, const char *name, float value) {
    jw_field_name(j, name);
    jw_printf(j, "%.4f", (double)value);
}
void jw_field_f64(jw_t *j, const char *name, double value) {
    jw_field_name(j, name);
    jw_printf(j, "%.7f", value);
}
void jw_field_bool(jw_t *j, const char *name, bool value) {
    jw_field_name(j, name);
    jw_puts(j, value ? "true" : "false");
}
void jw_open(jw_t *j) { jw_putc(j, '{'); j->first_field = true; }
void jw_close(jw_t *j) { jw_putc(j, '}'); j->first_field = false; }
void jw_open_array(jw_t *j, const char *name) {
    jw_field_name(j, name); jw_putc(j, '['); j->first_field = true;
}
void jw_close_array(jw_t *j) { jw_putc(j, ']'); j->first_field = false; }
void jw_array_sep(jw_t *j) {
    if (!j->first_field) jw_putc(j, ',');
    j->first_field = false;
}
