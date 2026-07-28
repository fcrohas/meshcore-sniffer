/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: JSON Schema for the event format. See schema.c.
 */

#ifndef SCHEMA_H
#define SCHEMA_H

/* Returns a pointer to a static, NUL-terminated JSON Schema string
 * describing the event format that feed.c emits. Caller does not free. */
const char *schema_json_text(void);

/* Convenience: print schema to stdout (single fputs). */
void schema_print(void);

#endif /* SCHEMA_H */
