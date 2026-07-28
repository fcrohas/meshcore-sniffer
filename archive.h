/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: long-term JSONL archive sink.
 *
 * When --archive=DIR is set, every emitted JSON event is appended to a
 * daily-rotated gzipped file at DIR/meshtastic-YYYYMMDD.jsonl.gz.
 * Append-only, no retention/cleanup logic; operators rotate or prune
 * out-of-band per their compliance policy.
 *
 * Format: one JSON event per line, identical to stdout. Daily rotation
 * happens at UTC midnight; the rotation check runs on every publish so
 * a long-quiet receiver still ends up with same-day events in the
 * right file.
 */

#ifndef ARCHIVE_H
#define ARCHIVE_H

#include <stdbool.h>
#include <stddef.h>

bool archive_init(const char *dir);
void archive_publish(const char *json_line, size_t len);
void archive_shutdown(void);

#endif /* ARCHIVE_H */
