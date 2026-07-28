/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * No-op stub for node_db_persist_hook(), the hook node_db.c fires on
 * every learned/updated node. Linked by binaries that pull in
 * node_db.c but not db_sqlite.c (the real implementation) -- mirrors
 * meshcore_hashtag_dict_stub.c's role for the same reason: avoid
 * dragging sqlite/threading dependencies into lightweight test/tool
 * binaries that don't need cross-restart persistence.
 */

#include <stdint.h>

void node_db_persist_hook(uint32_t id, const char *long_name,
                          const char *short_name, uint32_t hw_model, uint32_t role)
{
    (void)id; (void)long_name; (void)short_name; (void)hw_model; (void)role;
}
