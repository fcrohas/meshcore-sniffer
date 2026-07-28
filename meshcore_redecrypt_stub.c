/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * No-op stub for meshcore_redecrypt_channel(), for binaries that pull
 * in code calling it (meshcore_hashtag_dict.c, c2.c) but don't want
 * the db_sqlite/feed_meshcore_json dependency chain -- mirrors
 * meshcore_hashtag_dict_stub.c's role for the same reason.
 */

#include "meshcore_redecrypt.h"

int meshcore_redecrypt_channel(uint8_t channel_hash, const meshcore_channelset_t *channels)
{
    (void)channel_hash;
    (void)channels;
    return 0;
}
