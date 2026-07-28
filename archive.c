/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: long-term JSONL archive sink.
 *
 * Daily-rotated gzipped JSONL using zlib's gzFile interface. Single
 * mutex serializes writes; the rotation check runs on every publish
 * so we don't depend on a wakeup-on-midnight timer to land events in
 * the right file.
 */

#include "archive.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <zlib.h>

static char           *g_dir = NULL;
static gzFile          g_fp = NULL;
static int             g_open_yyyymmdd = 0;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static int             g_started = 0;

static int utc_yyyymmdd(time_t t)
{
    struct tm tm;
    gmtime_r(&t, &tm);
    return (tm.tm_year + 1900) * 10000 + (tm.tm_mon + 1) * 100 + tm.tm_mday;
}

/* Ensure the file for today's UTC date is open. Caller holds g_mu. */
static int open_today_locked(void)
{
    time_t now = time(NULL);
    int today = utc_yyyymmdd(now);
    if (g_fp && today == g_open_yyyymmdd) return 0;

    if (g_fp) {
        gzclose(g_fp);
        g_fp = NULL;
    }

    char path[1024];
    snprintf(path, sizeof(path), "%s/meshtastic-%08d.jsonl.gz", g_dir, today);
    g_fp = gzopen(path, "ab");
    if (!g_fp) {
        fprintf(stderr, "archive: cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }
    g_open_yyyymmdd = today;
    fprintf(stderr, "archive: writing %s\n", path);
    return 0;
}

bool archive_init(const char *dir)
{
    if (g_started) return true;
    if (!dir || !*dir) return false;
    /* Create the directory if absent (best-effort; ignore EEXIST). */
    if (mkdir(dir, 0755) < 0 && errno != EEXIST) {
        fprintf(stderr, "archive: cannot create %s: %s\n", dir, strerror(errno));
        return false;
    }
    g_dir = strdup(dir);
    if (!g_dir) return false;
    pthread_mutex_lock(&g_mu);
    int rc = open_today_locked();
    pthread_mutex_unlock(&g_mu);
    if (rc < 0) {
        free(g_dir); g_dir = NULL;
        return false;
    }
    g_started = 1;
    return true;
}

void archive_publish(const char *json_line, size_t len)
{
    if (!g_started || !json_line || len == 0) return;
    pthread_mutex_lock(&g_mu);
    if (open_today_locked() == 0 && g_fp) {
        if (gzwrite(g_fp, json_line, (unsigned)len) != (int)len) {
            int err;
            const char *msg = gzerror(g_fp, &err);
            fprintf(stderr, "archive: gzwrite failed (%s); closing\n", msg);
            gzclose(g_fp);
            g_fp = NULL;
            g_started = 0;
        } else {
            /* Flush periodically. Z_SYNC_FLUSH every write is wasteful;
             * leaving it to gzclose at shutdown is safer. The gzip
             * stream is recoverable mid-stream after a kill if we
             * gzflush(Z_SYNC_FLUSH) every event -- worth the hit since
             * SIGKILL during decode is a real risk. */
            gzflush(g_fp, Z_SYNC_FLUSH);
        }
    }
    pthread_mutex_unlock(&g_mu);
}

void archive_shutdown(void)
{
    pthread_mutex_lock(&g_mu);
    if (g_fp) { gzclose(g_fp); g_fp = NULL; }
    g_started = 0;
    pthread_mutex_unlock(&g_mu);
    free(g_dir);
    g_dir = NULL;
}
