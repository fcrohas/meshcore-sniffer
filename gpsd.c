/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: gpsd client.
 *
 * Background thread connects to gpsd over TCP, sends ?WATCH to enable
 * JSON-mode reports, then reads newline-delimited JSON and parses each
 * TPV report for class/mode/lat/lon/alt. Cheap field-by-name extractor
 * (no full JSON parser pulled in for four numeric fields).
 *
 * Reconnects on socket failure; exits when running -> 0. Latest fix is
 * shared with the feed thread under a small mutex.
 */

#include "gpsd.h"
#include "options.h"

#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static pthread_t       g_thread;
static volatile int    g_run = 0;
static int             g_started = 0;
static char           *g_endpoint = NULL;

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static double          g_lat = 0, g_lon = 0, g_alt_m = 0;
static double          g_last_update_s = 0;
static int             g_has_fix = 0;

static double mono_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1.0e9;
}

/* Find a numeric JSON field by exact "key": match. Tolerates whitespace
 * after the colon. Returns 0.0 if the field is absent (caller should
 * separately confirm presence if zero is a meaningful value). */
static int find_number(const char *line, const char *key, double *out)
{
    char needle[64];
    int nl = snprintf(needle, sizeof(needle), "\"%s\":", key);
    if (nl < 0 || nl >= (int)sizeof(needle)) return 0;
    const char *p = strstr(line, needle);
    if (!p) return 0;
    p += nl;
    while (*p == ' ' || *p == '\t') ++p;
    char *end = NULL;
    double v = strtod(p, &end);
    if (end == p) return 0;
    *out = v;
    return 1;
}

static void parse_tpv_line(const char *line)
{
    if (!strstr(line, "\"class\":\"TPV\"")) return;
    double mode = 0;
    if (!find_number(line, "mode", &mode) || mode < 2.0) return;
    double lat = 0, lon = 0, alt = 0;
    int got_lat = find_number(line, "lat", &lat);
    int got_lon = find_number(line, "lon", &lon);
    if (!got_lat || !got_lon) return;
    int got_alt = find_number(line, "altMSL", &alt);
    if (!got_alt) got_alt = find_number(line, "alt", &alt);

    pthread_mutex_lock(&g_mu);
    g_lat = lat;
    g_lon = lon;
    g_alt_m = got_alt ? alt : 0.0;
    g_last_update_s = mono_s();
    g_has_fix = 1;
    pthread_mutex_unlock(&g_mu);
}

static int connect_to_gpsd(const char *host, int port)
{
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", port);
    struct addrinfo hints = {0}, *ai = NULL;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int rc = getaddrinfo(host, portbuf, &hints, &ai);
    if (rc != 0 || !ai) return -1;
    int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) { freeaddrinfo(ai); return -1; }
    if (connect(fd, ai->ai_addr, ai->ai_addrlen) < 0) {
        close(fd);
        freeaddrinfo(ai);
        return -1;
    }
    freeaddrinfo(ai);
    return fd;
}

static void *gpsd_thread_fn(void *arg)
{
    (void)arg;
#ifdef _GNU_SOURCE
    pthread_setname_np(pthread_self(), "gpsd");
#endif
    /* Parse endpoint. Default = localhost:2947. Accept "host", "host:port",
     * or ":port" forms. */
    char host[64] = "localhost";
    int  port = 2947;
    if (g_endpoint && g_endpoint[0]) {
        const char *colon = strrchr(g_endpoint, ':');
        if (colon) {
            size_t hl = (size_t)(colon - g_endpoint);
            if (hl > 0 && hl < sizeof(host)) {
                memcpy(host, g_endpoint, hl);
                host[hl] = 0;
            }
            int p = atoi(colon + 1);
            if (p > 0 && p < 65536) port = p;
        } else {
            strncpy(host, g_endpoint, sizeof(host) - 1);
            host[sizeof(host) - 1] = 0;
        }
    }

    int announced = 0;
    while (g_run && running) {
        int fd = connect_to_gpsd(host, port);
        if (fd < 0) {
            if (!announced) {
                fprintf(stderr, "gpsd: cannot connect to %s:%d (will retry)\n", host, port);
                announced = 1;
            }
            for (int i = 0; i < 50 && g_run && running; ++i) usleep(100000);
            continue;
        }
        fprintf(stderr, "gpsd: connected to %s:%d\n", host, port);
        announced = 0;

        /* Subscribe to JSON-mode TPV reports. */
        const char *watch = "?WATCH={\"enable\":true,\"json\":true}\n";
        ssize_t wn = write(fd, watch, strlen(watch));
        (void)wn;

        char  buf[4096];
        size_t off = 0;
        while (g_run && running) {
            ssize_t n = read(fd, buf + off, sizeof(buf) - 1 - off);
            if (n <= 0) break;
            off += (size_t)n;
            buf[off] = 0;
            char *line = buf, *end;
            while ((end = strchr(line, '\n')) != NULL) {
                *end = 0;
                if (line[0]) parse_tpv_line(line);
                line = end + 1;
            }
            size_t leftover = (size_t)((buf + off) - line);
            if (leftover > 0 && line != buf) memmove(buf, line, leftover);
            off = leftover;
            if (off == sizeof(buf) - 1) off = 0; /* line too long: drop */
        }
        close(fd);
        if (g_run && running) {
            fprintf(stderr, "gpsd: connection lost, reconnecting...\n");
            for (int i = 0; i < 20 && g_run && running; ++i) usleep(100000);
        }
    }
    return NULL;
}

bool gpsd_init(const char *endpoint)
{
    if (g_started) return true;
    g_endpoint = endpoint ? strdup(endpoint) : NULL;
    g_run = 1;
    if (pthread_create(&g_thread, NULL, gpsd_thread_fn, NULL) != 0) {
        g_run = 0;
        free(g_endpoint);
        g_endpoint = NULL;
        return false;
    }
    g_started = 1;
    return true;
}

void gpsd_shutdown(void)
{
    if (!g_started) return;
    g_run = 0;
    pthread_join(g_thread, NULL);
    free(g_endpoint);
    g_endpoint = NULL;
    g_started = 0;
}

bool gpsd_get_fix(double *out_lat, double *out_lon,
                  double *out_alt_m, double *out_age_s)
{
    pthread_mutex_lock(&g_mu);
    int has = g_has_fix;
    if (has) {
        if (out_lat)    *out_lat    = g_lat;
        if (out_lon)    *out_lon    = g_lon;
        if (out_alt_m)  *out_alt_m  = g_alt_m;
        if (out_age_s)  *out_age_s  = mono_s() - g_last_update_s;
    }
    pthread_mutex_unlock(&g_mu);
    return has != 0;
}
