/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: ZMQ PUB output.
 *
 * One PUB socket bound or connected to --zmq=ENDPOINT (default
 * tcp endpoints, default tcp://(asterisk):7008). One JSON line per send. Uses ZMQ_DONTWAIT so a
 * stalled subscriber drops messages rather than blocking decode.
 *
 */

#include "options.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_ZMQ

#include <zmq.h>

static void *g_ctx = NULL;
static void *g_sock = NULL;

void zmq_pub_init(void)
{
    if (!opt_zmq_endpoint) return;
    g_ctx = zmq_ctx_new();
    if (!g_ctx) { fprintf(stderr, "zmq: ctx_new failed\n"); return; }
    g_sock = zmq_socket(g_ctx, ZMQ_PUB);
    if (!g_sock) {
        fprintf(stderr, "zmq: socket failed\n");
        zmq_ctx_term(g_ctx); g_ctx = NULL; return;
    }
    int hwm = 1000;
    zmq_setsockopt(g_sock, ZMQ_SNDHWM, &hwm, sizeof(hwm));
    int linger = 0;
    zmq_setsockopt(g_sock, ZMQ_LINGER, &linger, sizeof(linger));

    /* Optional CurveZMQ on the wire. The secret-key file is the Z85
     * sensor secret; PATH.pub is the matching public key. We act as
     * server (ZMQ_CURVE_SERVER=1) since fusion-side SUB connects to us
     * and authenticates with our public key as ServerKey. */
    if (opt_zmq_curve_secret) {
        FILE *f = fopen(opt_zmq_curve_secret, "r");
        char sec[64] = {0};
        if (f) {
            size_t n = fread(sec, 1, sizeof(sec) - 1, f);
            fclose(f);
            /* Trim trailing whitespace from the Z85 line. */
            while (n > 0 && (sec[n-1] == '\n' || sec[n-1] == '\r' || sec[n-1] == ' ')) sec[--n] = 0;
        }
        if (sec[0]) {
            int curve_server = 1;
            zmq_setsockopt(g_sock, ZMQ_CURVE_SERVER, &curve_server, sizeof(curve_server));
            if (zmq_setsockopt(g_sock, ZMQ_CURVE_SECRETKEY, sec, strlen(sec)) != 0) {
                fprintf(stderr, "zmq: CURVE_SECRETKEY rejected: %s\n", zmq_strerror(zmq_errno()));
            } else {
                fprintf(stderr, "zmq: CurveZMQ server enabled (secret loaded from %s)\n", opt_zmq_curve_secret);
            }
        } else {
            fprintf(stderr, "zmq: failed to read curve secret from %s\n", opt_zmq_curve_secret);
        }
    }

    /* Endpoints with a wildcard host bind; everything else connects. */
    int rc = (strstr(opt_zmq_endpoint, "://*") || strstr(opt_zmq_endpoint, "*:"))
        ? zmq_bind(g_sock, opt_zmq_endpoint)
        : zmq_connect(g_sock, opt_zmq_endpoint);
    if (rc != 0) {
        fprintf(stderr, "zmq: %s %s failed: %s\n",
                rc ? "bind/connect" : "ok", opt_zmq_endpoint, zmq_strerror(zmq_errno()));
        zmq_close(g_sock); g_sock = NULL;
        zmq_ctx_term(g_ctx); g_ctx = NULL;
        return;
    }
    if (verbose) fprintf(stderr, "zmq: PUB %s\n", opt_zmq_endpoint);
}

void zmq_pub_publish(const char *json, size_t len)
{
    if (!g_sock) return;
    zmq_send(g_sock, json, len, ZMQ_DONTWAIT);
}

void zmq_pub_shutdown(void)
{
    if (g_sock) { zmq_close(g_sock); g_sock = NULL; }
    if (g_ctx)  { zmq_ctx_term(g_ctx); g_ctx = NULL; }
}

#else  /* !HAVE_ZMQ */

void zmq_pub_init(void) {}
void zmq_pub_publish(const char *json, size_t len) { (void)json; (void)len; }
void zmq_pub_shutdown(void) {}

#endif
