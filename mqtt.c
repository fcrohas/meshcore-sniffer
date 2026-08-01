/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: MQTT publisher.
 *
 * Connects to a broker (libmosquitto) and publishes one JSON line per
 * decoded packet. Topic defaults to meshtastic/<station-id>; user can
 * override with --mqtt-topic.
 *
 * Compiled in only when libmosquitto is found at configure time
 * (HAVE_MQTT define). When it isn't, the symbols below are stubs.
 *
 */

#include "options.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_MQTT

#include <mosquitto.h>

static struct mosquitto *g_mq = NULL;
static char             *g_topic = NULL;
static char             *g_status_topic = NULL;

static const char *find_default_cafile(void)
{
    /* Common CA bundle locations across distros; first readable one wins.
     * No single path is portable, so this is a best-effort search --
     * operators on anything else should pass --mqtt-cafile explicitly. */
    static const char *candidates[] = {
        "/etc/ssl/certs/ca-certificates.crt",  /* Debian/Ubuntu/Arch */
        "/etc/pki/tls/certs/ca-bundle.crt",    /* RHEL/Fedora/CentOS */
        "/etc/ssl/cert.pem",                   /* Alpine/macOS */
        NULL,
    };
    for (int i = 0; candidates[i]; ++i) {
        if (access(candidates[i], R_OK) == 0) return candidates[i];
    }
    return NULL;
}

void mqtt_init(void)
{
    if (!opt_mqtt_host) return;
    mosquitto_lib_init();
    g_mq = mosquitto_new(NULL, true, NULL);
    if (!g_mq) {
        fprintf(stderr, "mqtt: mosquitto_new failed\n");
        return;
    }

    if (opt_mqtt_tls) {
        const char *cafile = opt_mqtt_cafile ? opt_mqtt_cafile : find_default_cafile();
        if (!cafile && !opt_mqtt_insecure) {
            fprintf(stderr,
                    "mqtt: --mqtt-tls set but no CA bundle found; pass "
                    "--mqtt-cafile=PATH or --mqtt-insecure\n");
            mosquitto_destroy(g_mq); g_mq = NULL;
            return;
        }
        int rc = mosquitto_tls_set(g_mq, cafile, NULL, NULL, NULL, NULL);
        if (rc != MOSQ_ERR_SUCCESS) {
            fprintf(stderr, "mqtt: tls_set failed: %s\n", mosquitto_strerror(rc));
            mosquitto_destroy(g_mq); g_mq = NULL;
            return;
        }
        if (opt_mqtt_insecure) mosquitto_tls_insecure_set(g_mq, true);
    }
    if (opt_mqtt_user) {
        mosquitto_username_pw_set(g_mq, opt_mqtt_user, opt_mqtt_pass);
    }

    /* Observer mode: stable topic derived from iata+id (validated present
     * in options.c), with an online/offline status LWT so the platform's
     * dashboard can show this observer's connectivity -- set before
     * connect since the will can only be registered pre-connect. */
    if (opt_mqtt_observer) {
        size_t n = strlen("meshcore//status/") + strlen(opt_mqtt_iata) +
                   strlen(opt_mqtt_observer_id) + 1;
        g_status_topic = malloc(n);
        if (g_status_topic)
            snprintf(g_status_topic, n, "meshcore/%s/%s/status",
                     opt_mqtt_iata, opt_mqtt_observer_id);
        if (g_status_topic) {
            static const char offline[] = "{\"status\":\"offline\"}";
            mosquitto_will_set(g_mq, g_status_topic, (int)sizeof(offline) - 1,
                               offline, 0, true);
        }
    }

    int rc = mosquitto_connect(g_mq, opt_mqtt_host, opt_mqtt_port, 60);
    if (rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "mqtt: connect %s:%d failed: %s\n",
                opt_mqtt_host, opt_mqtt_port, mosquitto_strerror(rc));
        mosquitto_destroy(g_mq); g_mq = NULL;
        return;
    }
    /* mosquitto_loop_start() runs reads/writes in a background thread. */
    mosquitto_loop_start(g_mq);

    if (opt_mqtt_topic) {
        g_topic = strdup(opt_mqtt_topic);
    } else if (opt_mqtt_observer) {
        size_t n = strlen("meshcore//packets/") + strlen(opt_mqtt_iata) +
                   strlen(opt_mqtt_observer_id) + 1;
        g_topic = malloc(n);
        if (g_topic) snprintf(g_topic, n, "meshcore/%s/%s/packets",
                              opt_mqtt_iata, opt_mqtt_observer_id);
    } else {
        const char *st = opt_station_id ? opt_station_id : "default";
        size_t n = strlen("meshtastic/") + strlen(st) + 1;
        g_topic = malloc(n);
        if (g_topic) snprintf(g_topic, n, "meshtastic/%s", st);
    }
    if (!g_topic) {
        fprintf(stderr, "mqtt: topic allocation failed; publish disabled.\n");
        return;
    }
    if (g_status_topic) {
        static const char online[] = "{\"status\":\"online\"}";
        mosquitto_publish(g_mq, NULL, g_status_topic, (int)sizeof(online) - 1,
                          online, 0, true);
    }
    if (verbose) fprintf(stderr, "mqtt: connected %s:%d topic %s\n",
                          opt_mqtt_host, opt_mqtt_port, g_topic);
}

void mqtt_publish(const char *json, size_t len)
{
    if (!g_mq || !g_topic) return;
    /* QoS 0 (fire-and-forget), retain off. */
    mosquitto_publish(g_mq, NULL, g_topic, (int)len, json, 0, false);
}

void mqtt_shutdown(void)
{
    if (g_mq) {
        if (g_status_topic) {
            /* Best-effort: publish "offline" ourselves on a clean shutdown
             * rather than relying solely on the broker firing the LWT
             * (which is for ungraceful disconnects). loop_stop below still
             * flushes the background thread's write queue first. */
            static const char offline[] = "{\"status\":\"offline\"}";
            mosquitto_publish(g_mq, NULL, g_status_topic,
                              (int)sizeof(offline) - 1, offline, 0, true);
        }
        mosquitto_loop_stop(g_mq, true);
        mosquitto_disconnect(g_mq);
        mosquitto_destroy(g_mq);
        g_mq = NULL;
    }
    free(g_topic); g_topic = NULL;
    free(g_status_topic); g_status_topic = NULL;
    mosquitto_lib_cleanup();
}

#else  /* !HAVE_MQTT */

void mqtt_init(void) {}
void mqtt_publish(const char *json, size_t len) { (void)json; (void)len; }
void mqtt_shutdown(void) {}

#endif
