/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: CayenneLPP decode for MeshCore GRP_DATA blobs.
 * See meshcore_lpp.h for the wire-format rationale.
 *
 * Type table transcribed verbatim from MeshCore firmware's
 * src/helpers/sensors/LPPDataHelpers.h (electroniccats/CayenneLPP
 * variant) -- width in bytes, multiplier, signedness, and the number
 * of sub-values (1 for scalars, 3 for GPS/accelerometer/gyrometer/
 * colour). LPP_POLYLINE (240) is intentionally NOT supported: its
 * on-wire length is variable and even the firmware's own skipData()
 * comments its 8-byte skip as "TODO: this is MINIMUM" (i.e. not
 * reliably decodable), so any record with that type code fails
 * validation rather than risk desyncing the parse.
 */

#include "meshcore_lpp.h"

#include <string.h>
#include <stdio.h>

typedef struct {
    uint8_t     type;
    const char *name;
    const char *unit;
    int         width;      /* bytes per sub-value */
    int         n_values;   /* 1, or 3 for GPS/accel/gyro/colour */
    uint32_t    mult;
    bool        is_signed;
} lpp_type_info_t;

/* clang-format off */
static const lpp_type_info_t LPP_TYPES[] = {
    { 0,   "digital_in",       "",     1, 1, 1,     false },
    { 1,   "digital_out",      "",     1, 1, 1,     false },
    { 2,   "analog_in",        "",     2, 1, 100,   true  },
    { 3,   "analog_out",       "",     2, 1, 100,   true  },
    { 100, "generic",          "",     4, 1, 1,     false },
    { 101, "luminosity",       "lux",  2, 1, 1,     false },
    { 102, "presence",         "",     1, 1, 1,     false },
    { 103, "temperature",      "C",    2, 1, 10,    true  },
    { 104, "humidity",         "%",    1, 1, 2,     false },
    { 113, "accelerometer",    "G",    2, 3, 1000,  true  },
    { 115, "pressure",         "hPa",  2, 1, 10,    false },
    { 116, "voltage",          "V",    2, 1, 100,   false },
    { 117, "current",          "A",    2, 1, 1000,  true  },
    { 118, "frequency",        "Hz",   4, 1, 1,     false },
    { 120, "percentage",       "%",    1, 1, 1,     false },
    { 121, "altitude",         "m",    2, 1, 1,     true  },
    { 125, "concentration",    "ppm",  2, 1, 1,     false },
    { 128, "power",            "W",    2, 1, 1,     false },
    { 130, "distance",         "m",    4, 1, 1000,  false },
    { 131, "energy",           "kWh",  4, 1, 1000,  false },
    { 132, "direction",        "deg",  2, 1, 1,     false },
    { 133, "unixtime",         "",     4, 1, 1,     false },
    { 134, "gyrometer",        "deg/s",2, 3, 100,   true  },
    { 135, "colour",           "",     1, 3, 1,     false },
    { 136, "gps",              "",     3, 3, 0,     true  }, /* mixed mult, handled specially */
    { 142, "switch",           "",     1, 1, 1,     false },
};
/* clang-format on */
#define N_LPP_TYPES (int)(sizeof(LPP_TYPES) / sizeof(LPP_TYPES[0]))

static const lpp_type_info_t *lpp_type_lookup(uint8_t type)
{
    for (int i = 0; i < N_LPP_TYPES; ++i)
        if (LPP_TYPES[i].type == type) return &LPP_TYPES[i];
    return NULL;
}

static float lpp_read_value(const uint8_t *p, int width, uint32_t mult, bool is_signed)
{
    uint32_t raw = 0;
    for (int i = 0; i < width; ++i) raw = (raw << 8) | p[i];

    int sign = 1;
    if (is_signed) {
        uint32_t bit = 1u << (width * 8 - 1);
        if (raw & bit) {
            raw = (bit << 1) - raw;
            sign = -1;
        }
    }
    return mult ? (float)sign * ((float)raw / (float)mult) : (float)sign * (float)raw;
}

int meshcore_lpp_decode(const uint8_t *buf, size_t len,
                        meshcore_lpp_record_t *out, int max_records)
{
    if (!buf || len == 0) return -1;

    size_t pos = 0;
    int n = 0;
    while (pos < len) {
        if (pos + 2 > len) return -1;         /* truncated header */
        uint8_t channel = buf[pos];
        uint8_t type    = buf[pos + 1];
        pos += 2;
        if (channel == 0) return -1;          /* end-of-data marker mid-buffer: not a full record run */

        const lpp_type_info_t *ti = lpp_type_lookup(type);
        if (!ti) return -1;                   /* unknown type code -- not LPP (or a type we don't support) */

        size_t rec_bytes = (size_t)ti->width * (size_t)ti->n_values;
        if (pos + rec_bytes > len) return -1; /* truncated value */

        if (n < max_records) {
            meshcore_lpp_record_t *r = &out[n];
            r->channel   = channel;
            r->type      = type;
            r->type_name = ti->name;
            r->unit      = ti->unit;
            r->n_values  = ti->n_values;
            if (type == 136) {
                /* GPS: lat/lon /10000, alt /100, all 3-byte signed */
                r->values[0] = lpp_read_value(buf + pos,     3, 10000, true);
                r->values[1] = lpp_read_value(buf + pos + 3, 3, 10000, true);
                r->values[2] = lpp_read_value(buf + pos + 6, 3, 100,   true);
            } else {
                for (int v = 0; v < ti->n_values; ++v)
                    r->values[v] = lpp_read_value(buf + pos + (size_t)v * ti->width,
                                                  ti->width, ti->mult, ti->is_signed);
            }
        }
        n++;
        pos += rec_bytes;
    }

    if (n == 0) return -1;                    /* nothing decoded */
    return n > max_records ? max_records : n;
}

int meshcore_lpp_to_json(const meshcore_lpp_record_t *records, int n_records,
                         char *out, size_t cap)
{
    if (!out || cap == 0) return -1;
    size_t off = 0;
    int rc = snprintf(out + off, cap - off, "[");
    if (rc < 0 || (size_t)rc >= cap - off) return -1;
    off += (size_t)rc;

    for (int i = 0; i < n_records; ++i) {
        const meshcore_lpp_record_t *r = &records[i];
        if (r->n_values == 3) {
            rc = snprintf(out + off, cap - off,
                          "%s{\"ch\":%u,\"type\":%u,\"name\":\"%s\",\"unit\":\"%s\","
                          "\"value\":[%.4f,%.4f,%.4f]}",
                          i ? "," : "", r->channel, r->type, r->type_name, r->unit,
                          (double)r->values[0], (double)r->values[1], (double)r->values[2]);
        } else {
            rc = snprintf(out + off, cap - off,
                          "%s{\"ch\":%u,\"type\":%u,\"name\":\"%s\",\"unit\":\"%s\","
                          "\"value\":%.4f}",
                          i ? "," : "", r->channel, r->type, r->type_name, r->unit,
                          (double)r->values[0]);
        }
        if (rc < 0 || (size_t)rc >= cap - off) return -1;
        off += (size_t)rc;
    }

    rc = snprintf(out + off, cap - off, "]");
    if (rc < 0 || (size_t)rc >= cap - off) return -1;
    off += (size_t)rc;
    return (int)off;
}

int meshcore_lpp_to_text(const meshcore_lpp_record_t *records, int n_records,
                         char *out, size_t cap)
{
    if (!out || cap == 0) return -1;
    size_t off = 0;
    for (int i = 0; i < n_records; ++i) {
        const meshcore_lpp_record_t *r = &records[i];
        int rc;
        if (r->n_values == 3) {
            rc = snprintf(out + off, cap - off, "%s%s=%.3f,%.3f,%.3f%s",
                         i ? " " : "", r->type_name,
                         (double)r->values[0], (double)r->values[1], (double)r->values[2],
                         r->unit);
        } else {
            rc = snprintf(out + off, cap - off, "%s%s=%.2f%s",
                         i ? " " : "", r->type_name, (double)r->values[0], r->unit);
        }
        if (rc < 0 || (size_t)rc >= cap - off) return -1;
        off += (size_t)rc;
    }
    return (int)off;
}
