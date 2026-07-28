/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: outbound DEALER C2 socket.
 *
 * When --c2-dealer=tcp://host:port is set, opens a ZMQ DEALER socket
 * that connects outbound to a meshtastic-fusion ROUTER. NAT-friendly
 * (sensor connects out, no inbound port needed). Heartbeats every
 * 30 s; commands arrive as JSON envelopes that map to the same
 * handlers in c2.c that the HTTP path uses.
 *
 * Envelope:
 *   request:  {"cmd":"<name>", "body":"<arg string>", "id":<int>}
 *   reply:    {"id":<int>, "status":<int>, "body":"<json string>"}
 *
 * Stubbed to no-ops when libzmq isn't available at build time.
 */

#ifndef C2_DEALER_H
#define C2_DEALER_H

#include <stdbool.h>

bool c2_dealer_init(const char *endpoint);
void c2_dealer_shutdown(void);

#endif /* C2_DEALER_H */
