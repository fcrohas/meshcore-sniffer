/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: built-in web dashboard.
 *
 * Single-threaded TCP listener that accepts HTTP/1.1 connections.
 * GET /events upgrades to SSE; the socket is kept and registered in
 * a small client list. web_publish_line() iterates the list and
 * writes non-blocking; broken sockets are reaped.
 *
 * The dashboard HTML is a single embedded string -- Leaflet map +
 * node table + message log + discoveries panel, all wired to the
 * /events SSE stream.
 *
 */

#define _GNU_SOURCE
#include "web.h"
#include "c2.h"
#include "cot.h"
#include "keyset.h"
#include "options.h"
#include "db_sqlite.h"

extern keyset_t *app_get_keyset(void);
extern int       app_add_runtime_extra_freq(uint64_t f_hz, int bw_hz, int sf, int cr);

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_SSE_CLIENTS    8
#define HISTORY_RING_SIZE  1024  /* recent events replayed to new SSE clients */
#define API_MESSAGES_DEFAULT_LIMIT 100  /* GET /api/messages default row count */
#define API_MESSAGES_MAX_LIMIT     500  /* GET /api/messages hard cap */

static int  g_listen_fd = -1;
static int  g_sse_fds[MAX_SSE_CLIENTS];
static int  g_sse_count = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_thread;
static volatile int g_thread_running = 0;

/* Ring buffer of recently-published JSON lines. New SSE clients (browser
 * refresh, multi-tab) get the buffer's contents replayed to them so the
 * dashboard reconstructs its node / channel / activity / topology state
 * without having to wait for new traffic. Bounded memory: average event
 * is ~200 bytes -> <250 KB at full capacity. Cleared on sniffer restart;
 * the long-term archive feature is a separate, opt-in concern. */
typedef struct {
    char  *buf;
    size_t len;
} history_entry_t;
static history_entry_t g_history[HISTORY_RING_SIZE];
static int g_history_head  = 0;  /* index of next slot to write */
static int g_history_count = 0;  /* total entries currently stored, capped */

static const char DASHBOARD_HTML[] =
"<!doctype html>\n"
"<html><head><meta charset=\"utf-8\">\n"
"<title>meshcore-sniffer</title>\n"
"<link rel=\"stylesheet\" href=\"https://unpkg.com/leaflet@1.9.4/dist/leaflet.css\">\n"
"<script src=\"https://unpkg.com/leaflet@1.9.4/dist/leaflet.js\"></script>\n"
"<style>\n"
/* Slate palette mirroring inmarsat-sniffer: same family of tools.    */
"*{margin:0;padding:0;box-sizing:border-box}\n"
"body{font-family:system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;height:100vh;display:flex;flex-direction:column;font-size:14px}\n"
/* Persistent stats header (always visible across tabs).               */
"#bar{height:44px;flex-shrink:0;background:#1e293b;display:flex;align-items:center;padding:0 16px;gap:20px;border-bottom:1px solid #334155}\n"
"#bar .title{font-weight:600;color:#f8fafc;letter-spacing:0.5px}\n"
"#bar .stat{color:#94a3b8;font-size:13px}\n"
"#bar .val{color:#38bdf8;font-weight:600;font-variant-numeric:tabular-nums;margin-left:6px}\n"
"#bar #status{margin-left:auto;color:#64748b;font-size:12px}\n"
"#theme-toggle{background:transparent;color:inherit;border:1px solid currentColor;border-radius:4px;padding:0 8px;cursor:pointer;font-size:14px;line-height:22px;height:24px;opacity:0.55}\n"
"#theme-toggle:hover{opacity:1}\n"
/* Tab strip below the bar.                                           */
"#tabs{display:flex;align-items:center;background:#1e293b;border-bottom:1px solid #334155;flex-shrink:0}\n"
"#tabs button{background:none;color:#64748b;border:none;padding:8px 16px;cursor:pointer;font:inherit;text-transform:uppercase;font-size:12px;letter-spacing:1px;font-weight:600;border-bottom:2px solid transparent}\n"
"#tabs button:hover{color:#94a3b8}\n"
"#tabs button.active{color:#38bdf8;border-bottom-color:#38bdf8}\n"
".tab{flex:1;display:none;overflow:hidden}\n"
".tab.active{display:flex}\n"
/* Live tab: 2-col grid, map left, side panels right.                 */
".grid{display:grid;grid-template-columns:2fr 1fr;grid-template-rows:1fr 1fr 1fr 1fr;height:100%;width:100%;gap:1px;background:#334155}\n"
".pane{padding:8px 10px;overflow:auto;background:#0f172a}\n"
/* Live tab's mobile swipe-page indicator (see #live-swipe-nav markup
 * and the @media(max-width:860px) block below). Hidden on desktop --
 * the grid stays a normal CSS grid there, nothing to swipe between. */
"#live-swipe-nav{display:none}\n"
"#channelstab-swipe-nav{display:none}\n"
"#map{height:100%;width:100%}\n"
".leaflet-container{background:#0f172a}\n"
".leaflet-tooltip.node-id-label{background:rgba(15,23,42,0.85);border:1px solid #334155;color:#e2e8f0;font-size:10px;font-family:'SF Mono',Consolas,monospace;font-weight:600;padding:1px 4px;box-shadow:none}\n"
".leaflet-tooltip.node-id-label:before{display:none}\n"
"html.light .leaflet-tooltip.node-id-label{background:rgba(255,255,255,0.9);border-color:#cbd5e1;color:#1e293b}\n"
"h2{margin:0 0 6px 0;font-size:12px;color:#38bdf8;text-transform:uppercase;letter-spacing:1px;font-weight:600;border-bottom:1px solid #334155;padding-bottom:5px;display:flex;align-items:center;gap:8px}\n"
"h2 .muted{font-weight:400;text-transform:none;letter-spacing:0;color:#64748b;font-size:11px;flex:1}\n"
"h2 button{background:#1e293b;color:#cbd5e1;border:1px solid #334155;border-radius:3px;padding:3px 9px;cursor:pointer;font-size:11px}\n"
"h2 button:hover{background:#334155;color:#e2e8f0}\n"
"table{width:100%;border-collapse:collapse;font-size:12px;font-variant-numeric:tabular-nums}\n"
"th,td{text-align:left;padding:4px 6px;border-bottom:1px solid #1e293b}\n"
"th{color:#64748b;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:0.5px}\n"
"tr:hover td{background:#1e293b}\n"
".text{color:#4ade80}\n"
".disc{color:#fb923c}\n"
"button.promote{background:#0c4a6e;color:#bae6fd;border:1px solid #0284c7;border-radius:3px;padding:1px 8px;cursor:pointer;font-size:10px;margin-left:6px}\n"
"button.promote:hover{background:#075985;color:#e0f2fe}\n"
"button.promote:disabled{opacity:0.6;cursor:default}\n"
"html.light button.promote{background:#e0f2fe;color:#0c4a6e;border-color:#0284c7}\n"
"html.light button.promote:hover{background:#bae6fd}\n"
".atak{color:#f472b6}\n"
".muted{color:#64748b}\n"
"#analyzertbl{table-layout:fixed;width:100%}\n"
"#analyzertbl td.hex{font-family:monospace;font-size:11px;word-break:break-all;white-space:normal}\n"
"#analyzertbl td.mctype{color:#38bdf8;white-space:nowrap}\n"
"#analyzertbl td.ts{white-space:nowrap;color:#64748b}\n"
"#analyzertbl td.aexp{width:16px;cursor:pointer;color:#64748b;text-align:center}\n"
"#analyzertbl td.proto,#analyzertbl td.node,#analyzertbl td.chan,#analyzertbl td.snr{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:0}\n"
"tr.analyzer-row{cursor:pointer}\n"
"tr.analyzer-row:hover{background:#1e293b}\n"
"html.light tr.analyzer-row:hover{background:#e2e8f0}\n"
"tr.analyzer-detail td{background:#0b1220;padding:8px 12px}\n"
"html.light tr.analyzer-detail td{background:#f1f5f9}\n"
".analyzer-detail-tbl{width:100%;border-collapse:collapse;font-size:11px}\n"
".analyzer-detail-tbl td{padding:2px 8px 2px 0;vertical-align:top;border:none}\n"
".analyzer-detail-tbl td.k{color:#64748b;white-space:nowrap;width:1%}\n"
".analyzer-detail-tbl td.v{font-family:monospace;word-break:break-all}\n"
".analyzer-detail-tbl td.vmuted{font-family:monospace;word-break:break-all;color:#64748b}\n"
".crc-badge{border-radius:3px;padding:1px 6px;font-size:10px;font-weight:600}\n"
".crc-badge.crc-ok{background:#064e3b;color:#6ee7b7}\n"
".crc-badge.crc-corrected{background:#78350f;color:#fcd34d}\n"
".crc-badge.crc-fail{background:#450a0a;color:#fca5a5}\n"
".btn-mini{background:#1e293b;color:#cbd5e1;border:1px solid #334155;border-radius:3px;padding:1px 6px;cursor:pointer;font-size:10px;margin-left:6px}\n"
"html.light .btn-mini{background:#e2e8f0;color:#334155;border-color:#cbd5e1}\n"
".log-item{padding:5px 0;border-bottom:1px dotted #1e293b;font-size:12px;line-height:1.5;word-wrap:break-word}\n"
".log-item .ts{color:#64748b;font-size:11px;margin-right:6px}\n"
".log-item b{color:#38bdf8}\n"
".port{color:#a78bfa;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;background:#1e1b2e;padding:1px 5px;border-radius:3px;margin:0 4px}\n"
".snr-arrow{margin-left:3px;font-size:12px;line-height:1}\n"
".snr-up   {color:#4ade80}\n"
".snr-down {color:#f87171}\n"
".snr-flat {color:#64748b}\n"
/* Config tab is plain block content -- override the
 * .tab.active{display:flex} that's right for Live.
 * Topology tab uses a flex column so the canvas can fill the pane. */
"#config.tab.active{display:block}\n"
"#stats.tab.active{display:block}\n"
"#topology.tab.active{display:flex;flex-direction:column}\n"
"#topology{position:relative;overflow:hidden}\n"
"#topo-canvas{flex:1;display:block;width:100%;background:#0f172a;cursor:default}\n"
"#topo-canvas.hovering{cursor:pointer}\n"
"#topo-empty{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);max-width:480px;text-align:center;pointer-events:none;z-index:5}\n"
"#topo-legend{position:absolute;left:10px;top:10px;color:#64748b;font-size:11px;background:rgba(15,23,42,0.85);padding:7px 11px;border-radius:3px;border:1px solid #334155;z-index:4;pointer-events:none}\n"
"#topo-legend .l-node{display:inline-block;width:8px;height:8px;border-radius:50%;background:#38bdf8;vertical-align:middle;margin-right:3px}\n"
"#topo-legend .l-repeater{display:inline-block;width:8px;height:8px;background:#38bdf8;vertical-align:middle;margin-right:3px}\n"
"#topo-legend .l-edge{display:inline-block;width:14px;height:1px;background:#94a3b8;vertical-align:middle;margin-right:3px}\n"
"#topo-legend .l-relay{display:inline-block;width:14px;height:3px;background:#4ade80;vertical-align:middle;margin-right:3px}\n"
"html.light #topo-canvas{background:#ffffff}\n"
"html.light #topo-legend{background:rgba(255,255,255,0.92);color:#475569;border-color:#cbd5e1}\n"
/* Channels tab: list of channels on the left, message log (with
 * per-message routing path) for the selected channel on the right.
 * The base .tab.active{display:flex} rule already gives a flex row,
 * so the two panes split side by side with no extra override. */
"#channels-list-pane{width:340px;flex-shrink:0}\n"
/* Add-by-hashtag control (no key needed) at the top of the channel
 * list -- mirrors the Config tab's textarea/input/button/.hint
 * styling (#config rules below) so it doesn't look like a bare
 * unstyled browser form. */
"#channels-list-pane .row{margin-bottom:12px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}\n"
"#channels-list-pane input[type=text]{flex:1;min-width:120px;box-sizing:border-box;background:#0f172a;color:#e2e8f0;border:1px solid #334155;border-radius:3px;padding:7px 10px;font-family:'SF Mono',Consolas,monospace;font-size:13px}\n"
"#channels-list-pane input[type=text]:focus{outline:none;border-color:#38bdf8}\n"
"#channels-list-pane button{background:#0c4a6e;color:#bae6fd;border:1px solid #0284c7;border-radius:3px;padding:7px 16px;cursor:pointer;font-size:13px;font-weight:500}\n"
"#channels-list-pane button:hover{background:#075985;color:#e0f2fe}\n"
"#channels-list-pane button:disabled{opacity:0.6;cursor:default}\n"
"#channels-list-pane .hint{color:#64748b;font-size:12px}\n"
"html.light #channels-list-pane input[type=text]{background:#ffffff;color:#1e293b;border-color:#cbd5e1}\n"
"html.light #channels-list-pane input[type=text]:focus{border-color:#0284c7}\n"
"html.light #channels-list-pane button{background:#e0f2fe;color:#0c4a6e;border-color:#0284c7}\n"
"html.light #channels-list-pane button:hover{background:#bae6fd}\n"
"html.light #channels-list-pane .hint{color:#94a3b8}\n"
"#channels-msgs-pane{flex:1;min-width:0;display:flex;flex-direction:column}\n"
/* Wrapper around #channels-list-pane/#channels-msgs-pane. Transparent
 * pass-through on desktop (flex row, fills available width) so their
 * existing 340px+flex:1 side-by-side layout is unchanged; becomes a
 * horizontal swipe carousel on mobile (see @media(max-width:860px)
 * and #channelstab-swipe-nav). Not reusing .grid (Live tab's wrapper)
 * since that's a real CSS grid on desktop (2fr/1fr columns, 4 rows)
 * -- wrong shape for these two panes. */
"#channelstab .swipepanes{display:flex;flex-direction:row;flex:1;min-width:0;width:100%}\n"
"tr.chan-row{cursor:pointer}\n"
"tr.chan-row.selected td{background:#1e3a5f}\n"
"html.light tr.chan-row.selected td{background:#dbeafe}\n"
/* Channel messages rendered as a chat log: one bubble per message,
 * newest first (matches the existing "load older" pagination, which
 * appends further back in time). */
"#chantab-msgs.chat-log{display:flex;flex-direction:column;gap:10px;padding:4px 2px}\n"
"#chantab-msgs .chat-msg{display:flex}\n"
"#chantab-msgs .chat-msg.side-b{justify-content:flex-end}\n"
"#chantab-msgs .chat-col{display:flex;flex-direction:column;max-width:min(560px,78%)}\n"
"#chantab-msgs .chat-msg.side-b .chat-col{align-items:flex-end}\n"
"#chantab-msgs .chat-meta{font-size:11px;color:#64748b;margin-bottom:3px}\n"
"#chantab-msgs .chat-meta b{color:#38bdf8;font-weight:600}\n"
"#chantab-msgs .chat-msg.side-b .chat-meta b{color:#4ade80}\n"
"#chantab-msgs .chat-bubble{background:#1e293b;border-radius:12px;padding:8px 12px;font-size:13px;line-height:1.4;word-wrap:break-word;white-space:pre-wrap;display:inline-block}\n"
"#chantab-msgs .chat-msg.side-b .chat-bubble{background:#1e3a5f}\n"
"#chantab-msgs .chat-foot{display:flex;align-items:center;gap:8px;margin-top:4px;font-size:11px;color:#64748b}\n"
"#chantab-msgs .chat-path{font-family:'SF Mono',Consolas,monospace;color:#94a3b8;word-break:break-all}\n"
"html.light #chantab-msgs .chat-bubble{background:#e2e8f0;color:#1e293b}\n"
"html.light #chantab-msgs .chat-msg.side-b .chat-bubble{background:#dbeafe}\n"
"html.light #chantab-msgs .chat-msg.side-b .chat-meta b{color:#0284c7}\n"
"html.light #chantab-msgs .chat-meta,html.light #chantab-msgs .chat-foot{color:#94a3b8}\n"
"html.light #chantab-msgs .chat-path{color:#64748b}\n"
".empty-hint{color:#64748b;font-size:13px;padding:24px 4px;text-align:center;font-style:italic}\n"
"html.light .empty-hint{color:#94a3b8}\n"
"#config{padding:18px;overflow:auto;max-width:820px;width:100%}\n"
"#config h3{margin:18px 0 6px 0;font-size:12px;color:#38bdf8;text-transform:uppercase;letter-spacing:1px;font-weight:600;border-bottom:1px solid #334155;padding-bottom:4px}\n"
"#config h3:first-child{margin-top:0}\n"
/* Statistics tab: filter row + up to 3 cards (2 donuts + 1 CRC bar). */
"#stats{padding:18px;overflow:auto;width:100%}\n"
"#stats h3{margin:0 0 10px 0;font-size:12px;color:#38bdf8;text-transform:uppercase;letter-spacing:1px;font-weight:600;border-bottom:1px solid #334155;padding-bottom:4px}\n"
"#stats-filter.row{display:flex;gap:8px;margin-bottom:14px}\n"
".stats-window-btn.active{background:#0c4a6e;color:#bae6fd;border-color:#0284c7}\n"
"#stats-charts{display:flex;flex-wrap:wrap;gap:16px}\n"
".stats-card{background:#1e293b;border-radius:4px;padding:14px;flex:1;min-width:280px}\n"
".stats-chart-row{display:flex;align-items:center;gap:16px}\n"
".donut-wrap svg{display:block}\n"
".chart-legend{font-size:12px;line-height:1.7}\n"
".chart-legend .sw{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px;vertical-align:middle}\n"
".chart-legend .cnt{color:#64748b;margin-left:4px}\n"
"#stats-crcbar{display:flex;height:22px;border-radius:3px;overflow:hidden;margin:8px 0}\n"
".stats-table{margin-top:10px;width:100%}\n"
"#config textarea,#config input[type=text]{width:100%;box-sizing:border-box;background:#0f172a;color:#e2e8f0;border:1px solid #334155;border-radius:3px;padding:8px 10px;font-family:'SF Mono',Consolas,monospace;font-size:13px}\n"
"#config textarea:focus,#config input[type=text]:focus{outline:none;border-color:#38bdf8}\n"
"#config button{background:#0c4a6e;color:#bae6fd;border:1px solid #0284c7;border-radius:3px;padding:7px 16px;cursor:pointer;margin-top:6px;margin-right:8px;font-size:13px;font-weight:500}\n"
"#config button:hover{background:#075985;color:#e0f2fe}\n"
"#config .hint{color:#64748b;font-size:12px;margin-top:4px;display:block}\n"
"#config .row{margin-bottom:14px}\n"
".status-ok{color:#4ade80}\n"
".status-err{color:#f87171}\n"
/* Light theme overrides (dark stays default; toggled via html.light). */
"html.light body{background:#f8fafc;color:#1e293b}\n"
"html.light #bar{background:#ffffff;border-bottom-color:#cbd5e1}\n"
"html.light #bar .title{color:#0f172a}\n"
"html.light #bar .stat{color:#475569}\n"
"html.light #bar .val{color:#0284c7}\n"
"html.light #bar #status{color:#94a3b8}\n"
"html.light #tabs{background:#ffffff;border-bottom-color:#cbd5e1}\n"
"html.light #tabs button{color:#94a3b8}\n"
"html.light #tabs button:hover{color:#475569}\n"
"html.light #tabs button.active{color:#0284c7;border-bottom-color:#0284c7}\n"
"html.light .pane{background:#ffffff}\n"
"html.light h2{color:#0284c7;border-bottom-color:#e2e8f0}\n"
"html.light h2 .muted{color:#94a3b8}\n"
"html.light h2 button{background:#f1f5f9;color:#475569;border-color:#cbd5e1}\n"
"html.light h2 button:hover{background:#e2e8f0;color:#1e293b}\n"
"html.light th{color:#94a3b8}\n"
"html.light th,html.light td{border-bottom-color:#f1f5f9}\n"
"html.light tr:hover td{background:#f8fafc}\n"
"html.light .text{color:#15803d}\n"
"html.light .disc{color:#c2410c}\n"
"html.light .atak{color:#a21caf}\n"
"html.light .muted{color:#94a3b8}\n"
"html.light .log-item{border-bottom-color:#e2e8f0}\n"
"html.light .log-item .ts{color:#94a3b8}\n"
"html.light .log-item b{color:#0284c7}\n"
"html.light .grid{background:#cbd5e1}\n"
"html.light .leaflet-container{background:#f8fafc}\n"
"html.light #config h3{color:#0284c7;border-bottom-color:#e2e8f0}\n"
"html.light #stats h3{color:#0284c7;border-bottom-color:#e2e8f0}\n"
"html.light .stats-card{background:#f1f5f9}\n"
"html.light .stats-window-btn.active{background:#e0f2fe;color:#0c4a6e;border-color:#0284c7}\n"
"html.light .chart-legend .cnt{color:#94a3b8}\n"
"html.light #config textarea,html.light #config input[type=text]{background:#ffffff;color:#1e293b;border-color:#cbd5e1}\n"
"html.light #config textarea:focus,html.light #config input[type=text]:focus{border-color:#0284c7}\n"
"html.light #config button{background:#e0f2fe;color:#0c4a6e;border-color:#0284c7}\n"
"html.light #config button:hover{background:#bae6fd}\n"
"html.light #config .hint{color:#64748b}\n"
/* Nodes table: search input + sortable headers + clickable rows.       */
".tbl-tools{display:flex;align-items:center;gap:6px;margin:0 0 5px 0}\n"
".tbl-tools input{flex:1;background:#0f172a;color:#e2e8f0;border:1px solid #334155;border-radius:3px;padding:4px 8px;font-size:12px;font-family:inherit}\n"
".tbl-tools input:focus{outline:none;border-color:#38bdf8}\n"
".tbl-tools select{background:#0f172a;color:#e2e8f0;border:1px solid #334155;border-radius:3px;padding:4px 6px;font-size:12px;font-family:inherit}\n"
".tbl-tools select:focus{outline:none;border-color:#38bdf8}\n"
".tbl-tools .count{color:#64748b;font-size:11px;white-space:nowrap}\n"
"th.sortable{cursor:pointer;user-select:none}\n"
"th.sortable:hover{color:#38bdf8}\n"
"th.sortable .arr{display:inline-block;width:10px;color:#38bdf8;font-size:10px}\n"
"tr.node-row{cursor:pointer}\n"
"tr.node-row.selected td{background:#1e3a5f}\n"
"html.light .tbl-tools input{background:#ffffff;color:#1e293b;border-color:#cbd5e1}\n"
"html.light .tbl-tools input:focus{border-color:#0284c7}\n"
"html.light .tbl-tools select{background:#ffffff;color:#1e293b;border-color:#cbd5e1}\n"
"html.light .tbl-tools select:focus{border-color:#0284c7}\n"
"html.light .tbl-tools .count{color:#94a3b8}\n"
"html.light th.sortable:hover{color:#0284c7}\n"
"html.light th.sortable .arr{color:#0284c7}\n"
"html.light tr.node-row.selected td{background:#dbeafe}\n"
/* Drawer: slide-in detail panel from the right. Overlays the live grid */
/* but doesn't fully cover the map -- 380px wide is intentional.        */
"#drawer{position:fixed;top:44px;bottom:0;right:0;width:380px;max-width:90vw;background:#0f172a;border-left:1px solid #334155;box-shadow:-4px 0 16px rgba(0,0,0,0.4);transform:translateX(100%);transition:transform 0.18s ease;z-index:600;display:flex;flex-direction:column;overflow:hidden}\n"
"#drawer.open{transform:translateX(0)}\n"
"#drawer-head{padding:12px 14px;border-bottom:1px solid #334155;display:flex;align-items:flex-start;gap:8px}\n"
"#drawer-head .grow{flex:1;min-width:0}\n"
"#drawer-head .nm{font-size:15px;font-weight:600;color:#f8fafc;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}\n"
"#drawer-head .id{font-size:12px;color:#64748b;font-family:'SF Mono',Consolas,monospace;margin-top:2px}\n"
"#drawer-head .close{background:transparent;color:#64748b;border:none;font-size:20px;cursor:pointer;padding:0 6px;line-height:1}\n"
"#drawer-head .close:hover{color:#e2e8f0}\n"
"#drawer-body{flex:1;overflow-y:auto;padding:8px 14px}\n"
"#drawer-body section{margin:14px 0}\n"
"#drawer-body section:first-child{margin-top:6px}\n"
"#drawer-body h3{font-size:11px;color:#38bdf8;text-transform:uppercase;letter-spacing:1px;font-weight:600;margin-bottom:6px}\n"
".metric-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:6px}\n"
".metric{background:#1e293b;border-radius:3px;padding:7px 9px}\n"
".metric .lbl{color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:0.5px}\n"
".metric .v{color:#38bdf8;font-size:15px;font-weight:600;font-variant-numeric:tabular-nums}\n"
"#drawer-spark{display:block;width:100%;height:54px;background:#1e293b;border-radius:3px}\n"
"#drawer-msgs,#drawer-pos{font-size:12px;line-height:1.5;max-height:160px;overflow-y:auto}\n"
"#drawer-msgs .item{padding:4px 0;border-bottom:1px dotted #1e293b}\n"
"#drawer-pos td{padding:3px 6px;border:none;font-size:11px;font-family:'SF Mono',Consolas,monospace}\n"
"html.light #drawer{background:#ffffff;border-left-color:#cbd5e1;box-shadow:-4px 0 16px rgba(15,23,42,0.08)}\n"
"html.light #drawer-head{border-bottom-color:#e2e8f0}\n"
"html.light #drawer-head .nm{color:#0f172a}\n"
"html.light #drawer-head .id{color:#94a3b8}\n"
"html.light #drawer-body h3{color:#0284c7}\n"
"html.light .metric{background:#f1f5f9}\n"
"html.light .metric .lbl{color:#94a3b8}\n"
"html.light .metric .v{color:#0284c7}\n"
"html.light #drawer-spark{background:#f1f5f9}\n"
"html.light #drawer-msgs .item{border-bottom-color:#e2e8f0}\n"
/* Mobile / narrow-viewport layout. Desktop relies on the Live tab's
 * 2-col/4-row grid filling a tall viewport with each pane scrolling
 * internally; on a phone there isn't vertical room for that, so we
 * flatten the grid into a stacked column and let the whole tab
 * scroll instead. Same idea for the Channels tab's side-by-side
 * panes. */
"@media (max-width:860px){\n"
"  body{font-size:13px}\n"
"  #bar{height:auto;flex-wrap:wrap;row-gap:4px;padding:8px 12px}\n"
"  #bar .title{flex:1 0 100%}\n"
"  #bar #status{margin-left:0}\n"
"  #tabs{overflow-x:auto;-webkit-overflow-scrolling:touch}\n"
"  #tabs button{flex-shrink:0;padding:10px 14px}\n"
"  .tab.active{overflow-y:auto;-webkit-overflow-scrolling:touch}\n"
/* Live tab: horizontal swipeable carousel (map/nodes/channels/
 * messages/discoveries) instead of one long vertical stack -- each
 * pane is a full-viewport "page", native CSS scroll-snap handles the
 * touch swipe (no custom gesture JS needed). #live.tab.active
 * overrides the generic .tab.active{overflow-y:auto} above (wins on
 * specificity regardless of source order) since paging is now
 * horizontal and each pane scrolls its own content vertically --
 * letting the outer tab ALSO scroll vertically would fight the snap.
 * .tab.active's flex:1 (base stylesheet) already sizes #live to
 * fill the viewport between #bar/#tabs, so no height calc() needed. */
"  #live.tab.active{overflow:hidden;flex-direction:column}\n"
"  #live .grid{display:flex;flex-direction:row;flex-wrap:nowrap;flex:1;min-height:0;width:100%;"
"overflow-x:auto;overflow-y:hidden;scroll-snap-type:x mandatory;-webkit-overflow-scrolling:touch}\n"
"  #live .grid .pane{flex:0 0 100%;width:100%;height:100%;box-sizing:border-box;"
"scroll-snap-align:start;scroll-snap-stop:always;overflow-y:auto}\n"
/* Styled to match #tabs button above (flat underline tab, not a
 * rounded pill/chip) -- this is a second tier of tabs, not a row of
 * action buttons, so it should read as one. */
"  #live-swipe-nav{display:flex;overflow-x:auto;background:#1e293b;"
"border-bottom:1px solid #334155;flex-shrink:0;-webkit-overflow-scrolling:touch}\n"
"  #live-swipe-nav button{flex:0 0 auto;background:none;color:#64748b;border:none;padding:7px 14px;"
"cursor:pointer;font:inherit;text-transform:uppercase;font-size:11px;letter-spacing:0.5px;"
"font-weight:600;border-bottom:2px solid transparent;white-space:nowrap}\n"
"  #live-swipe-nav button.active{color:#38bdf8;border-bottom-color:#38bdf8}\n"
/* Channels tab: same horizontal swipe-carousel treatment as Live
 * (see the #live rules above) -- #channelstab-swipe-nav on top,
 * .swipepanes below as the two-page (Channels list / Messages) snap
 * container. selectChannel() also auto-swipes to the Messages page
 * on mobile once a channel is picked -- see the JS. */
"  #channelstab.tab.active{overflow:hidden;flex-direction:column}\n"
"  #channelstab .swipepanes{flex-direction:row;flex:1;min-height:0;width:100%;"
"overflow-x:auto;overflow-y:hidden;scroll-snap-type:x mandatory;-webkit-overflow-scrolling:touch}\n"
"  #channels-list-pane{flex:0 0 100%;width:100%;height:100%;max-height:none;box-sizing:border-box;"
"scroll-snap-align:start;scroll-snap-stop:always;overflow-y:auto}\n"
"  #channels-msgs-pane{flex:0 0 100%;width:100%;height:100%;box-sizing:border-box;"
"scroll-snap-align:start;scroll-snap-stop:always;overflow-y:auto}\n"
"  #channelstab-swipe-nav{display:flex;overflow-x:auto;background:#1e293b;"
"border-bottom:1px solid #334155;flex-shrink:0;-webkit-overflow-scrolling:touch}\n"
"  #channelstab-swipe-nav button{flex:0 0 auto;background:none;color:#64748b;border:none;padding:7px 14px;"
"cursor:pointer;font:inherit;text-transform:uppercase;font-size:11px;letter-spacing:0.5px;"
"font-weight:600;border-bottom:2px solid transparent;white-space:nowrap}\n"
"  #channelstab-swipe-nav button.active{color:#38bdf8;border-bottom-color:#38bdf8}\n"
"  #config{padding:14px}\n"
"  .metric-grid{grid-template-columns:1fr 1fr}\n"
"  #drawer{width:100%;max-width:100vw;top:0;padding-top:44px}\n"
"  table{font-size:11px}\n"
"  th,td{padding:6px 4px}\n"
"  .stats-card{min-width:100%}\n"
"  .tbl-tools{flex-wrap:wrap}\n"
"  .tbl-tools input{min-width:150px}\n"
"  #tabs button,h2 button,.btn-mini,button.promote,#config button,#channels-list-pane button{min-height:28px}\n"
"}\n"
"@media (max-width:480px){\n"
"  #bar .stat{display:none}\n"
"  .metric-grid{grid-template-columns:1fr}\n"
"}\n"
"</style></head><body>\n"
"<div id=\"bar\">\n"
"  <span class=\"title\">meshcore-sniffer</span>\n"
"  <span class=\"stat\">Rate <span id=\"st-msps\" class=\"val\">--</span> Msps</span>\n"
"  <span class=\"stat\">Frames <span id=\"st-frames\" class=\"val\">0</span></span>\n"
"  <span class=\"stat\">Decrypted <span id=\"st-decrypted\" class=\"val\">0</span></span>\n"
"  <span class=\"stat\" id=\"st-offgrid-wrap\" style=\"display:none\">Off-grid <span id=\"st-offgrid\" class=\"val\">0</span></span>\n"
"  <span class=\"stat\" id=\"st-focus-wrap\" style=\"display:none\" title=\"Focused pool: workers / promotions / dropped / below-snr / cumulative focus-decoded frames\">Focus <span id=\"st-focus\" class=\"val\">--</span></span>\n"
"  <span class=\"stat\" id=\"st-clock-wrap\" style=\"display:none\" title=\"Self-reported clock-discipline class (--station-t-acc-ns). Affects TDOA accuracy when 3+ stations correlate.\">Clock <span id=\"st-clock\" class=\"val\">--</span></span>\n"
"  <span id=\"status\">connecting...</span>\n"
"  <button id=\"theme-toggle\" onclick=\"toggleTheme()\" title=\"Toggle light/dark theme\">dark</button>\n"
"</div>\n"
"<div id=\"tabs\">\n"
"  <button id=\"tab-live\" class=\"active\" onclick=\"showTab('live')\">Live</button>\n"
"  <button id=\"tab-channelstab\" onclick=\"showTab('channelstab')\">Channels</button>\n"
"  <button id=\"tab-topology\" onclick=\"showTab('topology')\">Topology</button>\n"
"  <button id=\"tab-config\" onclick=\"showTab('config')\">Config</button>\n"
"  <button id=\"tab-stats\" onclick=\"showTab('stats')\">Statistics</button>\n"
"  <button id=\"tab-analyzer\" onclick=\"showTab('analyzer')\">Analyzer</button>\n"
"  <button id=\"tab-telemetry\" onclick=\"showTab('telemetry')\">Telemetry</button>\n"
"</div>\n"
"<div id=\"live\" class=\"tab active\">\n"
"  <div id=\"live-swipe-nav\">\n"
"    <button data-idx=\"0\" class=\"active\">Map</button>\n"
"    <button data-idx=\"1\">Nodes</button>\n"
"    <button data-idx=\"2\">Channels</button>\n"
"    <button data-idx=\"3\">Messages</button>\n"
"    <button data-idx=\"4\">Discoveries</button>\n"
"  </div>\n"
"  <div class=\"grid\">\n"
"    <div class=\"pane\" style=\"grid-row:span 4;padding:0;\"><div id=\"map\"></div></div>\n"
"    <div class=\"pane\"><h2>Nodes <span class=muted id=\"nodes-count\"></span><button onclick=\"exportCsv()\" style=\"background:#1e293b;color:#cbd5e1;border:1px solid #334155;border-radius:3px;padding:2px 8px;cursor:pointer;font-size:10px;\">CSV</button></h2>\n"
"      <div class=\"tbl-tools\"><input id=\"nodes-search\" type=\"text\" placeholder=\"Search id, name...\" autocomplete=\"off\"></div>\n"
"      <table id=\"nodes\">\n"
"        <thead><tr>\n"
"          <th class=\"sortable\" data-sort=\"id\">ID<span class=arr></span></th>\n"
"          <th class=\"sortable\" data-sort=\"name\">Name<span class=arr></span></th>\n"
"          <th class=\"sortable\" data-sort=\"snr\">SNR<span class=arr></span></th>\n"
"          <th class=\"sortable\" data-sort=\"frames\">Frames<span class=arr></span></th>\n"
"          <th class=\"sortable\" data-sort=\"ts\">Last seen<span class=arr></span></th>\n"
"        </tr></thead>\n"
"        <tbody></tbody>\n"
"      </table>\n"
"    </div>\n"
"    <div class=\"pane\"><h2>Channels <span class=muted>(by hash)</span></h2><table id=\"channels\"><thead><tr><th>Hash</th><th>Name</th><th>Preset</th><th>Frames</th><th>Decrypt</th><th>Slots</th><th>SNR (24h)</th><th>Last</th></tr></thead><tbody></tbody></table></div>\n"
"    <div class=\"pane\"><h2>Messages</h2><div id=\"msgs\"></div></div>\n"
"    <div class=\"pane\"><h2>Discoveries &amp; ATAK</h2><div id=\"disc\"></div></div>\n"
"  </div>\n"
"</div>\n"
"<div id=\"channelstab\" class=\"tab\">\n"
"  <div id=\"channelstab-swipe-nav\">\n"
"    <button data-idx=\"0\" class=\"active\">Channels</button>\n"
"    <button data-idx=\"1\">Messages</button>\n"
"  </div>\n"
"  <div class=\"swipepanes\">\n"
"  <div class=\"pane\" id=\"channels-list-pane\"><h2>Channels <span class=muted id=\"chantab-count\"></span></h2>\n"
"    <div class=\"row\"><input id=\"chantab-hashtag-input\" type=\"text\" placeholder=\"channel name (no key needed)\"><button id=\"chantab-hashtag-btn\" onclick=\"addHashtagChannel()\">Add</button> <span id=\"chantab-hashtag-status\" class=\"hint\"></span></div>\n"
"    <table id=\"chantab-list\"><thead><tr><th>Hash</th><th>Name</th><th>Protocol</th><th>Frames</th><th>Last</th></tr></thead><tbody></tbody></table>\n"
"    <div id=\"chantab-empty\" class=\"empty-hint\">Waiting for packets... channels appear as frames arrive.</div>\n"
"  </div>\n"
"  <div class=\"pane\" id=\"channels-msgs-pane\"><h2 id=\"chantab-msgs-title\">Messages <span class=muted>select a channel</span></h2>\n"
"    <div id=\"chantab-msgs\" class=\"chat-log\"></div>\n"
"    <div id=\"chantab-msgs-empty\" class=\"empty-hint\">Select a channel on the left to see its messages.</div>\n"
"    <div id=\"chantab-msgs-loadolder-wrap\" style=\"display:none\"><button id=\"chantab-msgs-loadolder\" class=\"btn-mini\">Load older messages</button> <span id=\"chantab-msgs-loadolder-status\" class=\"muted\"></span></div>\n"
"  </div>\n"
"</div>\n"
"<div id=\"topology\" class=\"tab\">\n"
"  <div id=\"topo-empty\" class=\"empty-hint\">Waiting for the first frame... nodes appear as soon as the sniffer hears them, and link up via NEIGHBORINFO and relay-hop hints.</div>\n"
"  <div id=\"topo-legend\"><span class=l-node></span> node, size = frames seen &nbsp;|&nbsp; <span class=l-repeater></span> repeater/room/sensor &nbsp;|&nbsp; <span class=l-edge></span> observed RX, color = SNR &nbsp;|&nbsp; <span class=l-relay></span> relay path, width = exchange count, radiates outward by hop-distance &nbsp;|&nbsp; click a node to inspect<span id=\"topo-relay-stats\"></span></div>\n"
"  <canvas id=\"topo-canvas\"></canvas>\n"
"</div>\n"
"<div id=\"config\" class=\"tab\">\n"
"  <h3>Add MeshCore channel</h3>\n"
"  <div class=\"row\">\n"
"    <textarea id=\"mc-channel-input\" rows=\"2\" placeholder=\"test&#10;Ops:izOH6cXN6mrJ5e26oRXNcg==\"></textarea>\n"
"    <button onclick=\"postMeshcoreChannel()\">Add</button>\n"
"    <span id=\"mc-channel-status\" class=\"hint\"></span>\n"
"    <div class=\"hint\">MeshCore has no numbered channels like Meshtastic -- group traffic is tagged only by a 1-byte hash of the shared secret. One spec per line, two forms: a bare Name (or #Name) joins a public hashtag channel exactly like the app's 'Add Channel' -- the secret is derived from the name, no key needed. Name:SECRET joins a private channel using an explicit hex (32/64 chars) or base64 secret someone shared with you. The default 'Public' channel is pre-loaded.</div>\n"
"    <div id=\"mc-channel-list\"></div>\n"
"    <div class=\"hint\">Remembered in this browser (localStorage) and re-added automatically on page load, since the sniffer itself forgets added channels on restart. \"Remove\" only forgets it here -- the sniffer keeps decrypting with it until restart.</div>\n"
"  </div>\n"
"  <h3>View options</h3>\n"
"  <div class=\"row\">\n"
"    <label><input type=\"checkbox\" id=\"showUntrusted\"> Show untrusted frames (CRC-fail or no-decrypt) in map / nodes / channels</label>\n"
"    <div class=\"hint\">Off by default. Frames without verified bytes (e.g. cross-slot phantoms of a real TX, or noise patterns that passed the 5-bit header checksum by chance) decode to corrupted from/to/packet_id fields. Surfacing them invents nodes that don't exist. Turn this on for diagnostic inspection of what the demod produced before trust filtering.</div>\n"
"  </div>\n"
"</div>\n"
"<div id=\"stats\" class=\"tab\">\n"
"  <div class=\"pane\" style=\"width:100%\">\n"
"    <h2>Statistics <span class=muted>MeshCore traffic, filtered by time window</span></h2>\n"
"    <div id=\"stats-filter\" class=\"row\">\n"
"      <button class=\"btn-mini stats-window-btn active\" data-window=\"24h\">24h</button>\n"
"      <button class=\"btn-mini stats-window-btn\" data-window=\"1w\">1 week</button>\n"
"      <button class=\"btn-mini stats-window-btn\" data-window=\"1m\">1 month</button>\n"
"    </div>\n"
"    <div id=\"stats-charts\">\n"
"      <div class=\"stats-card\" id=\"stats-card-type\">\n"
"        <h3>Message type</h3>\n"
"        <div class=\"stats-chart-row\">\n"
"          <div id=\"stats-donut-type\" class=\"donut-wrap\"></div>\n"
"          <div id=\"stats-legend-type\" class=\"chart-legend\"></div>\n"
"        </div>\n"
"        <button class=\"btn-mini stats-table-toggle\" data-target=\"type\">View as table</button>\n"
"        <table class=\"stats-table\" id=\"stats-table-type\" style=\"display:none\"><thead><tr><th>Type</th><th>Count</th><th>%</th></tr></thead><tbody></tbody></table>\n"
"      </div>\n"
"      <div class=\"stats-card\" id=\"stats-card-channel\">\n"
"        <h3>Channel</h3>\n"
"        <div class=\"stats-chart-row\">\n"
"          <div id=\"stats-donut-channel\" class=\"donut-wrap\"></div>\n"
"          <div id=\"stats-legend-channel\" class=\"chart-legend\"></div>\n"
"        </div>\n"
"        <button class=\"btn-mini stats-table-toggle\" data-target=\"channel\">View as table</button>\n"
"        <table class=\"stats-table\" id=\"stats-table-channel\" style=\"display:none\"><thead><tr><th>Channel</th><th>Count</th><th>%</th></tr></thead><tbody></tbody></table>\n"
"      </div>\n"
"      <div class=\"stats-card\" id=\"stats-card-crc\">\n"
"        <h3>CRC ratio</h3>\n"
"        <div id=\"stats-crcbar\"></div>\n"
"        <div id=\"stats-legend-crc\" class=\"chart-legend\"></div>\n"
"      </div>\n"
"    </div>\n"
"    <div id=\"stats-empty\" class=\"empty-hint\" style=\"display:none\">No MeshCore events with SQLite persistence in this window.</div>\n"
"  </div>\n"
"</div>\n"
"<div id=\"analyzer\" class=\"tab\">\n"
"  <div class=\"pane\"><h2>Analyzer <span class=muted>decoded frames, all protocols -- click a row to inspect</span> <span class=muted id=\"analyzer-count\"></span> <button onclick=\"clearAnalyzer()\" style=\"background:#1e293b;color:#cbd5e1;border:1px solid #334155;border-radius:3px;padding:2px 8px;cursor:pointer;font-size:10px;\">Clear</button></h2>\n"
"    <div class=\"tbl-tools\">\n"
"      <input id=\"analyzer-search\" type=\"text\" placeholder=\"Search node, channel, hex, text...\" autocomplete=\"off\">\n"
"      <select id=\"analyzer-filter-protocol\"><option value=\"\">All protocols</option><option value=\"meshcore\">MeshCore</option><option value=\"meshtastic\">Meshtastic</option></select>\n"
"      <select id=\"analyzer-filter-crc\"><option value=\"\">All CRC</option><option value=\"ok\">CRC ok</option><option value=\"corrected\">CRC corrected</option><option value=\"fail\">CRC fail</option></select>\n"
"    </div>\n"
"    <table id=\"analyzertbl\"><thead><tr><th></th><th>Time</th><th>Protocol</th><th>Type</th><th>Node</th><th>Channel</th><th>CRC</th><th>SNR</th><th>Frame (hex)</th></tr></thead><tbody></tbody></table>\n"
"    <div id=\"analyzer-empty\" class=\"empty-hint\">Waiting for frames...</div>\n"
"  </div>\n"
"</div>\n"
"<aside id=\"drawer\" aria-hidden=\"true\">\n"
"  <div id=\"drawer-head\">\n"
"    <div class=\"grow\"><div class=\"nm\" id=\"d-name\">--</div><div class=\"id\" id=\"d-id\">--</div></div>\n"
"    <button class=\"close\" onclick=\"closeDrawer()\" title=\"Close\">&times;</button>\n"
"  </div>\n"
"  <div id=\"drawer-body\">\n"
"    <section><div class=\"metric-grid\">\n"
"      <div class=\"metric\"><div class=\"lbl\">Frames</div><div class=\"v\" id=\"d-frames\">0</div></div>\n"
"      <div class=\"metric\"><div class=\"lbl\">Avg SNR</div><div class=\"v\" id=\"d-snr\">--</div></div>\n"
"      <div class=\"metric\"><div class=\"lbl\">Last seen</div><div class=\"v\" id=\"d-last\">--</div></div>\n"
"    </div></section>\n"
"    <section><h3>SNR (last 60)</h3><canvas id=\"drawer-spark\" width=\"360\" height=\"50\"></canvas></section>\n"
"    <section><h3>Recent messages</h3><div id=\"drawer-msgs\"></div></section>\n"
"    <section><h3>Recent positions</h3><div id=\"drawer-pos\"></div></section>\n"
"    <section><h3>Channels seen on</h3><div id=\"drawer-channels\"></div></section>\n"
"  </div>\n"
"</aside>\n"
"<script>\n"
"function showTab(name){\n"
"  for(const t of ['live','channelstab','topology','config','stats','analyzer']){\n"
"    document.getElementById(t).classList.toggle('active',t===name);\n"
"    document.getElementById('tab-'+t).classList.toggle('active',t===name);\n"
"  }\n"
"  /* Drawer slides over the tab content; if it stays open after a tab\n"
"   * switch it covers the new tab and looks broken. Close on every\n"
"   * switch -- user re-opens by clicking a row in the new tab. */\n"
"  if (drawerNodeId) closeDrawer();\n"
"  if (name==='live') setTimeout(()=>map.invalidateSize(),60);\n"
"  if (name==='channelstab') refreshChannelsTab();\n"
"  if (name==='stats') fetchStats();\n"
"  if (name==='telemetry') fetchTelemetry();\n"
"  if (name==='topology') topoStart(); else topoStop();\n"
"}\n"
/* Mobile swipe-page nav, shared by the Live tab (#live-swipe-nav +
 * .grid) and the Channels tab (#channelstab-swipe-nav + .swipepanes).
 * CSS-hidden on desktop -- see the @media(max-width:860px) block.
 * Clicking a pill scrolls the matching page into view; scrolling/
 * swiping the container (native CSS scroll-snap, no gesture JS)
 * updates which pill is highlighted. Both directions harmless no-ops
 * on desktop: the click handlers are only reachable through a hidden
 * element, and the container never overflows horizontally there so
 * scrollLeft stays 0. Returns a swipeTo(idx) function so other code
 * (e.g. selectChannel()) can navigate to a page programmatically. */
"function initSwipeNav(navId, containerSelector){\n"
"  const nav = document.getElementById(navId);\n"
"  const container = document.querySelector(containerSelector);\n"
"  if (!nav || !container) return () => {};\n"
"  const btns = Array.from(nav.querySelectorAll('button'));\n"
"  const pages = Array.from(container.querySelectorAll(':scope > .pane'));\n"
/* scrollIntoView() lets the browser walk the WHOLE ancestor chain
 * (including document/body) to satisfy its vertical alignment, which
 * on mobile was scrolling the page itself out from under the fixed
 * header -- the clicked page ended up "on top" with #bar/#tabs/nav
 * scrolled away instead of staying fullscreen. scrollTo() on just
 * this one container is exact and can't touch anything else. */
"  const swipeTo = (idx) => { if (pages[idx]) container.scrollTo({left: idx * container.clientWidth, behavior:'smooth'}); };\n"
"  btns.forEach((b, i) => b.addEventListener('click', () => swipeTo(i)));\n"
"  let raf = null;\n"
"  container.addEventListener('scroll', () => {\n"
"    if (raf) return;\n"
"    raf = requestAnimationFrame(() => {\n"
"      raf = null;\n"
"      const w = container.clientWidth || 1;\n"
"      const idx = Math.max(0, Math.min(btns.length - 1, Math.round(container.scrollLeft / w)));\n"
"      btns.forEach((b, i) => b.classList.toggle('active', i === idx));\n"
"    });\n"
"  }, {passive:true});\n"
"  return swipeTo;\n"
"}\n"
"initSwipeNav('live-swipe-nav', '#live .grid');\n"
"const channelsSwipeTo = initSwipeNav('channelstab-swipe-nav', '#channelstab .swipepanes');\n"
"// Theme toggle: dark is default, light persists in localStorage. Map\n"
"// tile layer swaps between Carto dark/light to match. Same pattern as\n"
"// inmarsat-sniffer / iridium-sniffer.\n"
"let tileLayer=null;\n"
"function setTheme(name){const html=document.documentElement;if(name==='light')html.classList.add('light');else html.classList.remove('light');try{localStorage.setItem('theme',name);}catch(e){}if(tileLayer)map.removeLayer(tileLayer);const url=(name==='light')?'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png':'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png';tileLayer=L.tileLayer(url,{maxZoom:19,attribution:'(c) OSM (c) CARTO'}).addTo(map);const btn=document.getElementById('theme-toggle');if(btn)btn.textContent=(name==='light')?'light':'dark';}\n"
"function toggleTheme(){setTheme(document.documentElement.classList.contains('light')?'dark':'light');}\n"
"const map = L.map('map').setView([39.5, -98.0], 4);\n"
"// Apply persisted theme (also adds the matching tile layer to the map).\n"
"setTheme((function(){try{return localStorage.getItem('theme')||'dark';}catch(e){return 'dark';}})());\n"
"const markers = {}, trails = {}, nodes = {}, edges = {}, channels = {};\n"
/* channels{} MUST be keyed by (hash, name), not hash alone: MeshCore's
 * channel_hash is a single byte (256 values), so two completely
 * distinct, independently-decrypting channels routinely collide on
 * the same hash (seen in practice: "#meteo" and "#lazarus" both
 * hashing to 0x78) -- keying by hash alone silently merged their
 * messages into one thread and flip-flopped the displayed name
 * between them every time a message from the other channel arrived.
 * Undecrypted traffic (channel_name unknown -- could belong to either
 * colliding channel, or a third unknown one) pools under the bare-
 * hash key since it can't be attributed to a specific channel. */
"function chanKey(hash, name){ return name ? (hash + '|' + name) : String(hash); }\n"
"function chanKeyHash(key){ return parseInt(key, 10); }\n"
"const msgsEl = document.getElementById('msgs'); const discEl = document.getElementById('disc'); const tbody = document.querySelector('#nodes tbody');\n"
"// Delegated click handler: 'promote' button on an OFF_GRID_LORA row\n"
"// POSTs the discovered freq + sensible (BW, SF, CR) to /api/extra-freq.\n"
"// On success the button text changes to '\\u2713 added' and disables; on\n"
"// error the row's button shows the failure inline.\n"
"discEl.addEventListener('click', async (e) => {\n"
"  const btn = e.target.closest('button.promote');\n"
"  if (!btn) return;\n"
"  const f  = btn.dataset.f, bw = btn.dataset.bw, sf = btn.dataset.sf, cr = btn.dataset.cr;\n"
"  btn.disabled = true; btn.textContent = '...';\n"
"  try {\n"
"    const r = await fetch('/api/extra-freq', { method: 'POST', body: `${f}:bw=${bw}:sf=${sf}:cr=${cr}` });\n"
"    const j = await r.json();\n"
"    if (r.ok && j.channel_id !== undefined) { btn.textContent = '\\u2713 added (ch '+j.channel_id+')'; }\n"
"    else { btn.textContent = 'failed'; btn.disabled = false; }\n"
"  } catch (err) { btn.textContent = 'error'; btn.disabled = false; }\n"
"});\n"
"const chTbody = document.querySelector('#channels tbody');\n"
"const analyzerTbody = document.querySelector('#analyzertbl tbody');\n"
"const analyzerEmpty = document.getElementById('analyzer-empty');\n"
"const analyzerCountEl = document.getElementById('analyzer-count');\n"
"const DEBUG_MAX = 500;\n"
"let analyzerSeq = 0;\n"
"const analyzerEvents = {};\n"
"let analyzerQuery = '', analyzerProtoFilter = '', analyzerCrcFilter = '';\n"
"let analyzerVisible = 0;\n"
/* Per-slot rolling SNR history, keyed by physical slot id. Filled from
 * CHAN_SNR SSE events; renderChannels() averages buckets across the
 * slots that map to each channel hash. */
"const chanSnr = {};\n"
"const nodesCount = document.getElementById('nodes-count');\n"
"const nodesSearch = document.getElementById('nodes-search');\n"
"// LRU cap on the nodes map. Busy environments produce hundreds of\n"
"// distinct ids; we keep the 1000 most-recently-seen and drop older ones\n"
"// (and their map markers/trails) so memory + paint cost stays bounded.\n"
"const NODES_MAX = 1000;\n"
"function evictNodes(){\n"
"  const ids = Object.keys(nodes);\n"
"  if (ids.length <= NODES_MAX) return;\n"
"  ids.sort((a,b)=>nodes[a].ts-nodes[b].ts);\n"
"  const drop = ids.length - NODES_MAX;\n"
"  for (let i=0;i<drop;++i){\n"
"    const id = ids[i];\n"
"    if (markers[id]) { map.removeLayer(markers[id]); delete markers[id]; }\n"
"    if (trails[id]) { if (trails[id].line) map.removeLayer(trails[id].line); delete trails[id]; }\n"
"    delete nodes[id];\n"
"  }\n"
"  if (drawerNodeId && !nodes[drawerNodeId]) closeDrawer();\n"
"}\n"
"function fmtTime(t){return new Date(t*1000).toLocaleTimeString();}\n"
"// Sortable + searchable Nodes table. State + RAF-coalesced renders so\n"
"// burst traffic doesn't trigger a full DOM rebuild per frame.\n"
"let nodesSortKey = 'ts', nodesSortDir = -1, nodesQuery = '';\n"
"function nodesValue(n, id, key){\n"
"  if (key==='id') return id;\n"
"  if (key==='name') return (n.name||'').toLowerCase();\n"
"  if (key==='snr') return n.snr_db===undefined ? -999 : n.snr_db;\n"
"  if (key==='frames') return n.frames||0;\n"
"  return n.ts||0;\n"
"}\n"
"function nodesCmp(aId, bId){\n"
"  const a = nodesValue(nodes[aId], aId, nodesSortKey);\n"
"  const b = nodesValue(nodes[bId], bId, nodesSortKey);\n"
"  if (a < b) return -1*nodesSortDir;\n"
"  if (a > b) return  1*nodesSortDir;\n"
"  return 0;\n"
"}\n"
"function nodesMatches(id, n){\n"
"  if (!nodesQuery) return true;\n"
"  if (id.toLowerCase().includes(nodesQuery)) return true;\n"
"  if (n.name && n.name.toLowerCase().includes(nodesQuery)) return true;\n"
"  return false;\n"
"}\n"
"let nodesRafQueued = false;\n"
"function refreshNodes(){\n"
"  if (nodesRafQueued) return;\n"
"  nodesRafQueued = true;\n"
"  requestAnimationFrame(()=>{ nodesRafQueued = false; renderNodes(); });\n"
"}\n"
"function renderNodes(){\n"
"  const all = Object.keys(nodes).filter(id=>!nodes[id].synthetic);\n"
"  const matched = nodesQuery ? all.filter(id=>nodesMatches(id, nodes[id])) : all;\n"
"  matched.sort(nodesCmp);\n"
"  // Cap rendered rows -- the table pane scrolls but rendering 5000 rows\n"
"  // costs us nothing useful. 200 is more than fits on screen.\n"
"  const TOPN = 200;\n"
"  const rows = matched.slice(0, TOPN);\n"
"  const frag = document.createDocumentFragment();\n"
"  for (const id of rows){\n"
"    const n = nodes[id];\n"
"    const tr = document.createElement('tr');\n"
"    tr.className = 'node-row' + (id===drawerNodeId ? ' selected' : '');\n"
"    tr.dataset.id = id;\n"
"    const snr = n.snr_db !== undefined ? n.snr_db.toFixed(1) + ' dB' : '<span class=muted>-</span>';\n"
"    // Name fallback: NODEINFO_APP isn't seen until a node broadcasts it\n"
"    // (15-30 min cadence), so unknown names are normal early on. Show\n"
"    // the last 4 hex digits of the id (matches what the device's own\n"
"    // LCD shows) plus a state hint: 'await' = decrypting OK but no\n"
"    // NODEINFO yet, 'enc' = at least one frame failed to decrypt.\n"
"    let name;\n"
"    if (n.name) {\n"
"      name = n.name;\n"
"    } else {\n"
"      const tail = id.length >= 5 ? id.slice(-4) : id;\n"
"      const state = n.has_encrypted ? 'enc' : 'await';\n"
"      name = `${tail} <span class=muted>(${state})</span>`;\n"
"    }\n"
"    tr.innerHTML = `<td>${id}</td><td>${name}</td><td>${snr}</td><td>${n.frames||0}</td><td>${fmtTime(n.ts)}</td>`;\n"
"    tr.onclick = ()=>openDrawer(id);\n"
"    frag.appendChild(tr);\n"
"  }\n"
"  tbody.replaceChildren(frag);\n"
"  const totalShown = matched.length, totalAll = all.length;\n"
"  if (nodesQuery) nodesCount.textContent = `(${Math.min(rows.length,totalShown)}/${totalShown} of ${totalAll})`;\n"
"  else nodesCount.textContent = `(${Math.min(rows.length,totalAll)} of ${totalAll})`;\n"
"  // Update sort arrows.\n"
"  for (const th of document.querySelectorAll('#nodes th.sortable')){\n"
"    const k = th.dataset.sort;\n"
"    th.querySelector('.arr').textContent = (k===nodesSortKey) ? (nodesSortDir<0?'\\u25BC':'\\u25B2') : '';\n"
"  }\n"
"}\n"
"// Wire search + sort once at startup.\n"
"nodesSearch.addEventListener('input', ()=>{ nodesQuery = nodesSearch.value.trim().toLowerCase(); refreshNodes(); });\n"
"for (const th of document.querySelectorAll('#nodes th.sortable')){\n"
"  th.addEventListener('click', ()=>{\n"
"    const k = th.dataset.sort;\n"
"    if (nodesSortKey === k) nodesSortDir = -nodesSortDir;\n"
"    else { nodesSortKey = k; nodesSortDir = (k==='id'||k==='name') ? 1 : -1; }\n"
"    refreshNodes();\n"
"  });\n"
"}\n"
"// Per-node history rings -- bounded so a long-running session in a busy\n"
"// environment doesn't grow without limit. The drawer reads from these.\n"
"const NODE_HIST_MSGS = 50, NODE_HIST_POS = 30, NODE_HIST_SNR = 60;\n"
"function nodeHistory(id){\n"
"  let h = nodes[id] && nodes[id]._hist;\n"
"  if (!h && nodes[id]) {\n"
"    h = nodes[id]._hist = {msgs:[], positions:[], snr:[], channels:{}};\n"
"  }\n"
"  return h;\n"
"}\n"
"function noteNodeFrame(id, p){\n"
"  const h = nodeHistory(id); if (!h) return;\n"
"  if (p.snr_db !== undefined) {\n"
"    h.snr.push({t:p.ts, v:p.snr_db});\n"
"    if (h.snr.length > NODE_HIST_SNR) h.snr.shift();\n"
"  }\n"
"  if (p.text) {\n"
"    h.msgs.unshift({t:p.ts, ch:p.channel_name||'', text:p.text});\n"
"    if (h.msgs.length > NODE_HIST_MSGS) h.msgs.length = NODE_HIST_MSGS;\n"
"  }\n"
"  if (p.lat !== undefined && p.lon !== undefined) {\n"
"    h.positions.unshift({t:p.ts, lat:p.lat, lon:p.lon});\n"
"    if (h.positions.length > NODE_HIST_POS) h.positions.length = NODE_HIST_POS;\n"
"  }\n"
"  if (p.channel_hash !== undefined) {\n"
"    const k = chanKey(p.channel_hash, p.channel_name);\n"
"    if (!h.channels[k]) h.channels[k] = {n:0, name:p.channel_name||null};\n"
"    h.channels[k].n++;\n"
"    if (p.channel_name) h.channels[k].name = p.channel_name;\n"
"  }\n"
"  if (drawerNodeId === id) refreshDrawer();\n"
"}\n"
/* loadNodeHistoryFromApi -- one-shot hydration of a node's drawer
 * history (msgs/positions/snr/channels) from the SQLite-backed
 * /api/node-history, the same idea as bootstrapNodesFromApi()/
 * bootstrapChannelsFromApi(): nodeHistory()'s rings are otherwise
 * built ONLY from live SSE traffic seen since page load/last
 * reconnect, so opening the drawer for a repeater that's been quiet
 * this session (or was cracked/known long before this browser tab
 * connected) shows an almost-empty panel even though the DB has a
 * full history. Runs once per node per session (n._histLoaded);
 * REPLACES the rings rather than merging with whatever live traffic
 * already accumulated, since every live event is also already
 * persisted to the DB by the time it reaches this browser over SSE --
 * merging would just duplicate those rows. */
"async function loadNodeHistoryFromApi(id){\n"
"  const n = nodes[id]; if (!n || n._histLoaded) return;\n"
"  n._histLoaded = true;\n"
"  try {\n"
"    const r = await fetch(`/api/node-history?id=${encodeURIComponent(id)}&limit=300`);\n"
"    if (!r.ok) return;\n"
"    const j = await r.json();\n"
"    const events = j.events || []; // newest-first (DESC ts), same convention as the query.\n"
"    const msgs = [], positions = [], channels = {};\n"
"    for (const p of events) {\n"
"      if (p.text) msgs.push({t:p.ts, ch:p.channel_name||'', text:p.text});\n"
"      if (p.lat !== undefined && p.lon !== undefined) positions.push({t:p.ts, lat:p.lat, lon:p.lon});\n"
"      if (p.channel_hash !== undefined) {\n"
"        const k = chanKey(p.channel_hash, p.channel_name);\n"
"        if (!channels[k]) channels[k] = {n:0, name:p.channel_name||null};\n"
"        channels[k].n++;\n"
"        if (p.channel_name) channels[k].name = p.channel_name;\n"
"      }\n"
"    }\n"
"    // Sparkline wants oldest-first (matches noteNodeFrame()'s push() order); events[] is newest-first, so walk it backwards.\n"
"    const snr = [];\n"
"    for (let i = events.length - 1; i >= 0; i--) {\n"
"      const p = events[i];\n"
"      if (p.snr_db !== undefined) snr.push({t:p.ts, v:p.snr_db});\n"
"    }\n"
"    const h = nodeHistory(id); if (!h) return;\n"
"    h.msgs = msgs.slice(0, NODE_HIST_MSGS);\n"
"    h.positions = positions.slice(0, NODE_HIST_POS);\n"
"    h.snr = snr.slice(-NODE_HIST_SNR);\n"
"    h.channels = channels;\n"
"    if (drawerNodeId === id) refreshDrawer();\n"
"  } catch (e) { n._histLoaded = false; /* allow a retry on next open */ }\n"
"}\n"
"// Drawer: per-node detail panel that slides in on row-click.\n"
"let drawerNodeId = null;\n"
"const drawerEl = document.getElementById('drawer');\n"
"const dName = document.getElementById('d-name'), dId = document.getElementById('d-id');\n"
"const dFrames = document.getElementById('d-frames'), dSnr = document.getElementById('d-snr');\n"
"const dLast = document.getElementById('d-last');\n"
"const dMsgs = document.getElementById('drawer-msgs'), dPos = document.getElementById('drawer-pos');\n"
"const dChan = document.getElementById('drawer-channels');\n"
"const dSpark = document.getElementById('drawer-spark');\n"
"function openDrawer(id){\n"
"  drawerNodeId = id;\n"
"  drawerEl.classList.add('open');\n"
"  drawerEl.setAttribute('aria-hidden','false');\n"
"  refreshDrawer();\n"
"  // Repaint table to show the .selected row highlight.\n"
"  refreshNodes();\n"
"}\n"
"function closeDrawer(){\n"
"  drawerEl.classList.remove('open');\n"
"  drawerEl.setAttribute('aria-hidden','true');\n"
"  drawerNodeId = null;\n"
"  refreshNodes();\n"
"}\n"
"// Esc closes the drawer.\n"
"document.addEventListener('keydown', e=>{ if (e.key==='Escape' && drawerNodeId) closeDrawer(); });\n"
"let drawerRafQueued = false;\n"
"function refreshDrawer(){\n"
"  if (drawerRafQueued) return;\n"
"  drawerRafQueued = true;\n"
"  requestAnimationFrame(()=>{ drawerRafQueued = false; renderDrawer(); });\n"
"}\n"
"function renderDrawer(){\n"
"  if (!drawerNodeId) return;\n"
"  const n = nodes[drawerNodeId];\n"
"  if (!n) { closeDrawer(); return; }\n"
"  const h = nodeHistory(drawerNodeId);\n"
"  dName.textContent = n.name || '(unknown)';\n"
"  dId.textContent = drawerNodeId;\n"
"  dFrames.textContent = fmtCount(n.frames||0);\n"
"  if (h && h.snr.length) {\n"
"    const avg = h.snr.reduce((s,x)=>s+x.v,0)/h.snr.length;\n"
"    dSnr.textContent = avg.toFixed(1)+' dB';\n"
"  } else dSnr.textContent = '--';\n"
"  dLast.textContent = fmtAgo(n.ts);\n"
"  // SNR sparkline.\n"
"  const ctx = dSpark.getContext('2d'); const W = dSpark.width, H = dSpark.height;\n"
"  ctx.clearRect(0,0,W,H);\n"
"  if (h && h.snr.length > 1) {\n"
"    const vs = h.snr.map(x=>x.v);\n"
"    const lo = Math.min(...vs), hi = Math.max(...vs);\n"
"    const span = Math.max(1, hi - lo);\n"
"    const isLight = document.documentElement.classList.contains('light');\n"
"    ctx.strokeStyle = isLight ? '#0284c7' : '#38bdf8';\n"
"    ctx.lineWidth = 1.5; ctx.beginPath();\n"
"    for (let i=0;i<vs.length;++i) {\n"
"      const x = (i/(vs.length-1))*W;\n"
"      const y = H - 4 - ((vs[i]-lo)/span) * (H-8);\n"
"      if (i===0) ctx.moveTo(x,y); else ctx.lineTo(x,y);\n"
"    }\n"
"    ctx.stroke();\n"
"    ctx.fillStyle = isLight?'#94a3b8':'#64748b'; ctx.font='9px system-ui';\n"
"    ctx.fillText(hi.toFixed(1)+' dB', 4, 10);\n"
"    ctx.fillText(lo.toFixed(1)+' dB', 4, H-2);\n"
"  } else {\n"
"    ctx.fillStyle = '#64748b'; ctx.font='10px system-ui'; ctx.fillText('no SNR samples yet', 8, H/2+3);\n"
"  }\n"
"  // Messages.\n"
"  if (h && h.msgs.length) {\n"
"    dMsgs.innerHTML = h.msgs.map(m=>`<div class=item><span class=muted>${fmtTime(m.t)}</span> ${m.ch?'<span class=muted>'+m.ch+'</span> ':''}<span class=text>${escHtml(m.text)}</span></div>`).join('');\n"
"  } else dMsgs.innerHTML = '<div class=muted>no text frames captured</div>';\n"
"  // Positions.\n"
"  if (h && h.positions.length) {\n"
"    dPos.innerHTML = '<table>'+h.positions.map(p=>`<tr><td class=muted>${fmtTime(p.t)}</td><td>${p.lat.toFixed(5)}</td><td>${p.lon.toFixed(5)}</td></tr>`).join('')+'</table>';\n"
"  } else dPos.innerHTML = '<div class=muted>no positions captured</div>';\n"
"  // Channels.\n"
"  if (h && Object.keys(h.channels).length) {\n"
"    dChan.innerHTML = Object.keys(h.channels).map(k=>{\n"
"      const c = h.channels[k];\n"
"      const hex = '0x'+(chanKeyHash(k)&0xff).toString(16).padStart(2,'0');\n"
"      return `<div class=item>${c.name||'<span class=muted>(encrypted)</span>'} <span class=muted>${hex} | ${c.n} frames</span></div>`;\n"
"    }).join('');\n"
"  } else dChan.innerHTML = '<div class=muted>no channel data</div>';\n"
/* Region scoping (v1.10+ flood scoping): only counts frames this
 * node itself AUTHORED (see the regionScopedCount/regionUnscopedCount
 * bookkeeping in es.onmessage) -- a repeater's rebroadcasts of other
 * nodes' scoped traffic don't reflect its own configuration. Flags a
 * likely misconfiguration when the network overall uses scoping
 * meaningfully but this node's own traffic mostly doesn't. */
"  const rScoped = n.regionScopedCount || 0, rUnscoped = n.regionUnscopedCount || 0;\n"
"  const rTotal = rScoped + rUnscoped;\n"
"  if (rTotal === 0) {\n"
"    dRegion.innerHTML = '<div class=muted>no region-scope data (no frames authored by this node observed)</div>';\n"
"  } else {\n"
"    const names = Object.keys(n.regionScopes||{}).sort((a,b)=>n.regionScopes[b]-n.regionScopes[a]);\n"
"    const badges = names.map(nm=>{\n"
"      const unresolved = /^0x[0-9a-f]{4}$/i.test(nm);\n"
"      return `<span class=\"region-badge${unresolved?' unresolved':''}\">${escHtml(nm)} <span class=muted>(${n.regionScopes[nm]})</span></span>`;\n"
"    }).join('');\n"
"    const netScopedRatio = regionStats.scoped / Math.max(1, regionStats.scoped + regionStats.unscoped);\n"
"    const nodeScopedRatio = rScoped / rTotal;\n"
"    const warn = (rTotal >= 3 && netScopedRatio > 0.2 && nodeScopedRatio < 0.1)\n"
"      ? `<div class=status-err style=\"margin-top:6px;font-size:11px\">no region scope on ${rUnscoped}/${rTotal} of this node's own frames, while ${(netScopedRatio*100).toFixed(0)}% of network traffic is scoped -- possible misconfiguration</div>`\n"
"      : '';\n"
"    dRegion.innerHTML = `<div style=\"margin-bottom:4px\">${badges || '<span class=muted>none resolved/scoped</span>'}</div>`\n"
"      + `<div class=muted style=\"font-size:11px\">${rScoped}/${rTotal} of this node's own frames carried a region scope</div>`\n"
"      + warn;\n"
"  }\n"
"}\n"
"function escHtml(s){return String(s).replace(/[&<>\"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;','\\'':'&#39;'}[c]));}\n"
"let channelsRafQueued = false;\n"
"function refreshChannels(){\n"
"  if (channelsRafQueued) return;\n"
"  channelsRafQueued = true;\n"
"  requestAnimationFrame(()=>{ channelsRafQueued = false; renderChannels(); });\n"
"}\n"
/* aggregateSnr -- collapse per-slot rings into one SNR_BUCKETS-bucket view
 * for the channel hash (which can span multiple physical slots). Each
 * bucket is the mean across slots that had data in that window. */
"const SNR_BUCKETS = 288;\n"
"const SNR_BUCKET_MINUTES = 5;\n"
"function aggregateSnr(slotSet){\n"
"  const out = new Array(SNR_BUCKETS).fill(null);\n"
"  const sum = new Array(SNR_BUCKETS).fill(0);\n"
"  const cnt = new Array(SNR_BUCKETS).fill(0);\n"
"  if (!slotSet) return out;\n"
"  for (const slot of slotSet){\n"
"    const ring = chanSnr[slot];\n"
"    if (!ring) continue;\n"
"    for (let i=0; i<SNR_BUCKETS && i<ring.length; i++){\n"
"      if (ring[i] >= 0){ sum[i] += ring[i]; cnt[i] += 1; }\n"
"    }\n"
"  }\n"
"  for (let i=0; i<SNR_BUCKETS; i++) if (cnt[i]) out[i] = sum[i]/cnt[i];\n"
"  return out;\n"
"}\n"
/* snrSummary -- compress the SNR_BUCKETS-bucket history into one cell:
 *   current = newest populated bucket (rounded dB)
 *   trend   = least-squares slope over up to 10 most-recent populated
 *             buckets, normalized to dB/min (slope is computed in
 *             dB-per-bucket-step, so divide by SNR_BUCKET_MINUTES).
 *             slope > +0.5 dB/min = up, < -0.5 = down, else flat.
 *             Returns null when nothing populated so the cell shows
 *             '--' instead of confusing zeros. */
"function snrSummary(buckets){\n"
"  let current = null, currentIdx = -1;\n"
"  for (let i = buckets.length - 1; i >= 0; i--){\n"
"    if (buckets[i] !== null){ current = buckets[i]; currentIdx = i; break; }\n"
"  }\n"
"  if (currentIdx < 0) return null;\n"
"  const xs = [], ys = [];\n"
"  for (let i = currentIdx; i >= 0 && xs.length < 10; i--){\n"
"    if (buckets[i] !== null){ xs.push(i); ys.push(buckets[i]); }\n"
"  }\n"
"  let trend = 'flat';\n"
"  if (ys.length >= 3){\n"
"    const n = ys.length;\n"
"    const mx = xs.reduce((a,b)=>a+b,0)/n;\n"
"    const my = ys.reduce((a,b)=>a+b,0)/n;\n"
"    let num = 0, den = 0;\n"
"    for (let i = 0; i < n; i++){ const dx = xs[i]-mx; num += dx*(ys[i]-my); den += dx*dx; }\n"
"    const slope = den ? num/den : 0;\n"
"    const slopePerMin = slope / SNR_BUCKET_MINUTES;\n"
"    if (slopePerMin >  0.5) trend = 'up';\n"
"    else if (slopePerMin < -0.5) trend = 'down';\n"
"  }\n"
"  return { current: Math.round(current), trend };\n"
"}\n"
"function renderChannels(){\n"
"  const hashes = Object.keys(channels).sort((a,b)=>channels[b].ts-channels[a].ts);\n"
"  const frag = document.createDocumentFragment();\n"
"  for (const h of hashes){const c=channels[h]; const tr=document.createElement('tr');\n"
"    const hashHex = '0x'+(chanKeyHash(h)&0xff).toString(16).padStart(2,'0');\n"
"    // Channel name comes from decrypted frame metadata. If we've never\n"
"    // successfully decrypted a frame on this hash, we know the hash but\n"
"    // not the operator's name for the channel -- show '(encrypted)'\n"
"    // rather than a cryptic '?'.\n"
"    const name = c.name || '<span class=muted>(encrypted)</span>';\n"
"    // MeshCore has no SF/BW/CR-named preset like Meshtastic -- say so\n"
"    // plainly instead of a bare '--' that reads as missing data.\n"
"    const preset = c.protocol === 'meshcore' ? '<span class=muted>MeshCore</span>' : (c.preset || '<span class=muted>--</span>');\n"
"    const dec = c.total ? Math.round(100*c.decrypted/c.total) : 0;\n"
"    const decCell = c.decrypted>0 ? `${c.decrypted}/${c.total} (${dec}%)` : `<span class=muted>0/${c.total}</span>`;\n"
"    const slotN = c.slots ? c.slots.size : 0;\n"
"    const slotCell = slotN>0 ? (c.lastSlot!==undefined ? `${slotN} <span class=muted>(last #${c.lastSlot})</span>` : `${slotN}`) : '<span class=muted>--</span>';\n"
"    const s = snrSummary(aggregateSnr(c.slots));\n"
"    const arrows = {up:'\\u2197', down:'\\u2198', flat:'\\u2192'};\n"
"    const snrCell = s ? `${s.current} dB <span class='snr-arrow snr-${s.trend}'>${arrows[s.trend]}</span>` : `<span class=muted>--</span>`;\n"
"    tr.innerHTML=`<td>${hashHex}</td><td>${name}</td><td>${preset}</td><td>${c.total}</td><td>${decCell}</td><td>${slotCell}</td><td>${snrCell}</td><td>${fmtTime(c.ts)}</td>`;\n"
"    frag.appendChild(tr);\n"
"  }\n"
"  chTbody.replaceChildren(frag);\n"
"}\n"
"function exportCsv(){\n"
"  const rows = [['node_id','name','lat','lon','last_snr_db','last_seen']];\n"
"  for (const id of Object.keys(nodes)){const n=nodes[id]; if (n.synthetic) continue;\n"
"    const ll = (markers[id] && markers[id].getLatLng) ? markers[id].getLatLng() : null;\n"
"    rows.push([id, (n.name||'').replace(/,/g,';'), ll?ll.lat.toFixed(7):'', ll?ll.lng.toFixed(7):'', n.snr_db!==undefined?n.snr_db.toFixed(1):'', new Date(n.ts*1000).toISOString()]);\n"
"  }\n"
"  const csv = rows.map(r=>r.join(',')).join('\\n');\n"
"  const blob = new Blob([csv], {type:'text/csv'}); const url = URL.createObjectURL(blob);\n"
"  const a = document.createElement('a'); a.href = url;\n"
"  a.download = `meshtastic-nodes-${new Date().toISOString().replace(/[:.]/g,'-')}.csv`;\n"
"  a.click(); setTimeout(()=>URL.revokeObjectURL(url), 1000);\n"
"}\n"
"function pushTo(el, html, ts){\n"
"  const div = document.createElement('div'); div.className='log-item';\n"
"  div.innerHTML = `<span class=ts>${fmtTime(ts||Date.now()/1000)}</span>${html}`;\n"
"  el.insertBefore(div, el.firstChild);\n"
"  while (el.children.length>200) el.removeChild(el.lastChild);\n"
"}\n"
/* Analyzer tab: one row per received frame (either protocol), newest
 * first, capped at DEBUG_MAX rows so an active channel doesn't grow the
 * DOM forever. Each row expands in place (click to toggle) into a
 * structured field breakdown built from the same JSON the row itself
 * came from -- kept in analyzerEvents, pruned in lockstep with the DOM
 * so an old row falling off the cap also drops its stored event. */
"function analyzerCrcBadge(p){\n"
"  if (p.payload_crc_ok === undefined) return '<span class=muted>--</span>';\n"
"  if (!p.payload_crc_ok) return '<span class=\"crc-badge crc-fail\">fail</span>';\n"
"  return p.crc_corrected ? '<span class=\"crc-badge crc-corrected\" title=\"Recovered via single-bit brute-force\">corrected</span>' : '<span class=\"crc-badge crc-ok\">ok</span>';\n"
"}\n"
/* analyzerCrcBucket -- 'ok'/'corrected'/'fail'/'' classification used
 * by both the CRC badge above and the CRC filter dropdown, so the two
 * can never disagree on what a row counts as. */
"function analyzerCrcBucket(p){\n"
"  if (p.payload_crc_ok === undefined) return '';\n"
"  if (!p.payload_crc_ok) return 'fail';\n"
"  return p.crc_corrected ? 'corrected' : 'ok';\n"
"}\n"
"function analyzerNodeLabel(p){\n"
"  if (p.protocol === 'meshcore' &&\n"
"      (p.mc_type === 'TXT_MSG' || p.mc_type === 'REQ' || p.mc_type === 'RESPONSE' || p.mc_type === 'PATH')) {\n"
"    return `dest=${hashHint(p.dest_hash)} src=${hashHint(p.src_hash)}`;\n"
"  }\n"
"  return p.node_name || p.long_name || p.from || '';\n"
"}\n"
"function analyzerChanLabel(p){\n"
"  if (p.channel_name) return p.channel_name;\n"
"  if (p.channel_hash !== undefined) return '0x'+p.channel_hash.toString(16);\n"
"  return '';\n"
"}\n"
/* analyzerRowMatches -- true if a frame passes the current search box
 * + protocol/CRC dropdowns. The search box matches loosely across
 * every field an operator would plausibly search by (node identity,
 * channel, frame type, raw hex, decoded text) rather than one specific
 * column, since a live capture rarely gets searched by exact field. */
"function analyzerRowMatches(p){\n"
"  if (analyzerProtoFilter && p.protocol !== analyzerProtoFilter) return false;\n"
"  if (analyzerCrcFilter && analyzerCrcBucket(p) !== analyzerCrcFilter) return false;\n"
"  if (analyzerQuery){\n"
"    const hay = [p.raw_hex, p.mc_type, p.port_name, p.from, p.node_name, p.long_name,\n"
"                 p.channel_name, p.text]\n"
"      .filter(v => v !== undefined && v !== null).join(' ').toLowerCase();\n"
"    if (!hay.includes(analyzerQuery)) return false;\n"
"  }\n"
"  return true;\n"
"}\n"
"function analyzerUpdateCount(){\n"
"  const total = analyzerTbody.querySelectorAll('tr.analyzer-row').length;\n"
"  analyzerCountEl.textContent = (analyzerQuery || analyzerProtoFilter || analyzerCrcFilter)\n"
"    ? `(${analyzerVisible}/${total} shown)` : '';\n"
"}\n"
/* applyAnalyzerFilter -- re-run the current filter over every row
 * already in the DOM (search/dropdown changed, not a new frame
 * arriving -- see noteAnalyzerFrame for the incremental per-frame
 * path). Closes any open detail row first since it may belong to a
 * row that's about to be hidden. */
"function applyAnalyzerFilter(){\n"
"  document.querySelectorAll('tr.analyzer-detail').forEach(d => d.remove());\n"
"  document.querySelectorAll('#analyzertbl td.aexp').forEach(e => e.textContent = '\\u25b8');\n"
"  analyzerVisible = 0;\n"
"  for (const tr of analyzerTbody.querySelectorAll('tr.analyzer-row')){\n"
"    const p = analyzerEvents[tr.dataset.id];\n"
"    const match = !p || analyzerRowMatches(p);\n"
"    tr.style.display = match ? '' : 'none';\n"
"    if (match) analyzerVisible++;\n"
"  }\n"
"  analyzerUpdateCount();\n"
"}\n"
"function noteAnalyzerFrame(p){\n"
"  analyzerEmpty.style.display = 'none';\n"
"  const id = ++analyzerSeq;\n"
"  analyzerEvents[id] = p;\n"
"  const type = p.mc_type || p.port_name || '';\n"
"  const tr = document.createElement('tr');\n"
"  tr.className = 'analyzer-row';\n"
"  tr.dataset.id = id;\n"
"  const proto = p.protocol === 'meshcore' ? 'MeshCore' : (p.protocol === 'meshtastic' ? 'Meshtastic' : '');\n"
"  tr.innerHTML = `<td class=aexp>\\u25b8</td><td class=ts>${fmtTime(p.ts)}</td>`+\n"
"    `<td class=proto>${escHtml(proto)}</td><td class=mctype>${escHtml(type)}</td>`+\n"
"    `<td class=node>${escHtml(analyzerNodeLabel(p))}</td><td class=chan>${escHtml(analyzerChanLabel(p))}</td>`+\n"
"    `<td>${analyzerCrcBadge(p)}</td><td class=snr>${p.snr_db!==undefined?p.snr_db.toFixed(1)+' dB':''}</td>`+\n"
"    `<td class=hex>${escHtml(p.raw_hex||'')}</td>`;\n"
"  const visible = analyzerRowMatches(p);\n"
"  tr.style.display = visible ? '' : 'none';\n"
"  if (visible) analyzerVisible++;\n"
"  tr.onclick = () => toggleAnalyzerDetail(tr, id);\n"
"  analyzerTbody.insertBefore(tr, analyzerTbody.firstChild);\n"
"  const rows = analyzerTbody.querySelectorAll('tr.analyzer-row');\n"
"  if (rows.length > DEBUG_MAX) {\n"
"    const last = rows[rows.length-1];\n"
"    const lastP = analyzerEvents[last.dataset.id];\n"
"    if (lastP && last.style.display !== 'none' && analyzerRowMatches(lastP)) analyzerVisible--;\n"
"    delete analyzerEvents[last.dataset.id];\n"
"    const next = last.nextSibling;\n"
"    if (next && next.classList && next.classList.contains('analyzer-detail')) analyzerTbody.removeChild(next);\n"
"    analyzerTbody.removeChild(last);\n"
"  }\n"
"  analyzerUpdateCount();\n"
"}\n"
"function toggleAnalyzerDetail(tr, id){\n"
"  const next = tr.nextSibling;\n"
"  if (next && next.classList && next.classList.contains('analyzer-detail')) {\n"
"    tr.querySelector('td.aexp').textContent = '\\u25b8';\n"
"    analyzerTbody.removeChild(next);\n"
"    return;\n"
"  }\n"
"  document.querySelectorAll('tr.analyzer-detail').forEach(d => d.remove());\n"
"  document.querySelectorAll('#analyzertbl td.aexp').forEach(e => e.textContent = '\\u25b8');\n"
"  const p = analyzerEvents[id];\n"
"  if (!p) return;\n"
"  tr.querySelector('td.aexp').textContent = '\\u25be';\n"
"  const detailTr = document.createElement('tr');\n"
"  detailTr.className = 'analyzer-detail';\n"
"  const td = document.createElement('td');\n"
"  td.colSpan = 9;\n"
"  td.innerHTML = analyzerDetailHtml(p);\n"
"  detailTr.appendChild(td);\n"
"  tr.parentNode.insertBefore(detailTr, tr.nextSibling);\n"
"}\n"
"// analyzerDetailHtml -- structured field breakdown for one decoded\n"
"// frame, built entirely from JSON fields the server already emits.\n"
"// Protocol-specific fields render first with friendly labels; anything\n"
"// left over (any field not already shown) is dumped generically at the\n"
"// end so no data is ever silently hidden as the event schema grows.\n"
"function analyzerDetailHtml(p){\n"
"  const rows = [];\n"
"  const shown = new Set(['ts','raw_hex','protocol','mc_type']);\n"
"  const add = (label, val) => { if (val !== undefined && val !== null && val !== '') rows.push(`<tr><td class=k>${label}</td><td class=v>${val}</td></tr>`); };\n"
"  if (p.protocol === 'meshcore') {\n"
"    add('Route type', p.route_type_name !== undefined ? `${p.route_type_name} (${p.route_type})` : undefined);\n"
"    add('Payload type', p.payload_type !== undefined ? `${p.mc_type} (${p.payload_type})` : undefined);\n"
"    add('Payload ver', p.payload_ver);\n"
"    ['route_type','route_type_name','payload_type','payload_ver'].forEach(k=>shown.add(k));\n"
"    if (p.route_path_hash_count) {\n"
"      const size = p.route_path_hash_size || 1;\n"
"      const hex = p.route_path_hex || '';\n"
"      const hops = [];\n"
"      for (let i = 0; i < p.route_path_hash_count; i++) hops.push(hex.substr(i*size*2, size*2));\n"
"      add('Route path', `${hops.join(' \\u2192 ')} <button class=btn-mini onclick=\"drawMessagePath('${hex}',${p.route_path_hash_count},${size})\">Show path</button>`);\n"
"    }\n"
"    ['route_path_hex','route_path_hash_count','route_path_hash_size'].forEach(k=>shown.add(k));\n"
"    if (p.trace_route_hashes_hex) {\n"
"      const n = p.trace_route_hashes_hex.length / 2;\n"
"      add('Trace route (planned hops)', `${p.trace_route_hashes_hex} <button class=btn-mini onclick=\"drawMessagePath('${p.trace_route_hashes_hex}',${n},1)\">Show path</button>`);\n"
"      shown.add('trace_route_hashes_hex');\n"
"    }\n"
"    if (p.trace_snrs_hex) { add('Trace SNRs (hex, /4 dB each hop)', p.trace_snrs_hex); shown.add('trace_snrs_hex'); }\n"
"  } else {\n"
"    add('Port', p.port_name !== undefined ? `${p.port_name} (${p.portnum})` : undefined);\n"
"    add('From', p.from); add('To', p.to); add('Packet id', p.packet_id);\n"
"    add('Hops', (p.hop_start!==undefined && p.hop_limit!==undefined) ? `${p.hop_start-p.hop_limit}/${p.hop_start}` : undefined);\n"
"    ['port_name','portnum','from','to','packet_id','hop_start','hop_limit'].forEach(k=>shown.add(k));\n"
"  }\n"
"  add('Decrypted', p.decrypted === undefined ? undefined : (p.decrypted ? 'yes' : 'no'));\n"
"  add('CRC', p.payload_crc_ok === undefined ? undefined : (p.payload_crc_ok ? (p.crc_corrected ? 'ok (bit-flip corrected)' : 'ok') : 'FAIL'));\n"
"  ['decrypted','has_crc','payload_crc_ok','crc_corrected'].forEach(k=>shown.add(k));\n"
"  if (p.rssi_db !== undefined || p.snr_db !== undefined) {\n"
"    add('RSSI / SNR', `${p.rssi_db!==undefined?p.rssi_db.toFixed(1)+' dBm':'--'} / ${p.snr_db!==undefined?p.snr_db.toFixed(1)+' dB':'--'}`);\n"
"  }\n"
"  ['rssi_db','snr_db'].forEach(k=>shown.add(k));\n"
"  if (p.sf) add('Radio', `SF${p.sf} CR4/${p.cr} BW${Math.round(p.bw_hz/1000)}kHz${p.freq_hz?' @ '+(p.freq_hz/1e6).toFixed(3)+'MHz':''}`);\n"
"  ['sf','cr','bw_hz','freq_hz','preset','slot_id'].forEach(k=>shown.add(k));\n"
"  if (p.channel_name || p.channel_hash !== undefined) {\n"
"    add('Channel', `${p.channel_name||'<span class=muted>(unknown)</span>'}${p.channel_hash!==undefined?' hash=0x'+p.channel_hash.toString(16):''}`);\n"
"  }\n"
"  ['channel_name','channel_hash'].forEach(k=>shown.add(k));\n"
"  if (p.text) add('Text', escHtml(p.text));\n"
"  if (p.node_name || p.long_name) add('Node name', escHtml(p.node_name||p.long_name));\n"
"  ['text','node_name','long_name'].forEach(k=>shown.add(k));\n"
"  if (p.lat !== undefined && p.lon !== undefined) add('Position', `${p.lat.toFixed(5)}, ${p.lon.toFixed(5)}`);\n"
"  ['lat','lon'].forEach(k=>shown.add(k));\n"
"  if (p.sig_valid !== undefined) add('Sig valid', p.sig_valid ? 'yes' : 'no');\n"
"  ['sig_valid','station'].forEach(k=>shown.add(k));\n"
"  const rest = Object.keys(p).filter(k => !shown.has(k) && p[k] !== null && p[k] !== '').sort();\n"
"  if (rest.length) {\n"
"    const restStr = rest.map(k => `${k}=${typeof p[k]==='object'?JSON.stringify(p[k]):p[k]}`).join(', ');\n"
"    rows.push(`<tr><td class=k>Other</td><td class=vmuted>${escHtml(restStr)}</td></tr>`);\n"
"  }\n"
"  return `<table class=analyzer-detail-tbl>${rows.join('')}</table>`;\n"
"}\n"
"function clearAnalyzer(){\n"
"  analyzerTbody.replaceChildren();\n"
"  analyzerEmpty.style.display = '';\n"
"  for (const k of Object.keys(analyzerEvents)) delete analyzerEvents[k];\n"
"  analyzerVisible = 0;\n"
"  analyzerUpdateCount();\n"
"}\n"
"document.getElementById('analyzer-search').addEventListener('input', e => {\n"
"  analyzerQuery = e.target.value.trim().toLowerCase();\n"
"  applyAnalyzerFilter();\n"
"});\n"
"document.getElementById('analyzer-filter-protocol').addEventListener('change', e => {\n"
"  analyzerProtoFilter = e.target.value;\n"
"  applyAnalyzerFilter();\n"
"});\n"
"document.getElementById('analyzer-filter-crc').addEventListener('change', e => {\n"
"  analyzerCrcFilter = e.target.value;\n"
"  applyAnalyzerFilter();\n"
"});\n"
"// drawMessagePath -- best-effort: resolve each path-hop-hash-hex prefix\n"
"// against known node ids (a MeshCore path hop hash is literally a\n"
"// leading-byte prefix of the relaying node's pubkey, matching the same\n"
"// prefix mc_derive_from_id() uses to build the node's \"!xxxxxxxx\" id --\n"
"// see Identity::copyHashTo in the upstream firmware). 1-3 byte hashes\n"
"// can collide between distinct nodes; unresolved hops are reported, not\n"
"// guessed.\n"
"function drawMessagePath(hex, hopCount, hashSize){\n"
"  hashSize = hashSize || 1;\n"
"  const hops = [];\n"
"  for (let i = 0; i < hopCount; i++) hops.push(hex.substr(i*hashSize*2, hashSize*2).toLowerCase());\n"
"  const pts = [];\n"
"  let resolved = 0;\n"
"  for (const hop of hops) {\n"
"    let match = null;\n"
"    for (const id of Object.keys(nodes)) {\n"
"      if (id.length === 9 && id.slice(1, 1+hop.length) === hop) { match = id; break; }\n"
"    }\n"
"    if (match && markers[match]) { pts.push(markers[match].getLatLng()); resolved++; }\n"
"  }\n"
"  if (window.pathLine) { map.removeLayer(window.pathLine); window.pathLine = null; }\n"
"  if (pts.length < 2) {\n"
"    alert(`Path: ${resolved}/${hops.length} hop(s) resolved to a known position -- not enough to draw a line.`);\n"
"    return;\n"
"  }\n"
"  window.pathLine = L.polyline(pts, {color:'#f59e0b', weight:3, opacity:0.85, dashArray:'6,4'}).addTo(map);\n"
"  map.fitBounds(window.pathLine.getBounds(), {padding:[40,40]});\n"
"  showTab('live');\n"
"}\n"
/* msgSummary -- per-port short string for the global Messages pane.
 * Returns null if the event should not appear in the pane (e.g. ATAK
 * which already lands in Discoveries, or unknown ports with no
 * useful summary). Keep each port to one tight line so the log
 * stays readable when 100+ events scroll past. */
"// Message-row 'from' label. Group traffic (GRP_TXT/GRP_DATA) is keyed by\n"
"// channel, not a device -- show the channel identity instead of the\n"
"// synthetic !8000xxxx id. Envelope-only 1:1 traffic (TXT_MSG/REQ/RESPONSE/\n"
"// PATH) has no real sender identity either -- a passive sniffer only ever\n"
"// sees the low-entropy dest_hash/src_hash pair, not a stable node id --\n"
"// so show that pair directly instead of the synthetic !4000xxxx id.\n"
"// Everything else (including ANON_REQ, keyed off a real pubkey prefix)\n"
"// falls back to the normal node name/id.\n"
/* Best-effort dest_hash/src_hash -> node name resolution. dest_hash/
 * src_hash (TXT_MSG/REQ/RESPONSE/PATH's envelope, 1 byte each) is
 * literally pub_key[0] (MeshCore firmware's Identity::copyHashTo(),
 * confirmed against src/Identity.h) -- the SAME byte that's also the
 * first byte of every ADVERT-derived node id ("!XXxxxxxx", see
 * mc_node_id() in db_sqlite.c / mc_derive_from_id() in
 * feed_meshcore_json.c). So any already-known, non-synthetic node
 * whose id starts with that byte is a candidate for "who this packet
 * is addressed to/from" -- still can't decrypt the payload (no ECDH
 * key), but at least ties the traffic to a name instead of an opaque
 * hex byte. Genuinely ambiguous on a collision (1-in-256 by chance,
 * worse with many known nodes) -- shown as a joined list rather than
 * silently picking one. */
"function resolveHashCandidates(byte) {\n"
"  if (byte === undefined || byte === null) return [];\n"
"  const hex = byte.toString(16).padStart(2,'0');\n"
"  const out = [];\n"
"  for (const id of Object.keys(nodes)) {\n"
"    if (/^!(4000|8000)/i.test(id)) continue;\n"
"    if (id.slice(1,3).toLowerCase() === hex) out.push(nodes[id].name || id);\n"
"  }\n"
"  return out;\n"
"}\n"
"function hashHint(byte) {\n"
"  if (byte === undefined || byte === null) return '?';\n"
"  const hex = '0x'+byte.toString(16).padStart(2,'0');\n"
"  const cands = resolveHashCandidates(byte);\n"
"  return cands.length ? `${hex} (${cands.join(' or ')})` : hex;\n"
"}\n"
"function msgFromLabel(p, n, id) {\n"
"  if (p.protocol === 'meshcore') {\n"
"    if (p.mc_type === 'GRP_TXT' || p.mc_type === 'GRP_DATA') {\n"
"      return '#' + (p.channel_name || ('0x' + (p.channel_hash||0).toString(16).padStart(2,'0')));\n"
"    }\n"
"    if (p.mc_type === 'TXT_MSG' || p.mc_type === 'REQ' || p.mc_type === 'RESPONSE' || p.mc_type === 'PATH') {\n"
"      return `dest=${hashHint(p.dest_hash)} src=${hashHint(p.src_hash)}`;\n"
"    }\n"
"  }\n"
"  return n.name || id;\n"
"}\n"
"function msgSummary(p) {\n"
"  if (p.protocol === 'meshcore') {\n"
"    switch (p.mc_type) {\n"
"      case 'GRP_TXT':\n"
"        return p.text ? `<span class=text>${escHtml(p.text)}</span>` : null;\n"
"      case 'GRP_DATA': {\n"
"        const x = [];\n"
"        if (p.data_type !== undefined) x.push('type='+p.data_type);\n"
"        if (p.data_len !== undefined)  x.push('len='+p.data_len);\n"
"        if (p.text) x.push(escHtml(p.text));\n"
"        return x.length ? x.join(' ') : null;\n"
"      }\n"
"      case 'ADVERT': {\n"
"        const x = [];\n"
"        if (p.adv_type_name) x.push(p.adv_type_name);\n"
"        if (typeof p.lat==='number' && typeof p.lon==='number')\n"
"          x.push(`${p.lat.toFixed(5)},${p.lon.toFixed(5)}`);\n"
"        x.push(p.sig_valid ? 'sig=ok' : 'sig=?');\n"
"        return x.join(' ');\n"
"      }\n"
"      case 'TXT_MSG':\n"
"      case 'REQ':\n"
"      case 'RESPONSE':\n"
"      case 'PATH':\n"
"      case 'ANON_REQ':\n"
"        // Genuinely opaque to a passive sniffer -- 1:1 packets encrypted\n"
"        // with a per-pair ECDH shared secret we don't have (confirmed\n"
"        // against the MeshCore firmware: dest_hash/src_hash + MAC is the\n"
"        // entirety of the cleartext for all four, no route/ack info\n"
"        // hides in there like TRACE's route list does). Label it as\n"
"        // such instead of a bare dash so it doesn't look like a decode\n"
"        // failure.\n"
"        return '<span class=muted>encrypted 1:1 (no content without the peer\\'s key)</span>';\n"
"      case 'TRACE':\n"
"        return (typeof p.path_hop_count === 'number') ? `${p.path_hop_count} hops` : '\\u2014';\n"
"      default:\n"
"        return p.text ? escHtml(p.text) : '\\u2014';\n"
"    }\n"
"  }\n"
"  const pn = p.port_name || '';\n"
"  switch (pn) {\n"
"    case 'TEXT_MESSAGE_APP':\n"
"    case 'RANGE_TEST_APP':\n"
"    case 'DETECTION_SENSOR_APP':\n"
"      return p.text ? `<span class=text>${escHtml(p.text)}</span>` : null;\n"
"    case 'NODEINFO_APP': {\n"
"      const x = [];\n"
"      if (p.long_name)  x.push(escHtml(p.long_name));\n"
"      if (p.short_name) x.push('('+escHtml(p.short_name)+')');\n"
"      if (p.hw_model!==undefined) x.push('hw='+p.hw_model);\n"
"      if (p.role!==undefined)     x.push('role='+p.role);\n"
"      return x.length ? x.join(' ') : null;\n"
"    }\n"
"    case 'POSITION_APP': {\n"
"      const x = [];\n"
"      if (typeof p.lat==='number' && typeof p.lon==='number')\n"
"        x.push(`${p.lat.toFixed(5)},${p.lon.toFixed(5)}`);\n"
"      if (p.alt_m!==undefined)    x.push(`alt=${p.alt_m}m`);\n"
"      if (p.speed_mps!==undefined)x.push(`spd=${p.speed_mps}m/s`);\n"
"      if (p.sats!==undefined)     x.push(`sats=${p.sats}`);\n"
"      return x.length ? x.join(' ') : null;\n"
"    }\n"
"    case 'TELEMETRY_APP': {\n"
"      const x = [];\n"
"      const d = (p.device && p.device[0]) || {};\n"
"      if (d.battery!==undefined) x.push(`bat=${d.battery}%`);\n"
"      if (d.voltage!==undefined) x.push(`v=${d.voltage.toFixed(2)}`);\n"
"      if (d.ch_util!==undefined) x.push(`chu=${d.ch_util.toFixed(1)}`);\n"
"      if (d.uptime !==undefined) x.push(`up=${d.uptime}s`);\n"
"      const e = (p.environment && p.environment[0]) || {};\n"
"      if (e.temp_c   !==undefined) x.push(`t=${e.temp_c.toFixed(1)}C`);\n"
"      if (e.humidity !==undefined) x.push(`rh=${e.humidity.toFixed(0)}%`);\n"
"      if (e.pressure !==undefined) x.push(`p=${e.pressure.toFixed(0)}hPa`);\n"
"      const ls = (p.local_stats && p.local_stats[0]) || {};\n"
"      if (ls.nodes_online!==undefined) x.push(`online=${ls.nodes_online}`);\n"
"      const aq = (p.air_quality && p.air_quality[0]) || {};\n"
"      if (aq.pm25_std!==undefined) x.push(`pm25=${aq.pm25_std}`);\n"
"      if (aq.co2_ppm !==undefined) x.push(`co2=${aq.co2_ppm}`);\n"
"      return x.length ? x.join(' ') : null;\n"
"    }\n"
"    case 'WAYPOINT_APP': {\n"
"      const x = [];\n"
"      if (p.wp_name) x.push(escHtml(p.wp_name));\n"
"      if (typeof p.lat==='number' && typeof p.lon==='number')\n"
"        x.push(`${p.lat.toFixed(5)},${p.lon.toFixed(5)}`);\n"
"      return x.length ? x.join(' ') : null;\n"
"    }\n"
"    case 'MAP_REPORT_APP': {\n"
"      const x = [];\n"
"      if (p.long_name) x.push(escHtml(p.long_name));\n"
"      if (p.firmware)  x.push('fw='+escHtml(p.firmware));\n"
"      if (p.region!==undefined) x.push('region='+p.region);\n"
"      if (typeof p.lat==='number' && typeof p.lon==='number')\n"
"        x.push(`${p.lat.toFixed(5)},${p.lon.toFixed(5)}`);\n"
"      return x.length ? x.join(' ') : null;\n"
"    }\n"
"    case 'TRACEROUTE_APP':\n"
"      return (p.route && p.route.length) ? `${p.route.length} hops` : null;\n"
"    case 'NEIGHBORINFO_APP':\n"
"      return (p.neighbors && p.neighbors.length) ? `${p.neighbors.length} neighbors` : null;\n"
"    case 'ROUTING_APP':\n"
"      return p.routing_kind || null;\n"
"    case 'PAXCOUNTER_APP': {\n"
"      const x = [];\n"
"      if (p.pax_wifi!==undefined) x.push('wifi='+p.pax_wifi);\n"
"      if (p.pax_ble !==undefined) x.push('ble=' +p.pax_ble);\n"
"      return x.length ? x.join(' ') : null;\n"
"    }\n"
"    case 'STORE_FORWARD_APP':\n"
"      return p.sf_rr || null;\n"
"    case 'KEY_VERIFICATION_APP':\n"
"    case 'REMOTE_HARDWARE_APP':\n"
"    case 'ADMIN_APP':\n"
"      return '\\u2014';\n"  /* en dash; show the row but no useful body */
"    case 'ATAK_PLUGIN':\n"
"      return null;\n"  /* ATAK already lands in Discoveries pane */
"    default:\n"
"      return null;\n"
"  }\n"
"}\n"
"function updateTrail(id, ll){\n"
"  if (!trails[id]) trails[id] = {pts:[], line:null};\n"
"  trails[id].pts.push(ll);\n"
"  if (trails[id].pts.length > 8) trails[id].pts.shift();\n"
"  if (trails[id].line) map.removeLayer(trails[id].line);\n"
"  if (trails[id].pts.length > 1)\n"
"    trails[id].line = L.polyline(trails[id].pts, {color:'#9bf',weight:2,opacity:0.6}).addTo(map);\n"
"}\n"
/* MC_ADV_TYPE_NAMES -- mirrors adv_type_names[] in feed_meshcore_json.c;
 * decodes both a live ADVERT event's numeric fallback and the
 * bootstrap API's persisted "role" column (see bootstrapNodesFromApi
 * and the node_db_remember() call in feed_meshcore_json.c) into the
 * same adv_type string nodeKind() below checks. */
"const MC_ADV_TYPE_NAMES = ['NONE','CHAT','REPEATER','ROOM','SENSOR'];\n"
/* nodeKind -- classifies a node for map styling. REPEATER wins over
 * ROOM/SENSOR whenever hopDepth is known (topoNoteRelayPath() has
 * observed this node actually relaying a real packet's path) --
 * most community repeaters just run default firmware config
 * regardless of their physical role, so relying on the self-reported
 * adv_type alone leaves genuinely-relaying nodes stuck looking like
 * people. Anything else (including nodes with no adv_type at all,
 * e.g. bootstrapNodesFromApi()'s /api/nodes data) is 'people'. */
"function nodeKind(n) {\n"
"  if (n && (n.adv_type === 'REPEATER' || n.hopDepth !== undefined)) return 'repeater';\n"
"  if (n && n.adv_type === 'SENSOR') return 'sensor';\n"
"  if (n && n.adv_type === 'ROOM') return 'room';\n"
"  return 'people';\n"
"}\n"
/* Per-kind marker styling. Repeater/sensor render as a small red
 * circle with a white perimeter; people render the same shape in
 * blue; rooms render as a red square (same color scheme as
 * repeater/sensor) via a divIcon, since a plain circleMarker can't
 * do square. All four replace the plain default Leaflet pin nodes
 * used to fall back to. */
"const NODE_STYLES = {\n"
"  repeater: {radius:6, color:'#fff', weight:2, fillColor:'#ef4444', fillOpacity:1},\n"
"  sensor:   {radius:6, color:'#fff', weight:2, fillColor:'#ef4444', fillOpacity:1},\n"
"  people:   {radius:6, color:'#fff', weight:2, fillColor:'#3b82f6', fillOpacity:1},\n"
"};\n"
"const REPEATER_BLINK_STYLE = {radius:7, color:'#fff', weight:2, fillColor:'#22c55e', fillOpacity:1};\n"
"const ROOM_ICON = L.divIcon({\n"
"  className: 'room-marker-icon',\n"
"  html: '<span style=\"display:block;width:12px;height:12px;background:#ef4444;border:2px solid #fff;box-sizing:border-box;\"></span>',\n"
"  iconSize: [12, 12], iconAnchor: [6, 6],\n"
"});\n"
/* placeMarker -- shared node-marker creation/update for both the live
 * SSE path (es.onmessage) and bootstrapNodesFromApi()'s restart
 * recovery. Kind (see nodeKind()) determines shape/color; a room's
 * L.Marker+divIcon and a circle-kind's L.CircleMarker are different
 * Leaflet classes with no in-place conversion, so a kind change
 * (e.g. adv_type learned only after the marker already exists)
 * removes and recreates rather than mutating. */
"function placeMarker(id, ll, n) {\n"
"  const kind = nodeKind(n);\n"
"  const existing = markers[id];\n"
"  if (existing) {\n"
"    if (existing._kind === kind) { existing.setLatLng(ll); return existing; }\n"
"    map.removeLayer(existing);\n"
"  }\n"
"  const marker = kind === 'room' ? L.marker(ll, {icon: ROOM_ICON}) : L.circleMarker(ll, NODE_STYLES[kind]);\n"
"  marker._kind = kind;\n"
"  marker.addTo(map).bindPopup(`<b>${id}</b><br>${(n && n.name) || ''}`);\n"
"  markers[id] = marker;\n"
"  return marker;\n"
"}\n"
/* blinkRepeater -- 10s green blink on a repeater/sensor marker relaying
 * a live frame (see traceLivePath() below). No-op for markers with no
 * .setStyle() (rooms use L.Marker+divIcon, which has none). Restores
 * the marker's own kind style (NODE_STYLES[m._kind]) when the blink
 * ends, not a hardcoded repeater red, so a people-kind marker that
 * happens to resolve as a hop blinks back to blue rather than staying
 * red. Re-triggering while already blinking restarts the 10s window
 * instead of stacking timers, so a busy repeater just stays lit
 * rather than flickering from overlapping timeouts. */
"function blinkRepeater(id) {\n"
"  const m = markers[id];\n"
"  if (!m || !m.setStyle) return;\n"
"  const baseStyle = NODE_STYLES[m._kind] || NODE_STYLES.repeater;\n"
"  if (m._blinkTimer) clearInterval(m._blinkTimer);\n"
"  if (m._blinkTimeout) clearTimeout(m._blinkTimeout);\n"
"  let on = false;\n"
"  m._blinkTimer = setInterval(() => { on = !on; m.setStyle(on ? REPEATER_BLINK_STYLE : baseStyle); }, 400);\n"
"  m._blinkTimeout = setTimeout(() => { clearInterval(m._blinkTimer); m._blinkTimer = null; m.setStyle(baseStyle); }, 10000);\n"
"}\n"
/* frameHopIds -- best-effort list of known node ids (path order) that
 * relayed this frame, for traceLivePath() below. Meshtastic
 * ROUTING_APP/TRACEROUTE_APP already carries full ids (p.route);
 * MeshCore only ever carries 1-3 byte hash prefixes (route_path_hex,
 * or trace_route_hashes_hex for TRACE -- see feed_meshcore_json.c),
 * resolved the same leading-prefix-match way drawMessagePath() (above)
 * does. Hash collisions between distinct nodes are possible for short
 * prefixes; unresolved hops are dropped rather than guessed. */
"function frameHopIds(p) {\n"
"  if (p.route && p.route.length) return p.route.filter(id => nodes[id]);\n"
"  let hex = null, hashSize = 1, hopCount = 0;\n"
"  if (p.trace_route_hashes_hex) { hex = p.trace_route_hashes_hex; hopCount = hex.length / 2; }\n"
"  else if (p.route_path_hex) { hex = p.route_path_hex; hashSize = p.route_path_hash_size || 1; hopCount = p.route_path_hash_count || 0; }\n"
"  if (!hex || !hopCount) return [];\n"
"  const ids = [];\n"
"  for (let i = 0; i < hopCount; i++) {\n"
"    const hop = hex.substr(i * hashSize * 2, hashSize * 2).toLowerCase();\n"
"    let match = null;\n"
"    for (const id of Object.keys(nodes)) {\n"
"      if (id.length === 9 && id.slice(1, 1 + hop.length) === hop) { match = id; break; }\n"
"    }\n"
"    if (match) ids.push(match);\n"
"  }\n"
"  return ids;\n"
"}\n"
/* FRAME_TYPE_COLORS -- live path-trace line color per frame type
 * (mc_type for MeshCore, port_name for Meshtastic); unlisted types
 * fall back to the same amber drawMessagePath() (above) uses for its
 * operator-triggered path line, for visual consistency. */
"const FRAME_TYPE_COLORS = {\n"
"  ADVERT: '#38bdf8', GRP_TXT: '#a78bfa', GRP_DATA: '#f472b6', TRACE: '#fbbf24',\n"
"  ACK: '#94a3b8', TXT_MSG: '#fb923c', REQ: '#f87171', RESPONSE: '#f87171',\n"
"  PATH: '#f87171', ANON_REQ: '#f87171',\n"
"};\n"
/* traceLivePath -- automatic per-frame relay visualization: draws the
 * resolved hop path as a line (color by frame type, see
 * FRAME_TYPE_COLORS) and blinks every resolved repeater hop green for
 * 10s (blinkRepeater()), the line itself fading out after the same
 * 10s. Distinct from drawMessagePath() (above), the operator-triggered
 * single-path lookup from a past message row, which persists on the
 * map until superseded by another manual lookup.
 *
 * Skips anything older than a few seconds: db_sqlite_replay_recent()
 * (--history-replay-hours, default 24h) pushes historical rows through
 * this same SSE stream on every reconnect/page load so the dashboard
 * isn't blank after a restart -- without this guard, a reload floods
 * the map with blink/trace animations for potentially hundreds of old
 * frames all at once instead of a clean, one-time reveal, and buries
 * whatever a genuinely live frame does under the noise. */
"function traceLivePath(p) {\n"
"  if (Date.now()/1000 - p.ts > 5) return;\n"
"  const ids = frameHopIds(p);\n"
"  for (const id of ids) blinkRepeater(id);\n"
"  const pts = ids.map(id => (markers[id] && markers[id].getLatLng) ? markers[id].getLatLng() : null).filter(Boolean);\n"
"  if (pts.length < 2) return;\n"
"  const color = FRAME_TYPE_COLORS[p.mc_type || p.port_name] || '#f59e0b';\n"
"  const line = L.polyline(pts, {color, weight:3, opacity:0.9}).addTo(map);\n"
"  setTimeout(() => map.removeLayer(line), 10000);\n"
"}\n"
"// Mesh edge: draw a line from src node to dst node when both are positioned.\n"
"// Used for relay_node hints and NEIGHBORINFO entries. SNR scales opacity.\n"
"function noteEdge(srcId, dstId, snr){\n"
"  if (!srcId || !dstId || srcId===dstId) return;\n"
"  if (!markers[srcId] || !markers[dstId]) return;\n"
"  const k = srcId<dstId ? srcId+'|'+dstId : dstId+'|'+srcId;\n"
"  const a = markers[srcId].getLatLng(), b = markers[dstId].getLatLng();\n"
"  // 0 dB -> 1.0 opacity, -20 dB -> 0.2 opacity, clamp.\n"
"  const op = Math.max(0.2, Math.min(1.0, 1.0 + (snr||0)/30.0));\n"
"  if (edges[k]) map.removeLayer(edges[k]);\n"
"  edges[k] = L.polyline([a,b], {color:'#fc6',weight:1,opacity:op,dashArray:'3,4'}).addTo(map);\n"
"}\n"
"// This sniffer's own GPS marker. Distinct from node markers: cyan ring,\n"
"// fixed pixel radius (circleMarker not Marker), 'RX' popup. Only present\n"
"// when --gpsd is running and a recent fix has been propagated through\n"
"// the JSON event stream. One marker, position updated in place.\n"
"let stationMarker = null;\n"
"function noteStation(lat, lon, alt){\n"
"  if (typeof lat !== 'number' || typeof lon !== 'number') return;\n"
"  const ll = [lat, lon];\n"
"  if (!stationMarker) {\n"
"    stationMarker = L.circleMarker(ll, {\n"
"      radius: 8, color: '#38bdf8', weight: 2,\n"
"      fillColor: '#0c4a6e', fillOpacity: 0.85\n"
"    }).addTo(map);\n"
"    stationMarker.bindPopup('<b>RX station</b><br>this sniffer');\n"
"    if (Object.keys(markers).length === 0) map.setView(ll, 11);\n"
"  } else {\n"
"    stationMarker.setLatLng(ll);\n"
"  }\n"
"  if (typeof alt === 'number')\n"
"    stationMarker.setPopupContent(`<b>RX station</b><br>this sniffer<br>${alt.toFixed(1)} m`);\n"
"}\n"
// Channels tab: a list of every channel hash seen (left) and, for the
// selected channel, its message log with a best-effort routing path per
// message (right). Message history + rendering both key off the same
// `channels[hash]` object the Live-tab Channels pane already maintains
// (see the channel bookkeeping block in es.onmessage below); this tab
// just adds a `_msgs` ring buffer and a click-to-select UI on top of it.
"const CHAN_HIST_MSGS = 200;\n"
"const chantabListTbody = document.querySelector('#chantab-list tbody');\n"
"const chantabEmpty = document.getElementById('chantab-empty');\n"
"const chantabCount = document.getElementById('chantab-count');\n"
"const chantabMsgsTbody = document.getElementById('chantab-msgs');\n"
"const chantabMsgsEmpty = document.getElementById('chantab-msgs-empty');\n"
"const chantabMsgsTitle = document.getElementById('chantab-msgs-title');\n"
"const chantabMsgsLoadOlderWrap = document.getElementById('chantab-msgs-loadolder-wrap');\n"
"const chantabMsgsLoadOlderBtn = document.getElementById('chantab-msgs-loadolder');\n"
"const chantabMsgsLoadOlderStatus = document.getElementById('chantab-msgs-loadolder-status');\n"
"let selectedChannelHash = null;\n"
"function fmtAgo(ts){\n"
"  /* ts is fractional epoch seconds from the JSON event; floor the whole\n"
"   * delta so we render '14s ago' instead of '14.936086893081665s ago'. */\n"
"  const dt = Math.max(0, Math.floor(Date.now()/1000 - ts));\n"
"  if (dt < 60) return dt+'s ago';\n"
"  if (dt < 3600) return Math.floor(dt/60)+'m ago';\n"
"  return Math.floor(dt/3600)+'h ago';\n"
"}\n"
/* pathSummary -- best-effort per-message routing path, in whichever
 * form the protocol/port actually carries one:
 *  - MeshCore: the packet-framing path[] (route_path_hex /
 *    route_path_hash_count) rides on every payload type, including
 *    plain GRP_TXT channel chat -- so it's shown whenever present,
 *    alongside the FLOOD/DIRECT route_type_name.
 *  - Meshtastic: there's no full path on ordinary traffic, only
 *    hop_start/hop_limit (hops used/total) and relay_node (last
 *    relayer's id upper byte). ROUTING_APP/TRACEROUTE_APP frames
 *    additionally carry a full node-id `route` array -- prefer that
 *    when present since it's the real answer. */
"function pathSummary(p){\n"
"  if (p.protocol === 'meshcore') {\n"
"    const rt = p.route_type_name || '';\n"
"    if (p.route_path_hash_count) {\n"
"      const size = p.route_path_hash_size || 1;\n"
"      const hex = p.route_path_hex || '';\n"
"      const hops = [];\n"
"      for (let i = 0; i < p.route_path_hash_count; i++) hops.push(hex.substr(i*size*2, size*2));\n"
"      return `${rt}: ${hops.join('\\u2192')}`;\n"
"    }\n"
"    return rt || null;\n"
"  }\n"
"  if (p.route && p.route.length) return p.route.join('\\u2192');\n"
"  const parts = [];\n"
"  if (typeof p.hop_start === 'number' && typeof p.hop_limit === 'number')\n"
"    parts.push(`${p.hop_start - p.hop_limit}/${p.hop_start} hops`);\n"
"  if (p.relay_node !== undefined && p.relay_node !== null)\n"
"    parts.push('via 0x' + (p.relay_node & 0xff).toString(16).padStart(2,'0'));\n"
"  return parts.length ? parts.join(' ') : null;\n"
"}\n"
/* buildMsgRow -- shared row shape for both live SSE chat frames
 * (noteChannelMessage) and DB-loaded scroll-back (loadOlderMessages),
 * so the two sources render identically without duplicating the
 * field mapping. */
"function buildMsgRow(p, summary){\n"
"  return {t:p.ts, from:p.from||null, name:p.long_name||p.node_name||null,\n"
"          type:p.port_name||p.mc_type||'', summary:summary, rawText:p.text||null, path:pathSummary(p),\n"
"          pathHex:p.route_path_hex||p.trace_route_hashes_hex||null,\n"
"          pathHopCount:p.route_path_hash_count||(p.trace_route_hashes_hex?p.trace_route_hashes_hex.length/2:0),\n"
"          pathHashSize:p.route_path_hash_size||1};\n"
"}\n"
"function noteChannelMessage(h, p, summary){\n"
"  const c = channels[h]; if (!c) return;\n"
"  if (!c._msgs) c._msgs = [];\n"
"  c._msgs.unshift(buildMsgRow(p, summary));\n"
"  if (c._msgs.length > CHAN_HIST_MSGS) c._msgs.length = CHAN_HIST_MSGS;\n"
"  if (selectedChannelHash === h) renderChannelMessages();\n"
"}\n"
"let chantabRafQueued = false;\n"
"function refreshChannelsTab(){\n"
"  if (chantabRafQueued) return;\n"
"  chantabRafQueued = true;\n"
"  requestAnimationFrame(()=>{ chantabRafQueued = false; renderChannelsTab(); });\n"
"}\n"
"function renderChannelsTab(){\n"
"  const hashes = Object.keys(channels).sort((a,b)=>channels[b].ts-channels[a].ts);\n"
"  chantabEmpty.style.display = hashes.length ? 'none' : 'block';\n"
"  chantabCount.textContent = hashes.length ? `(${hashes.length})` : '';\n"
"  const frag = document.createDocumentFragment();\n"
"  for (const h of hashes){\n"
"    const c = channels[h];\n"
"    const tr = document.createElement('tr');\n"
"    tr.className = 'chan-row' + (h === selectedChannelHash ? ' selected' : '');\n"
"    const hashHex = '0x'+(chanKeyHash(h)&0xff).toString(16).padStart(2,'0');\n"
"    const name = c.name || '<span class=muted>(encrypted)</span>';\n"
"    const proto = c.protocol === 'meshcore' ? 'MeshCore' : (c.preset || '<span class=muted>--</span>');\n"
"    tr.innerHTML = `<td>${hashHex}</td><td>${name}</td><td>${proto}</td><td>${fmtCount(c.total)}</td><td>${fmtAgo(c.ts)}</td>`;\n"
"    tr.onclick = ()=>selectChannel(h);\n"
"    frag.appendChild(tr);\n"
"  }\n"
"  chantabListTbody.replaceChildren(frag);\n"
"}\n"
"function selectChannel(h){\n"
"  selectedChannelHash = h;\n"
"  renderChannelsTab();\n"
"  renderChannelMessages();\n"
"  channelsSwipeTo(1);\n"
/* First time this channel is opened (no page loaded yet and no live
 * SSE traffic has arrived for it since page load either), pull its
 * history immediately instead of showing an empty pane until the
 * operator manually clicks "load older" -- most channels, especially
 * one just added/cracked, won't have any live c._msgs yet. */
"  const c = channels[h];\n"
"  if (c && !c._older && !c._olderDone) loadOlderMessages();\n"
"}\n"
/* grpTxtSender -- MeshCore's GRP_TXT firmware convention (BaseChatMesh)
 * embeds the real per-message sender as a "Name: message" prefix in
 * the decrypted text itself; the packet-level `from`/id is only a
 * synthetic per-CHANNEL tag (0x8000|channel_hash), not a per-sender
 * identity, so it can't be used to tell two people in the same channel
 * apart. Returns {name, body} split on the first ": ", or null if this
 * isn't a GRP_TXT row or the text doesn't look prefixed. */
"function grpTxtSender(m){\n"
"  if (m.type !== 'GRP_TXT' || !m.rawText) return null;\n"
"  const idx = m.rawText.indexOf(': ');\n"
"  if (idx <= 0 || idx > 40) return null;\n"
"  return { name: m.rawText.slice(0, idx), body: m.rawText.slice(idx + 2) };\n"
"}\n"
/* chatSide -- stable left/right bucket per distinct sender within a
 * channel, so a back-and-forth between two people renders like a real
 * SMS/WhatsApp thread instead of a uniform log. Assignment is sticky
 * (stored on the channel object) so a sender doesn't flip sides on
 * every re-render; a 3rd+ distinct sender just reuses the a/b split. */
"function chatSide(c, key){\n"
"  if (!c._sides) c._sides = {};\n"
"  if (!c._sides[key]) c._sides[key] = (Object.keys(c._sides).length % 2 === 0) ? 'a' : 'b';\n"
"  return c._sides[key];\n"
"}\n"
"function renderChannelMessages(){\n"
"  const h = selectedChannelHash;\n"
"  const c = h ? channels[h] : null;\n"
"  if (!c) {\n"
"    chantabMsgsTitle.innerHTML = 'Messages <span class=muted>select a channel</span>';\n"
"    chantabMsgsTbody.replaceChildren();\n"
"    chantabMsgsEmpty.style.display = 'block';\n"
"    chantabMsgsLoadOlderWrap.style.display = 'none';\n"
"    return;\n"
"  }\n"
"  const hashHex = '0x'+(chanKeyHash(h)&0xff).toString(16).padStart(2,'0');\n"
"  chantabMsgsTitle.innerHTML = `Messages <span class=muted>${c.name || '(encrypted)'} ${hashHex}</span>`;\n"
"  const hist = [...(c._msgs||[]), ...(c._older||[])];\n"
"  chantabMsgsEmpty.style.display = hist.length ? 'none' : 'block';\n"
"  const frag = document.createDocumentFragment();\n"
"  for (const m of hist){\n"
"    const div = document.createElement('div');\n"
"    const parsed = grpTxtSender(m);\n"
"    const senderKey = parsed ? parsed.name : (m.name || m.from || '?');\n"
"    div.className = 'chat-msg side-' + chatSide(c, senderKey);\n"
"    const senderLabel = escHtml(parsed ? parsed.name : (m.name || 'Unknown'));\n"
"    const body = parsed ? escHtml(parsed.body)\n"
"      : ((m.summary===null || m.summary===undefined) ? '<span class=muted>\\u2014</span>' : m.summary);\n"
"    const pathTitle = m.path ? ` title=\"${escHtml(m.path)}\"` : '';\n"
"    const pathBtn = m.pathHex ? ` <button class=btn-mini${pathTitle} onclick=\"drawMessagePath('${m.pathHex}',${m.pathHopCount},${m.pathHashSize})\">path</button>` : '';\n"
"    const pathHint = (!m.pathHex && m.path) ? `<span class=chat-path>${escHtml(m.path)}</span>` : '';\n"
"    div.innerHTML = `<div class=chat-col>`\n"
"      + `<div class=chat-meta><b>${senderLabel}</b></div>`\n"
"      + `<div class=chat-bubble>${body}</div>`\n"
"      + `<div class=chat-foot><span class=ts>${fmtTime(m.t)}</span>${pathHint}${pathBtn}</div>`\n"
"      + `</div>`;\n"
"    frag.appendChild(div);\n"
"  }\n"
"  chantabMsgsTbody.replaceChildren(frag);\n"
"  chantabMsgsLoadOlderWrap.style.display = c._olderDone ? 'none' : 'block';\n"
"}\n"
/* loadOlderMessages -- fetch the next page of a channel's chat history
 * directly from SQLite via /api/messages, older than the oldest row
 * currently held (across live c._msgs and already-loaded c._older).
 * Results are mapped through buildMsgRow/msgSummary only -- NOT run
 * through the live es.onmessage dispatcher, which has map/topology/
 * discovery side effects that must not fire for scroll-back history. */
"async function loadOlderMessages(){\n"
"  const h = selectedChannelHash; if (h == null) return;\n"
"  const c = channels[h]; if (!c) return;\n"
"  const all = [...(c._msgs||[]), ...(c._older||[])];\n"
"  const oldestTs = all.length ? all[all.length-1].t : (Date.now()/1000);\n"
"  chantabMsgsLoadOlderBtn.disabled = true;\n"
"  chantabMsgsLoadOlderStatus.textContent = 'loading...';\n"
"  try {\n"
"    const resp = await fetch(`/api/messages?channel=${chanKeyHash(h)}&before=${oldestTs}&limit=100`);\n"
"    if (!resp.ok) throw new Error('http '+resp.status);\n"
"    const j = await resp.json();\n"
/* The hash alone is ambiguous on a collision -- the API has no way to
 * filter by name (it's not a stored column keyed the same way), so
 * it returns every message on this raw hash, which can include the
 * OTHER colliding channel's history. Filter to just this specific
 * channel identity before appending: matching name, or (for the
 * bare-hash "(encrypted)" bucket) still-undecrypted rows only. */
"    const matches = (p) => c.name ? (p.channel_name === c.name) : !p.channel_name;\n"
"    if (!c._older) c._older = [];\n"
"    for (const p of (j.messages||[])) if (matches(p)) c._older.push(buildMsgRow(p, msgSummary(p)));\n"
"    if (!j.more) c._olderDone = true;\n"
"    chantabMsgsLoadOlderStatus.textContent = (j.messages||[]).length ? '' : 'no older messages';\n"
"  } catch (e) { chantabMsgsLoadOlderStatus.textContent = 'failed to load'; }\n"
"  chantabMsgsLoadOlderBtn.disabled = false;\n"
"  if (selectedChannelHash === h) renderChannelMessages();\n"
"}\n"
"chantabMsgsLoadOlderBtn.onclick = loadOlderMessages;\n"
"// =============================================================\n"
"// Topology tab: force-directed mesh-graph rendered to canvas.\n"
"// Edges come from two sources: NEIGHBORINFO_APP (authoritative\n"
"// 'I heard X with SNR Y') and the relay-hop hint (header.relay_node\n"
"// = upper byte of relayer's id, only resolved when we have a known\n"
"// node with that upper byte). Custom physics rather than vis-network\n"
"// to keep the dashboard CDN-free and bytecount tight.\n"
"// =============================================================\n"
"const topoCanvas = document.getElementById('topo-canvas');\n"
"const topoCtx = topoCanvas.getContext('2d');\n"
"const topoEmpty = document.getElementById('topo-empty');\n"
"// topoNodes[id] = {x, y, vx, vy, id, frames}\n"
"// topoEdges[a+'|'+b] = {a, b, snr, lastTs, count}  (a < b lexically)\n"
"const topoNodes = {}, topoEdges = {};\n"
"let topoActive = false, topoHover = null, topoMouse = {x:0, y:0};\n"
"let topoRafHandle = 0, topoLastTick = 0;\n"
"const TOPO_NODE_MAX = 200; /* render cap; nodes beyond this are pruned by recency */\n"
"// Synthetic 'this station' node id. Drawn at the canvas center,\n"
"// represents the sniffer's own RX. Every frame creates a faint dashed\n"
"// pseudo-edge from the transmitting node to this dot, colored by SNR --\n"
"// so even a sparse mesh with no NEIGHBORINFO traffic shows useful info\n"
"// (what the sniffer can hear and how well).\n"
"const RX_STATION_ID = '__rx_station__';\n"
"// Radial layout ring spacing shared by topoEnsureNode's initial seed and\n"
"// topoTick's ongoing radial spring, so a node with a known hopDepth\n"
"// (see topoNoteRelayPath) settles at ring (hopDepth-1), radiating\n"
"// outward from the RX station by real observed hop-distance.\n"
"const TOPO_RING_BASE = 50, TOPO_RING_STEP = 55;\n"
"function topoNoteEdge(srcId, dstId, snr){\n"
"  if (!srcId || !dstId || srcId === dstId) return;\n"
"  const k = srcId < dstId ? srcId+'|'+dstId : dstId+'|'+srcId;\n"
"  let e = topoEdges[k];\n"
"  if (!e) e = topoEdges[k] = {a: srcId<dstId?srcId:dstId, b: srcId<dstId?dstId:srcId, snr: snr, count: 0, kind:'real'};\n"
"  if (snr !== undefined && snr !== null) e.snr = snr;\n"
"  e.count++; e.lastTs = Date.now()/1000;\n"
"  topoEnsureNode(srcId); topoEnsureNode(dstId);\n"
"  if (topoEmpty.style.display !== 'none') topoEmpty.style.display = 'none';\n"
"}\n"
"// Conversation pairs: per (sender, recipient) direction we mark each\n"
"// half observed. When both halves have been seen at any point in the\n"
"// session, that's a confirmed bidirectional conversation pair and a\n"
"// distinct edge style is drawn (kind='convo'). 'addressed' alone\n"
"// (one direction only) is intent, not RF observation, and is not drawn.\n"
"const topoPairs = {}; /* 'min|max' -> {fwd:bool, rev:bool} */\n"
"function topoNoteAddressed(fromId, toId){\n"
"  if (!fromId || !toId || fromId === toId) return;\n"
"  if (toId === '!ffffffff') return; /* broadcast: not a conversation pair */\n"
"  const lo = fromId < toId ? fromId : toId;\n"
"  const hi = fromId < toId ? toId : fromId;\n"
"  const k = lo+'|'+hi;\n"
"  let p = topoPairs[k];\n"
"  if (!p) p = topoPairs[k] = {fwd:false, rev:false};\n"
"  if (fromId === lo) p.fwd = true; else p.rev = true;\n"
"  if (p.fwd && p.rev) {\n"
"    /* Both directions seen: draw the bidirectional convo edge. */\n"
"    let e = topoEdges[k];\n"
"    if (!e) e = topoEdges[k] = {a: lo, b: hi, snr: undefined, count: 0, kind:'convo'};\n"
"    e.count++; e.lastTs = Date.now()/1000;\n"
"    topoEnsureNode(lo); topoEnsureNode(hi);\n"
"    if (topoEmpty.style.display !== 'none') topoEmpty.style.display = 'none';\n"
"  }\n"
"}\n"
"// Pseudo-edge from a transmitting node to the RX station. Marked\n"
"// kind='heard' so the renderer can dash it differently from real\n"
"// observed-RX edges (NEIGHBORINFO_APP / relay_node hop).\n"
"function topoNoteHeard(srcId, snr){\n"
"  if (!srcId || srcId === RX_STATION_ID) return;\n"
"  const k = srcId < RX_STATION_ID ? srcId+'|'+RX_STATION_ID : RX_STATION_ID+'|'+srcId;\n"
"  let e = topoEdges[k];\n"
"  if (!e) e = topoEdges[k] = {a: srcId<RX_STATION_ID?srcId:RX_STATION_ID,\n"
"                              b: srcId<RX_STATION_ID?RX_STATION_ID:srcId,\n"
"                              snr: snr, count: 0, kind:'heard'};\n"
"  if (snr !== undefined && snr !== null) e.snr = snr;\n"
"  e.count++; e.lastTs = Date.now()/1000;\n"
"  topoEnsureNode(srcId); topoEnsureNode(RX_STATION_ID);\n"
"  if (topoEmpty.style.display !== 'none') topoEmpty.style.display = 'none';\n"
"}\n"
"// Resolve one path hop's hash bytes (hex string) to a known node id.\n"
"// A path hop hash is literally a prefix of the relaying repeater's own\n"
"// pubkey (confirmed against the MeshCore firmware: Identity::copyHashTo()\n"
"// copies pub_key bytes directly, no separate hash function) -- and this\n"
"// dashboard's node id IS that same pubkey's first 4 bytes (see\n"
"// mc_derive_from_id() in feed_meshcore_json.c), so a hop hash is always\n"
"// a byte-prefix of some known node's id once we've seen that node's\n"
"// ADVERT. Synthetic ids (GRP_TXT/envelope-only tags) are never pubkey-\n"
"// derived and are excluded. At hash_size=1 (256 possible values) two\n"
"// unrelated repeaters can legitimately share a hash -- the firmware\n"
"// itself only guarantees uniqueness among a node's immediate neighbors,\n"
"// not globally -- and once a few dozen nodes are known (easy: the\n"
"// cross-restart node-list reload pulls in every node ever seen) most\n"
"// 1-byte values collide with something. Rejecting all ambiguous 1-byte\n"
"// hops outright made the tree show almost nothing in practice, so those\n"
"// specifically fall back to a best-effort pick: whichever candidate was\n"
"// heard most recently (statistically more likely to still be the active\n"
"// repeater near us right now). 2-3 byte hops keep the strict\n"
"// reject-on-ambiguity behavior -- collisions there are vanishingly\n"
"// unlikely, so ambiguity is a real 'can't tell', not just noise.\n"
/* topoResolveHopCandidates -- every known non-synthetic node id whose
 * pubkey-prefix matches this hop's hash bytes, unfiltered. Split out
 * of topoResolveHop() (below) so the repeater-marker signal in
 * topoNoteRelayPath() can treat ALL candidates of an ambiguous 1-byte
 * hop as "possibly relayed this" instead of only whichever one
 * topoResolveHop()'s single-best-guess tie-break happens to pick. That
 * tie-break (most-recently-seen) is right for drawing one clean
 * Topology edge, but wrong here: two colliding real nodes bootstrapped
 * in the same instant (identical .ts) sort in a fixed, arbitrary
 * order, so the loser would NEVER get relay credit no matter how much
 * it actually relays. */
"function topoResolveHopCandidates(hex) {\n"
"  const want = hex.toLowerCase();\n"
"  const matches = [];\n"
"  for (const id of Object.keys(nodes)) {\n"
"    if (nodes[id].synthetic) continue;\n"
"    if (id.slice(1).toLowerCase().startsWith(want)) matches.push(id);\n"
"  }\n"
"  return matches;\n"
"}\n"
"function topoResolveHop(hex) {\n"
"  const matches = topoResolveHopCandidates(hex);\n"
"  if (matches.length === 0) return null;\n"
"  if (matches.length === 1) return matches[0];\n"
"  if (hex.length > 2) return null;\n"
"  matches.sort((a,b) => (nodes[b].ts||0) - (nodes[a].ts||0));\n"
"  return matches[0];\n"
"}\n"
"// Real relay edge, keyed in its own namespace so it never collides with\n"
"// (or gets overwritten by) the heard/real/convo edges above, which share\n"
"// one flat keyspace among themselves -- 'count' here means specifically\n"
"// how many times this exact repeater-to-repeater hop was observed.\n"
"function topoNoteRelay(srcId, dstId) {\n"
"  if (!srcId || !dstId || srcId === dstId) return;\n"
"  const pair = srcId < dstId ? srcId+'|'+dstId : dstId+'|'+srcId;\n"
"  const k = 'relay:' + pair;\n"
"  let e = topoEdges[k];\n"
"  if (!e) e = topoEdges[k] = {a: srcId<dstId?srcId:dstId, b: srcId<dstId?dstId:srcId, count: 0, kind:'relay'};\n"
"  e.count++; e.lastTs = Date.now()/1000;\n"
"  topoEnsureNode(srcId); topoEnsureNode(dstId);\n"
"  if (topoEmpty.style.display !== 'none') topoEmpty.style.display = 'none';\n"
"}\n"
"// Turn one event's route_path_hex into relay edges + hop-depth hints.\n"
"// path[] is ordered from the FIRST repeater to touch the packet (closest\n"
"// to origin) to the LAST (closest to us), each relay appending its own\n"
"// hash before forwarding -- so consecutive hops are real observed\n"
"// repeater-to-repeater exchanges, and the last hop is who actually\n"
"// delivered this packet to our receiver.\n"
"// Running tallies surfaced in the Topology legend (see topoRender) so\n"
"// it's visible at a glance whether the tree is empty because no path\n"
"// data has arrived yet (paths stays 0) vs. hops arriving but not\n"
"// resolving to known nodes (resolved << hops) vs. something else.\n"
"const topoRelayStats = { paths: 0, hops: 0, resolved: 0 };\n"
"function topoNoteRelayPath(p) {\n"
"  if (!p.route_path_hex || !p.route_path_hash_count || !p.route_path_hash_size) return;\n"
"  const hexLen = p.route_path_hash_size * 2;\n"
"  const hops = [];\n"
"  for (let i = 0; i < p.route_path_hash_count; ++i) {\n"
"    hops.push(p.route_path_hex.slice(i*hexLen, i*hexLen+hexLen));\n"
"  }\n"
"  const resolved = hops.map(topoResolveHop);\n"
"  topoRelayStats.paths++; topoRelayStats.hops += hops.length;\n"
"  topoRelayStats.resolved += resolved.filter(Boolean).length;\n"
"  for (let i = 0; i < resolved.length - 1; ++i) {\n"
"    if (resolved[i] && resolved[i+1]) topoNoteRelay(resolved[i], resolved[i+1]);\n"
"  }\n"
"  const last = resolved[resolved.length-1];\n"
"  if (last) topoNoteRelay(last, RX_STATION_ID);\n"
"  // Hop-depth from us, counted from the END of the path (last hop =\n"
"  // depth 1, closest to us; first hop = depth N, closest to origin).\n"
"  // Track the MINIMUM ever observed so the radial layout (topoTick)\n"
"  // stays put even if a later packet happens to take a longer route.\n"
/* Iterates raw hops (not `resolved`) and every candidate per hop, not
 * just topoResolveHop()'s single tie-broken winner -- see
 * topoResolveHopCandidates()'s comment above for why: an ambiguous
 * 1-byte hop's loser is still a real, plausible repeater for this
 * purpose, it just didn't win that one arbitrary tie-break. */
"  for (let i = 0; i < hops.length; ++i) {\n"
"    const depth = hops.length - i;\n"
"    for (const id of topoResolveHopCandidates(hops[i])) {\n"
"    const n = nodes[id];\n"
"    if (n && (n.hopDepth === undefined || depth < n.hopDepth)) {\n"
"      const firstRelaySeen = n.hopDepth === undefined;\n"
"      n.hopDepth = depth;\n"
/* This node just became known as an actual relay (see placeMarker()'s
 * repeater-style check above) -- restyle its marker immediately using
 * its current position instead of waiting for its next ADVERT. Only
 * on the transition into "known relay", not every depth update, so an
 * already-styled repeater's marker isn't torn down and rebuilt on
 * every single packet it relays. */
"      if (firstRelaySeen && markers[id] && markers[id].getLatLng) placeMarker(id, markers[id].getLatLng(), n);\n"
"    }\n"
"    }\n"
"  }\n"
"}\n"
"function topoEnsureNode(id){\n"
"  if (topoNodes[id]) return topoNodes[id];\n"
"  const rect = topoCanvas.getBoundingClientRect();\n"
"  const W = rect.width || 800, H = rect.height || 600;\n"
"  // RX station gets pinned at the canvas center so other nodes\n"
"  // arrange around it geographically. Real nodes seed at a random\n"
"  // ring around center so the force layout converges quickly -- ring\n"
"  // radius is biased by hopDepth (see topoNoteRelayPath) when known, so\n"
"  // repeaters start roughly where the ongoing radial spring in topoTick\n"
"  // will settle them instead of drifting in from a generic default ring.\n"
"  if (id === RX_STATION_ID) {\n"
"    topoNodes[id] = {id, x: W/2, y: H/2, vx:0, vy:0, pinned:true};\n"
"  } else {\n"
"    const n = nodes[id];\n"
"    const depth = (n && n.hopDepth) || 1;\n"
"    const baseR = TOPO_RING_BASE + (depth-1) * TOPO_RING_STEP;\n"
"    const a = Math.random()*Math.PI*2, r = baseR + Math.random()*30;\n"
"    topoNodes[id] = {id, x: W/2 + Math.cos(a)*r, y: H/2 + Math.sin(a)*r, vx:0, vy:0};\n"
"  }\n"
"  return topoNodes[id];\n"
"}\n"
"function topoSize(){ topoCanvas.width = topoCanvas.clientWidth; topoCanvas.height = topoCanvas.clientHeight; }\n"
"function topoSnrColor(snr, alpha){\n"
"  // SNR -> green (good) ... yellow ... red-ish (poor). Unknown SNR = neutral grey.\n"
"  if (snr === undefined || snr === null) return `rgba(148,163,184,${alpha||0.45})`;\n"
"  const s = Math.max(-25, Math.min(10, snr));\n"
"  const t = (s + 25) / 35; // 0..1\n"
"  const r = Math.round(255 * (1.0 - t));\n"
"  const g = Math.round(180 * t + 60);\n"
"  const b = 80;\n"
"  return `rgba(${r},${g},${b},${alpha||0.7})`;\n"
"}\n"
"function topoPrune(){\n"
"  const ids = Object.keys(topoNodes);\n"
"  if (ids.length <= TOPO_NODE_MAX) return;\n"
"  // Drop nodes with no recent edge activity, oldest first.\n"
"  ids.sort((a,b)=>{\n"
"    const la = (nodes[a] && nodes[a].ts) || 0;\n"
"    const lb = (nodes[b] && nodes[b].ts) || 0;\n"
"    return la - lb;\n"
"  });\n"
"  const drop = ids.length - TOPO_NODE_MAX;\n"
"  for (let i=0;i<drop;++i){\n"
"    delete topoNodes[ids[i]];\n"
"    for (const k of Object.keys(topoEdges)){\n"
"      if (topoEdges[k].a === ids[i] || topoEdges[k].b === ids[i]) delete topoEdges[k];\n"
"    }\n"
"  }\n"
"}\n"
"function topoTick(dt){\n"
"  const ids = Object.keys(topoNodes);\n"
"  if (!ids.length) return;\n"
"  const W = topoCanvas.width, H = topoCanvas.height;\n"
"  const cx = W/2, cy = H/2;\n"
"  // Repulsion (Coulomb-ish): O(n^2). At our 200-node cap that's 40k pair\n"
"  // checks per tick, well under the JS budget at 30 fps.\n"
"  const K_REP = 7000, K_ATT = 0.04, REST = 80, GRAV = 0.012, DAMP = 0.85, V_MAX = 240;\n"
"  const K_RAD = 0.02; // radial spring constant for hopDepth-ranked nodes\n"
"  for (let i=0;i<ids.length;++i){\n"
"    const id = ids[i];\n"
"    const a = topoNodes[id];\n"
"    let fx = 0, fy = 0;\n"
"    for (let j=0;j<ids.length;++j){\n"
"      if (i===j) continue;\n"
"      const b = topoNodes[ids[j]];\n"
"      let dx = a.x - b.x, dy = a.y - b.y;\n"
"      let d2 = dx*dx + dy*dy;\n"
"      if (d2 < 16) { dx = (Math.random()-0.5)*4; dy = (Math.random()-0.5)*4; d2 = 16; }\n"
"      const f = K_REP / d2;\n"
"      const d = Math.sqrt(d2);\n"
"      fx += (dx/d) * f; fy += (dy/d) * f;\n"
"    }\n"
"    // Nodes with a known hopDepth (real relay-path evidence) get pulled\n"
"    // toward their ring radius instead of straight at the center, so the\n"
"    // graph settles into rings radiating outward by hop-distance from us\n"
"    // -- 'root from path'. Everything else keeps the old flat pull-to-\n"
"    // center behavior unchanged.\n"
"    const nd = nodes[id];\n"
"    if (nd && nd.hopDepth) {\n"
"      const targetR = TOPO_RING_BASE + (nd.hopDepth-1) * TOPO_RING_STEP;\n"
"      const dx = a.x - cx, dy = a.y - cy;\n"
"      const dist = Math.sqrt(dx*dx + dy*dy) || 0.001;\n"
"      const diff = dist - targetR;\n"
"      fx -= (dx/dist) * diff * K_RAD; fy -= (dy/dist) * diff * K_RAD;\n"
"    } else {\n"
"      // Center gravity so isolated subgraphs don't drift forever.\n"
"      fx += (cx - a.x) * GRAV; fy += (cy - a.y) * GRAV;\n"
"    }\n"
"    a._fx = fx; a._fy = fy;\n"
"  }\n"
"  // Spring attraction along edges.\n"
"  for (const k in topoEdges){\n"
"    const e = topoEdges[k];\n"
"    const a = topoNodes[e.a], b = topoNodes[e.b];\n"
"    if (!a || !b) continue;\n"
"    const dx = b.x - a.x, dy = b.y - a.y;\n"
"    const d = Math.sqrt(dx*dx + dy*dy) || 0.001;\n"
"    const f = K_ATT * (d - REST);\n"
"    const fx = (dx/d) * f, fy = (dy/d) * f;\n"
"    a._fx += fx; a._fy += fy;\n"
"    b._fx -= fx; b._fy -= fy;\n"
"  }\n"
"  // Integrate. Pinned nodes (the RX station) skip integration so they\n"
"  // stay at their seeded center position regardless of edge forces.\n"
"  for (const id of ids){\n"
"    const a = topoNodes[id];\n"
"    if (a.pinned) { a.x = W/2; a.y = H/2; a.vx = 0; a.vy = 0; continue; }\n"
"    a.vx = (a.vx + a._fx*dt) * DAMP;\n"
"    a.vy = (a.vy + a._fy*dt) * DAMP;\n"
"    if (a.vx >  V_MAX) a.vx =  V_MAX; else if (a.vx < -V_MAX) a.vx = -V_MAX;\n"
"    if (a.vy >  V_MAX) a.vy =  V_MAX; else if (a.vy < -V_MAX) a.vy = -V_MAX;\n"
"    a.x += a.vx * dt; a.y += a.vy * dt;\n"
"    // Bounce softly at edges.\n"
"    const margin = 24;\n"
"    if (a.x < margin) { a.x = margin; a.vx *= -0.4; }\n"
"    if (a.y < margin) { a.y = margin; a.vy *= -0.4; }\n"
"    if (a.x > W-margin) { a.x = W-margin; a.vx *= -0.4; }\n"
"    if (a.y > H-margin) { a.y = H-margin; a.vy *= -0.4; }\n"
"  }\n"
"}\n"
"function topoNodeAt(mx, my){\n"
"  for (const id of Object.keys(topoNodes)){\n"
"    const a = topoNodes[id];\n"
"    const r = topoNodeRadius(id);\n"
"    const dx = a.x - mx, dy = a.y - my;\n"
"    if (dx*dx + dy*dy <= (r+3)*(r+3)) return id;\n"
"  }\n"
"  return null;\n"
"}\n"
"function topoNodeRadius(id){\n"
"  const n = nodes[id];\n"
"  const f = (n && n.frames) || 1;\n"
"  return Math.min(14, 4 + Math.log2(1 + f) * 1.4);\n"
"}\n"
"function topoRender(){\n"
"  const W = topoCanvas.width, H = topoCanvas.height;\n"
"  topoCtx.clearRect(0,0,W,H);\n"
"  const isLight = document.documentElement.classList.contains('light');\n"
"  const relayStatsEl = document.getElementById('topo-relay-stats');\n"
"  if (relayStatsEl) {\n"
"    const relayEdges = Object.keys(topoEdges).filter(k=>k.startsWith('relay:')).length;\n"
"    relayStatsEl.textContent = topoRelayStats.paths\n"
"      ? ` \\u00b7 relay: ${relayEdges} edge(s) from ${topoRelayStats.paths} path(s), ${topoRelayStats.resolved}/${topoRelayStats.hops} hops resolved`\n"
"      : '';\n"
"  }\n"
"  // Edges first. 'heard' kind (this-station-to-source pseudo-edge)\n"
"  // renders dashed and a touch fainter so it doesn't compete visually\n"
"  // with real observed-RX edges (NEIGHBORINFO_APP / relay-hop).\n"
"  for (const k in topoEdges){\n"
"    const e = topoEdges[k];\n"
"    const a = topoNodes[e.a], b = topoNodes[e.b];\n"
"    if (!a || !b) continue;\n"
"    const isH = topoHover && (e.a===topoHover || e.b===topoHover);\n"
"    const isHeard = e.kind === 'heard';\n"
"    const isConvo = e.kind === 'convo';\n"
"    const isRelay = e.kind === 'relay';\n"
"    if (isRelay) {\n"
"      /* Real relay-path edge: solid green, width scales with how many\n"
"       * times this exact hop-pair has been observed -- 'bigger edge is\n"
"       * the bigger exchange'. Capped/log-scaled so one very chatty pair\n"
"       * can't dwarf the rest of the drawing. */\n"
"      const w = Math.min(7, 1.5 + Math.log2(1 + e.count) * 1.2);\n"
"      topoCtx.strokeStyle = isH ? 'rgba(74,222,128,0.95)' : 'rgba(74,222,128,0.65)';\n"
"      topoCtx.lineWidth = isH ? w + 1 : w;\n"
"      topoCtx.setLineDash([]);\n"
"    } else if (isConvo) {\n"
"      /* Conversation pair (both directions observed). Soft amber\n"
"       * solid line, distinct from observed-RX SNR-colored edges. */\n"
"      topoCtx.strokeStyle = isH ? 'rgba(251,191,36,0.95)' : 'rgba(251,191,36,0.65)';\n"
"      topoCtx.lineWidth = isH ? 2 : 1.4;\n"
"      topoCtx.setLineDash([]);\n"
"    } else {\n"
"      topoCtx.strokeStyle = topoSnrColor(e.snr, isH ? 0.95 : (isHeard ? 0.30 : 0.55));\n"
"      topoCtx.lineWidth = isH ? 2 : 1;\n"
"      topoCtx.setLineDash(isHeard ? [4, 3] : []);\n"
"    }\n"
"    topoCtx.beginPath(); topoCtx.moveTo(a.x, a.y); topoCtx.lineTo(b.x, b.y); topoCtx.stroke();\n"
"  }\n"
"  topoCtx.setLineDash([]);\n"
"  // Nodes. The RX station (this sniffer) renders distinctly: cyan\n"
"  // outer ring, larger, always labeled 'RX'.\n"
"  topoCtx.font = '12px system-ui';\n"
"  topoCtx.textAlign = 'center'; topoCtx.textBaseline = 'top';\n"
"  for (const id of Object.keys(topoNodes)){\n"
"    const a = topoNodes[id];\n"
"    const isStation = id === RX_STATION_ID;\n"
"    const r = isStation ? 9 : topoNodeRadius(id);\n"
"    const isH = id === topoHover;\n"
"    // REPEATER/ROOM/SENSOR nodes (from ADVERT's adv_type_name) render as\n"
"    // squares so a repeater backbone reads visually distinct from chat\n"
"    // clients at a glance -- everything else (incl. the RX station,\n"
"    // handled separately above) stays a circle.\n"
"    const nd2 = nodes[id];\n"
"    const isRepeaterLike = !isStation && nd2 && (nd2.adv_type === 'REPEATER' || nd2.adv_type === 'ROOM' || nd2.adv_type === 'SENSOR');\n"
"    topoCtx.beginPath();\n"
"    if (isRepeaterLike) topoCtx.rect(a.x-r, a.y-r, r*2, r*2); else topoCtx.arc(a.x, a.y, r, 0, Math.PI*2);\n"
"    if (isStation) {\n"
"      topoCtx.fillStyle = isLight ? '#bae6fd' : '#0c4a6e';\n"
"      topoCtx.fill();\n"
"      topoCtx.strokeStyle = isLight ? '#0284c7' : '#38bdf8';\n"
"      topoCtx.lineWidth = 2; topoCtx.stroke();\n"
"      topoCtx.fillStyle = isLight ? '#0f172a' : '#e2e8f0';\n"
"      topoCtx.fillText('RX', a.x, a.y + r + 3);\n"
"      continue;\n"
"    }\n"
"    topoCtx.fillStyle = isH ? '#facc15' : (isLight ? '#0284c7' : '#38bdf8');\n"
"    topoCtx.fill();\n"
"    topoCtx.strokeStyle = isLight ? '#ffffff' : '#0f172a'; topoCtx.lineWidth = 1.2; topoCtx.stroke();\n"
"    if (isH) {\n"
"      const n = nodes[id];\n"
"      const label = (n && n.name) ? n.name : id;\n"
"      topoCtx.fillStyle = isLight ? '#1e293b' : '#e2e8f0';\n"
"      topoCtx.fillText(label, a.x, a.y + r + 3);\n"
"    }\n"
"  }\n"
"}\n"
"function topoLoop(now){\n"
"  if (!topoActive) { topoRafHandle = 0; return; }\n"
"  const dt = topoLastTick ? Math.min(0.05, (now - topoLastTick) / 1000) : 0.016;\n"
"  topoLastTick = now;\n"
"  topoTick(dt);\n"
"  topoRender();\n"
"  topoRafHandle = requestAnimationFrame(topoLoop);\n"
"}\n"
"function topoStart(){\n"
"  topoSize();\n"
"  topoActive = true; topoLastTick = 0;\n"
"  if (Object.keys(topoNodes).length === 0) topoEmpty.style.display = 'block';\n"
"  if (!topoRafHandle) topoRafHandle = requestAnimationFrame(topoLoop);\n"
"}\n"
"function topoStop(){ topoActive = false; }\n"
"window.addEventListener('resize', ()=>{ if (topoActive) topoSize(); });\n"
"topoCanvas.addEventListener('mousemove', e=>{\n"
"  const rect = topoCanvas.getBoundingClientRect();\n"
"  topoMouse.x = e.clientX - rect.left; topoMouse.y = e.clientY - rect.top;\n"
"  const hit = topoNodeAt(topoMouse.x, topoMouse.y);\n"
"  topoHover = hit;\n"
"  topoCanvas.classList.toggle('hovering', !!hit);\n"
"});\n"
"topoCanvas.addEventListener('mouseleave', ()=>{ topoHover = null; topoCanvas.classList.remove('hovering'); });\n"
"topoCanvas.addEventListener('click', ()=>{ if (topoHover && topoHover !== RX_STATION_ID) openDrawer(topoHover); });\n"
"// runs: 999 -> '999', 1234 -> '1.2k', 1234567 -> '1.2M', etc.\n"
"function fmtCount(n){if(n<1000)return String(n|0);if(n<1e6)return (n/1000).toFixed(n<10000?1:0)+'k';if(n<1e9)return (n/1e6).toFixed(n<10e6?1:0)+'M';return (n/1e9).toFixed(1)+'G';}\n"
"function setStat(id,v){const el=document.getElementById(id);if(el)el.textContent=v;}\n"
"const es = new EventSource('/events');\n"
"es.onopen=()=>{const s=document.getElementById('status');if(s){s.textContent='connected';s.style.color='';}};\n"
"es.onerror=()=>{const s=document.getElementById('status');if(s){s.textContent='disconnected';s.style.color='#f87171';}};\n"
"es.onmessage = (e) => {\n"
"  let p; try { p = JSON.parse(e.data); } catch(_){ return; }\n"
"  if (p.event === 'STATS') {\n"
"    setStat('st-msps', (typeof p.msps==='number')?p.msps.toFixed(2):'--');\n"
"    setStat('st-frames', fmtCount(p.frames||0));\n"
"    setStat('st-decrypted', fmtCount(p.decrypted||0));\n"
"    if (p.off_grid !== undefined) {\n"
"      document.getElementById('st-offgrid-wrap').style.display = '';\n"
"      setStat('st-offgrid', fmtCount(p.off_grid));\n"
"    }\n"
"    // Focus pool summary: hide entirely when --deep-decode=off so the\n"
"    // bar stays compact for users who haven't enabled it.\n"
"    if (p.focus_active === true) {\n"
"      const w = p.focus_workers||0;\n"
"      const prom = p.focus_promotions||0;\n"
"      const drop = p.focus_dropped||0;\n"
"      const below = p.focus_below_snr||0;\n"
"      const fr = p.focus_frames||0;\n"
"      document.getElementById('st-focus-wrap').style.display = '';\n"
"      // Compact: 'Nw / Pprom / Ddrop / Bsnr / Ffr' -- expand on hover via title.\n"
"      setStat('st-focus', `${w}w ${fmtCount(prom)}p ${fmtCount(drop)}d ${fmtCount(below)}s ${fmtCount(fr)}f`);\n"
"    }\n"
"    // Clock discipline class. Hidden until first STATS so we don't\n"
"    // flash 'NTP' on a station that hasn't reported yet.\n"
"    if (p.clock) {\n"
"      document.getElementById('st-clock-wrap').style.display = '';\n"
"      const accNs = p.clock_acc_ns;\n"
"      let accLabel = '';\n"
"      if (typeof accNs === 'number') {\n"
"        if (accNs >= 1e6) accLabel = ` (${(accNs/1e6).toFixed(0)} ms)`;\n"
"        else if (accNs >= 1e3) accLabel = ` (${(accNs/1e3).toFixed(0)} us)`;\n"
"        else accLabel = ` (${accNs} ns)`;\n"
"      }\n"
"      setStat('st-clock', p.clock + accLabel);\n"
"    }\n"
"    return;\n"
"  }\n"
"  if (p.event === 'CHAN_SNR') {\n"
/* Per-slot SNR sparkline updates. Each entry is {id, snr:[60 ints,
 * -1 for empty bucket, otherwise rounded dB]}. Store keyed by slot id;
 * renderChannels() aggregates across the slots that share a channel
 * hash because the Channels table groups by hash. */
"    if (Array.isArray(p.channels)) {\n"
"      for (const c of p.channels) chanSnr[c.id] = c.snr;\n"
"      refreshChannels();\n"
"    }\n"
"    return;\n"
"  }\n"
/* MC_CHANNEL_DISCOVERED -- the background hashtag dictionary attack
 * (meshcore_hashtag_dict.c) cracked a channel that was previously seen
 * only as encrypted. MC_CHANNEL_ADDED -- the same situation but for a
 * channel manually added via /api/meshcore-channel (Config tab form or
 * the Channels-tab hashtag button): the add itself is a plain POST
 * response to whoever submitted it, not a broadcast, so every
 * connected client (including the one that just submitted it) needs
 * this event to learn the hash<->name mapping. Without either handler
 * the Channels tab has no way to learn about it until (if ever)
 * another frame happens to arrive on that exact channel_hash -- neither
 * a crack nor a manual add generates a regular packet event on its own. */
"  if (p.event === 'MC_CHANNEL_DISCOVERED' || p.event === 'MC_CHANNEL_ADDED') {\n"
"    const h = p.channel_hash;\n"
"    if (h !== undefined) {\n"
"      const key = chanKey(h, p.channel_name);\n"
"      if (!channels[key]) channels[key] = {total:0, decrypted:0, ts:Date.now()/1000, slots:new Set()};\n"
"      channels[key].name = p.channel_name;\n"
/* A channel added/cracked after some of its traffic was already
 * captured gets its historical rows retroactively re-decrypted
 * server-side (meshcore_redecrypt.c) -- but this browser's in-memory
 * message cache for the channel (c._msgs, populated by live SSE
 * delivery -- including the on-restart replay of what were, at that
 * time, still-encrypted rows) has no way to know that happened, and
 * nothing else invalidates it. Without this, the Messages pane keeps
 * showing stale "(encrypted)" placeholders until the operator happens
 * to click "load older", which bypasses the cache and re-fetches
 * from /api/messages (now correct) -- confusing since the fix looks
 * like it silently failed. Drop the cache and, if this channel is
 * currently open, immediately re-pull it the same way that button
 * does. */
"      delete channels[h]._msgs;\n"
"      delete channels[h]._older;\n"
"      delete channels[h]._olderDone;\n"
"      refreshChannels();\n"
"      refreshChannelsTab();\n"
"      if (selectedChannelHash === h) { renderChannelMessages(); loadOlderMessages(); }\n"
"    }\n"
"    return;\n"
"  }\n"
"  if (p.event === 'OFF_GRID_LORA') {\n"
"    // Promote button: POSTs to /api/extra-freq to add a real decoder\n"
"    // slot at the discovered frequency. BW guess uses the scanner's\n"
"    // estimate clamped to a known LoRa BW (62.5 / 125 / 250 / 500 kHz).\n"
"    const bwGuess = p.bw_estimate_hz >= 400000 ? 500000\n"
"                  : p.bw_estimate_hz >= 200000 ? 250000\n"
"                  : p.bw_estimate_hz >= 100000 ? 125000 : 62500;\n"
"    const sf = 11; const cr = 5; // sensible defaults; user can override later\n"
"    const promoteBtn = `<button class=promote data-f=\"${p.f_hz}\" data-bw=\"${bwGuess}\" data-sf=\"${sf}\" data-cr=\"${cr}\">promote</button>`;\n"
"    pushTo(discEl, `<span class=disc>off-grid: ${(p.f_hz/1e6).toFixed(3)} MHz, SNR ${p.snr_db.toFixed(1)} dB, ~${(bwGuess/1000).toFixed(0)} kHz</span> ${promoteBtn}`, p.ts);\n"
"    return;\n"
"  }\n"
"  // Debug tab: log every frame (either protocol) with its raw over-the-\n"
"  // air bytes, unconditionally -- ahead of the trust/showUntrusted\n"
"  // filtering and the '!p.from' node-identity gate below, since the\n"
"  // whole point is to see frames those views intentionally hide or drop\n"
"  // (CRC failures, MeshCore ACK/TRACE/PATH with no derivable sender id,\n"
"  // etc).\n"
"  if (p.raw_hex) noteAnalyzerFrame(p);\n"
"  // Station-self marker on the live map (when --gpsd is running).\n"
"  if (p.station_lat !== undefined && p.station_lon !== undefined) {\n"
"    noteStation(p.station_lat, p.station_lon, p.station_alt_m);\n"
"  }\n"
"  // CRC-failed frames are corrupt -- their 'from'/'to' fields are\n"
"  // bit-flipped versions of real node IDs. Including them in the\n"
"  // topology / nodes table populates phantom nodes that don't exist.\n"
"  // The raw event still goes to the SSE stream so an operator can\n"
"  // see them in JSON for debugging, but the aggregate views default\n"
"  // to dropping them.\n"
"  //\n"
"  // fields_trusted is the explicit boolean from feed.c: true when\n"
"  // either the LoRa CRC passed or the AES payload parsed cleanly.\n"
"  // false catches both CRC-fail (bit-corrupted bytes) AND no-CRC\n"
"  // frames whose payload didn't decrypt (could be a real frame on\n"
"  // an unknown channel PSK, could be a noise pattern that survived\n"
"  // the 5-bit header checksum -- can't tell, so by default don't\n"
"  // surface as a sighting). Toggle via #showUntrusted checkbox in\n"
"  // the Config tab to include them in aggregates for diagnostic use.\n"
"  const untrusted = (p.fields_trusted === false) ||\n"
"                    (p.payload_crc_ok === false);\n"
"  const showUntrusted = document.getElementById('showUntrusted');\n"
"  if (untrusted && !(showUntrusted && showUntrusted.checked)) return;\n"
"  // Topology heard-edge: every frame this station decodes (encrypted\n"
"  // or not) draws a faint pseudo-edge from the source node to the\n"
"  // synthetic RX station, colored by SNR. Useful when there's no\n"
"  // NEIGHBORINFO_APP traffic to mine real mesh-edge info from.\n"
"  topoNoteHeard(p.from, p.snr_db);\n"
"  if (p.to) topoNoteAddressed(p.from, p.to);\n"
"  // Real relay-tree edges: unlike the heard-pseudo-edge above (which\n"
"  // just connects the packet's nominal sender straight to us, ignoring\n"
"  // any relaying), route_path_hex is the packet's ACTUAL hop-by-hop\n"
"  // repeater trail. Runs for every event carrying a path -- including\n"
"  // envelope-only REQ/RESPONSE/PATH/TXT_MSG, which have no resolvable\n"
"  // 'from' of their own but still traversed real repeaters. See\n"
"  // topoNoteRelayPath() below.\n"
"  topoNoteRelayPath(p);\n"
/* Live map: flash the same relay path across the Leaflet map itself
 * (traceLivePath(), defined above near placeMarker/blinkRepeater) --
 * a colored line by frame type plus a 10s green blink on every
 * resolved repeater hop. Independent of topoNoteRelayPath() above
 * (that's the Topology tab's force-directed graph, a different view). */
"  traceLivePath(p);\n"
"  // Per-channel stats: bucket by channel_hash so unknown networks are visible too.\n"
"  if (p.channel_hash !== undefined){\n"
"    const h = chanKey(p.channel_hash, p.channel_name);\n"
"    if (!channels[h]) channels[h] = {total:0, decrypted:0, ts:0, slots:new Set()};\n"
"    const c = channels[h]; c.total++; c.ts = p.ts;\n"
"    if (p.channel_name) c.name = p.channel_name;\n"
"    if (p.preset) c.preset = p.preset;\n"
"    if (p.protocol) c.protocol = p.protocol;\n"
"    if (p.slot_id !== undefined && p.slot_id !== null && p.slot_id >= 0) { if (!c.slots) c.slots = new Set(); c.slots.add(p.slot_id); c.lastSlot = p.slot_id; }\n"
"    // 'decrypted' is only emitted when false for Meshtastic (presence of\n"
"    // port_name/portnum implies success there); MeshCore always emits an\n"
"    // explicit boolean, so trust that directly instead of the (absent)\n"
"    // port_name check, which would otherwise read every MeshCore frame\n"
"    // -- including successfully-decrypted GRP_TXT/GRP_DATA/ADVERT ones --\n"
"    // as undecrypted.\n"
"    const wasDecrypted = p.protocol === 'meshcore' ? p.decrypted === true : (p.decrypted !== false && p.port_name);\n"
"    if (wasDecrypted) c.decrypted++;\n"
"    refreshChannels();\n"
"    refreshChannelsTab();\n"
"  }\n"
"  // Everything above (station marker, untrusted filter, topology heard-\n"
"  // edge, Channels pane) works from channel_hash/protocol\n"
"  // alone and needs no node identity. Frame types with no derivable\n"
"  // 'from' (MeshCore ACK/TRACE/PATH/REQ/RESPONSE/CONTROL -- see\n"
"  // mc_derive_from_id() in feed_meshcore_json.c) still light up those\n"
"  // views; only the node list / map / message log below need an id.\n"
"  if (!p.from) return;\n"
"  const id = p.from;\n"
"  // MeshCore GRP_TXT/GRP_DATA (id tagged !8000xxxx = 0x80000000|channel_hash)\n"
"  // and REQ/RESPONSE/PATH/TXT_MSG with only a dest/src hash visible (id\n"
"  // tagged !4000xxxx, see mc_node_id() in db_sqlite.c / mc_derive_from_id()\n"
"  // in feed_meshcore_json.c) aren't a real device -- they're a synthetic\n"
"  // grouping key so the same node_id field/column can carry a\n"
"  // best-effort identity for messages with no real sender. Still tracked\n"
"  // in `nodes` (message log below needs n.name/n.frames), just flagged so\n"
"  // the Nodes table/CSV export can exclude the phantom entries.\n"
"  const isSyntheticId = /^!(4000|8000)/i.test(id);\n"
"  if (!nodes[id]) nodes[id] = {ts:0, frames:0, synthetic:isSyntheticId};\n"
"  const n = nodes[id]; n.ts = p.ts; n.frames = (n.frames||0) + 1;\n"
"  if (p.snr_db !== undefined) n.snr_db = p.snr_db;\n"
"  if (p.decrypted === false) n.has_encrypted = true;\n"
"  if (p.long_name) n.name = p.long_name + (p.short_name ? ' ['+p.short_name+']' : '');\n"
"  else if (p.atak_callsign) n.name = p.atak_callsign + ' ['+p.atak_team+']';\n"
"  // adv_type_name (CHAT/REPEATER/ROOM/SENSOR) drives the repeater-tree\n"
"  // node shape in the Topology tab -- see topoRender().\n"
"  if (p.adv_type_name) {\n"
"    n.adv_type = p.adv_type_name;\n"
/* Repeater status just became known (or changed): restyle an
 * already-existing marker right away using its current position,
 * rather than only reacting inside the p.lat/p.lon block below --
 * that block only runs when THIS frame also carries a fresh position,
 * but many repeaters don't re-broadcast position on every ADVERT (or
 * the marker was placed earlier by bootstrapNodesFromApi(), whose
 * /api/nodes data has no adv_type at all). Without this, a repeater
 * discovered before this ADVERT keeps showing the default pin
 * indefinitely, until/unless a later frame happens to carry both
 * fields together. */
"    if (markers[id] && markers[id].getLatLng) placeMarker(id, markers[id].getLatLng(), n);\n"
"  }\n"
"  if (p.lat !== undefined && p.lon !== undefined) {\n"
"    const ll = [p.lat, p.lon];\n"
"    placeMarker(id, ll, n);\n"
"    updateTrail(id, ll);\n"
"    if (Object.keys(markers).length === 1) map.setView(ll, 10);\n"
"  }\n"
"  // Relay-hop hint: header.relay_node is the upper byte of the relayer's node id.\n"
"  // Useful enough to draw an approximate edge between any two known nodes whose\n"
"  // ids share that upper byte and are both positioned.\n"
"  // (Real edges come from NEIGHBORINFO_APP packets.)\n"
"  if (p.neighbors && Array.isArray(p.neighbors)){\n"
"    for (const nb of p.neighbors) {\n"
"      noteEdge(id, nb.id, nb.snr_db);\n"
"      topoNoteEdge(id, nb.id, nb.snr_db);\n"
"    }\n"
"  }\n"
"  // Relay-hop hint: try to resolve the upper byte to a known node and add\n"
"  // a topology edge between this node and the relayer. The map-side noteEdge\n"
"  // requires both to be positioned; the topology graph doesn't.\n"
"  if (p.relay_node !== undefined && p.relay_node !== null) {\n"
"    const relayByte = p.relay_node & 0xff;\n"
"    for (const candId of Object.keys(nodes)) {\n"
"      if (candId === id) continue;\n"
"      const numId = parseInt(candId.replace(/^!/,''), 16);\n"
"      if (((numId >> 24) & 0xff) === relayByte) topoNoteEdge(id, candId);\n"
"    }\n"
"  }\n"
"  if (Math.random() < 0.05) topoPrune();\n"
"  // Slot ids 1019..1023 are focused-pool / manual-focus workers (see\n"
"  // CHANNELIZER_MAX_CHANNELS in channelizer.h); flag those so the\n"
"  // operator can tell which frames the deep-decode path delivered.\n"
"  const focusedBadge = (typeof p.slot_id === 'number' && p.slot_id >= 1019)\n"
"    ? '<span class=muted style=\"color:#38bdf8\">[focused]</span> ' : '';\n"
"  const summary = msgSummary(p);\n"
"  if (summary) pushTo(msgsEl, `${focusedBadge}<b>${msgFromLabel(p,n,id)}</b> <span class=muted>${p.channel_name||''}</span> <span class=port>${p.port_name||''}</span>: ${summary}`, p.ts);\n"
"  if (p.channel_hash !== undefined) { noteChannelMessage(chanKey(p.channel_hash, p.channel_name), p, summary); refreshChannelsTab(); }\n"
"  if (p.atak_callsign) pushTo(discEl, `<span class=atak>ATAK ${p.atak_callsign} (${p.atak_team}/${p.atak_role})${p.atak_chat?' chat: '+p.atak_chat:''}</span>`, p.ts);\n"
"  noteNodeFrame(id, p);\n"
"  evictNodes();\n"
"  refreshNodes();\n"
"};\n"
"async function postBody(path, body){\n"
"  const r = await fetch(path, {method:'POST', body});\n"
"  return r.ok ? await r.json() : {error:'HTTP '+r.status};\n"
"}\n"
"function setStatus(id, txt, ok){const el=document.getElementById(id); el.textContent=txt; el.className='hint '+(ok?'status-ok':'status-err');}\n"
/* Persistent MeshCore channel list -- the sniffer itself never
 * persists added channels to disk (meshcore_channelset_t is in-memory
 * only), so localStorage is the only durable record across restarts.
 * the restore loop (below, run once at page load) re-POSTs every
 * saved entry so a restarted sniffer gets its channels back without
 * the user re-entering anything; add_channel_locked() (meshcore.c)
 * upserts by name so this is safe to repeat on every page load. */
"function loadMcChannels(){\n"
"  try { return JSON.parse(localStorage.getItem('mc_channels')) || []; } catch(e) { return []; }\n"
"}\n"
"function saveMcChannels(list){\n"
"  try { localStorage.setItem('mc_channels', JSON.stringify(list)); } catch(e) {}\n"
"}\n"
"function addMcChannelLocal(name, secret){\n"
"  const list = loadMcChannels();\n"
"  const i = list.findIndex(c => c.name === name);\n"
"  const entry = {name, secret: secret || null};\n"
"  if (i >= 0) list[i] = entry; else list.push(entry);\n"
"  saveMcChannels(list);\n"
"  renderMcChannelsList();\n"
"}\n"
"function removeMcChannelLocal(name){\n"
"  saveMcChannels(loadMcChannels().filter(c => c.name !== name));\n"
"  renderMcChannelsList();\n"
"}\n"
"function renderMcChannelsList(){\n"
"  const el = document.getElementById('mc-channel-list');\n"
"  if (!el) return;\n"
"  const list = loadMcChannels();\n"
"  if (!list.length) { el.innerHTML = '<div class=muted>no channels added yet</div>'; return; }\n"
"  el.innerHTML = list.map(c => `<div class=item>${escHtml(c.name)} <span class=muted>${c.secret ? 'keyed' : 'hashtag'}</span> <button class=\"btn-mini mc-remove\" data-name=\"${escHtml(c.name)}\">Remove</button></div>`).join('');\n"
"}\n"
"document.getElementById('mc-channel-list').addEventListener('click', (e) => {\n"
"  const btn = e.target.closest('button.mc-remove');\n"
"  if (!btn) return;\n"
"  removeMcChannelLocal(btn.dataset.name);\n"
"});\n"
"async function postMeshcoreChannel(){\n"
"  const body = document.getElementById('mc-channel-input').value.replace(/\\n/g,',');\n"
"  const r = await postBody('/api/meshcore-channel', body);\n"
"  if (r.error) setStatus('mc-channel-status', r.error, false);\n"
"  else {\n"
"    setStatus('mc-channel-status', 'added '+r.added+' channel(s)', true);\n"
"    for (const tok of body.split(/[,;]/)){\n"
"      const t = tok.trim(); if (!t) continue;\n"
"      const ci = t.indexOf(':');\n"
"      if (ci < 0) addMcChannelLocal(t, null); else addMcChannelLocal(t.slice(0, ci), t.slice(ci+1));\n"
"    }\n"
"    document.getElementById('mc-channel-input').value='';\n"
"  }\n"
"}\n"
/* addHashtagChannel -- Channels-tab control to add a channel by name
 * only, no key. Posts a bare name (no colon) to the same endpoint
 * postMeshcoreChannel() uses -- meshcore_channelset_add_hashtag()
 * derives a real, working secret from the name alone (see meshcore.c),
 * so this isn't a placeholder, it's a fully functional channel. */
"async function addHashtagChannel(){\n"
"  const input = document.getElementById('chantab-hashtag-input');\n"
"  const btn = document.getElementById('chantab-hashtag-btn');\n"
"  const name = input.value.trim();\n"
"  if (!name) { setStatus('chantab-hashtag-status', 'enter a channel name first', false); input.focus(); return; }\n"
"  btn.disabled = true;\n"
"  try {\n"
"    const r = await postBody('/api/meshcore-channel', name);\n"
"    if (r.error) setStatus('chantab-hashtag-status', r.error, false);\n"
"    else {\n"
"      setStatus('chantab-hashtag-status', 'added', true);\n"
"      addMcChannelLocal(name, null);\n"
"      input.value = '';\n"
"    }\n"
"  } finally { btn.disabled = false; }\n"
"}\n"
"document.getElementById('chantab-hashtag-input').addEventListener('keydown', (e) => {\n"
"  if (e.key === 'Enter') addHashtagChannel();\n"
"});\n"
/* One-time restore of every locally-remembered channel on page load
 * (see the comment above loadMcChannels()). Runs after the DOM consts
 * above are defined (renderMcChannelsList/postBody), same as the
 * theme-init IIFE elsewhere in this script. */
"renderMcChannelsList();\n"
"for (const c of loadMcChannels()) postBody('/api/meshcore-channel', c.secret ? `${c.name}:${c.secret}` : c.name);\n"
/* bootstrapNodesFromApi -- dashboard bootstrap-on-load counterpart to
 * the localStorage channel restore above, but for nodes: node_db and
 * the `nodes`/`markers` objects here are both live-traffic-only in
 * memory, so a browser tab opened right after a sniffer restart would
 * otherwise show nothing until every node happens to re-transmit.
 * GET /api/nodes reads straight from the `nodes` and `events` SQL
 * tables (see db_sqlite_query_nodes_json/_positions_json) and seeds
 * the same `nodes{}`/`markers{}` shapes es.onmessage's packet handler
 * builds up (web.c, around `const id = p.from;`), so renderNodes(),
 * the CSV export, and topology labels all pick this up unchanged --
 * this function intentionally does NOT call into es.onmessage itself,
 * since that dispatcher has many live-only side effects (discovery
 * panel, relay-hop edges, etc.) that don't apply to bootstrap data. */
"async function bootstrapNodesFromApi(){\n"
"  try {\n"
"    const r = await fetch('/api/nodes');\n"
"    if (!r.ok) return;\n"
"    const data = await r.json();\n"
"    for (const n of (data.nodes||[])) {\n"
"      const id = n.id;\n"
"      if (!nodes[id]) nodes[id] = {ts:0, frames:0, synthetic:/^!(4000|8000)/i.test(id)};\n"
"      if (n.long_name) nodes[id].name = n.long_name + (n.short_name ? ' ['+n.short_name+']' : '');\n"
"      if (n.last_seen && n.last_seen > nodes[id].ts) nodes[id].ts = n.last_seen;\n"
/* n.role: only meaningful for MeshCore nodes (see the persist-time
 * comment in feed_meshcore_json.c), same small enum as the live
 * ADVERT event's adv_type_name -- decode it the same way so a
 * bootstrapped repeater gets its red-circle marker (placeMarker(),
 * driven by nodes[id].adv_type) immediately on page load, not only
 * after it happens to send another live ADVERT. */
"      if (typeof n.role === 'number' && MC_ADV_TYPE_NAMES[n.role]) nodes[id].adv_type = MC_ADV_TYPE_NAMES[n.role];\n"
"    }\n"
"    const addedLatLngs = [];\n"
"    for (const p of (data.positions||[])) {\n"
"      const id = p.node_id;\n"
"      if (!nodes[id]) nodes[id] = {ts:0, frames:0, synthetic:/^!(4000|8000)/i.test(id)};\n"
"      if (p.ts && p.ts > nodes[id].ts) nodes[id].ts = p.ts;\n"
"      if (!markers[id]) {\n"
"        const ll = [p.lat, p.lon];\n"
"        placeMarker(id, ll, nodes[id]);\n"
"        addedLatLngs.push(ll);\n"
"      }\n"
"    }\n"
"    if (addedLatLngs.length) map.fitBounds(addedLatLngs, {maxZoom:10});\n"
"    refreshNodes();\n"
"  } catch(e) {}\n"
"}\n"
"bootstrapNodesFromApi();\n"
/* bootstrapChannelsFromApi -- Channels-tab counterpart to
 * bootstrapNodesFromApi() above: `channels{}` is likewise live-traffic-
 * only in memory, built up only from SSE packet/CHAN_SNR/discovery
 * events, so a plain browser refresh (no sniffer restart needed) loses
 * every channel_hash->name mapping already learned -- including ones
 * the background hashtag-dictionary attack cracked long ago -- until
 * fresh traffic happens to arrive on that exact channel again. GET
 * /api/meshcore-channels reads the durable hash->name mapping straight
 * out of the events table (see db_sqlite_query_channel_names_json()),
 * now including a real total/decrypted/last_ts/protocol from the DB's
 * full history, and seeds `channels{}` the same shape the live
 * handlers build, so renderChannelsTab() shows known names AND
 * accurate counts immediately on load.
 *
 * Only fills in a channel that has no in-memory entry yet -- one that
 * already has live/replayed traffic this session keeps its own
 * bookkeeping rather than being overwritten by a possibly-stale
 * snapshot from whenever this fetch resolves. Before this, a fresh
 * entry got hardcoded total:0/ts:0 stand-ins with no protocol at all,
 * which rendered as "0 messages", a decades-long "ago" (fmtAgo epoch
 * 0), and a bare "--" for protocol -- despite the channel having real
 * history, reachable by clicking it (which pulls messages straight
 * from the DB via loadOlderMessages(), unaffected by this stand-in). */
"async function bootstrapChannelsFromApi(){\n"
"  try {\n"
"    const r = await fetch('/api/meshcore-channels');\n"
"    if (!r.ok) return;\n"
"    const data = await r.json();\n"
"    for (const c of (data.channels||[])) {\n"
"      const h = c.channel_hash;\n"
"      if (h === undefined || h === null) continue;\n"
/* /api/meshcore-channels now returns one row per distinct (hash,name)
 * pair (see db_sqlite_query_channel_names_json()'s fix), so this
 * naturally seeds a separate bucket per colliding channel instead of
 * merging them under one hash. */
"      const key = chanKey(h, c.channel_name);\n"
"      if (!channels[key]) {\n"
"        channels[key] = {\n"
"          total: c.total || 0, decrypted: c.decrypted || 0,\n"
"          ts: c.last_ts || 0, protocol: c.protocol || 'meshcore',\n"
"          slots: new Set(),\n"
"        };\n"
"      }\n"
"      if (c.channel_name) channels[key].name = c.channel_name;\n"
"    }\n"
"    refreshChannels();\n"
"    refreshChannelsTab();\n"
"  } catch(e) {}\n"
"}\n"
"bootstrapChannelsFromApi();\n"
/* Statistics tab: hand-rolled SVG donuts (stroke-dasharray technique on
 * concentric <circle> elements) + a 100%-stacked CRC bar. No charting
 * library exists anywhere in this dashboard (only Leaflet, for the
 * map) -- matches that convention.
 *
 * Message type is a small closed vocabulary (mc_payload_type_name() in
 * meshcore.c) -- a fixed name->color map keeps colors stable across
 * every window switch/refetch. Channels are an open, unbounded universe
 * (76+ observed in real captures), so the channel donut recolors by
 * rank on every fetch instead: simpler, and always accurate to
 * whichever window is currently selected, at the cost of a channel's
 * color/legend slot being able to shift when the window changes -- a
 * deliberate tradeoff (a window switch is "show different data", not
 * an incremental live update). Both palettes are the dataviz skill's
 * validated 8-hue categorical set, already checked against this
 * dashboard's actual light/dark surfaces. */
"const STATS_CATEGORICAL_DARK  = ['#3987e5','#d95926','#199e70','#c98500','#d55181','#008300','#9085e9','#e66767'];\n"
"const STATS_CATEGORICAL_LIGHT = ['#2a78d6','#eb6834','#1baf7a','#eda100','#e87ba4','#008300','#4a3aa7','#e34948'];\n"
"const STATS_OTHER_COLOR = '#64748b';\n"
"const STATS_TYPE_COLORS_DARK = {GRP_TXT:'#3987e5',ADVERT:'#d95926',TRACE:'#199e70',ACK:'#c98500',TXT_MSG:'#d55181',REQ:'#008300',RESPONSE:'#9085e9',PATH:'#e66767'};\n"
"const STATS_TYPE_COLORS_LIGHT = {GRP_TXT:'#2a78d6',ADVERT:'#eb6834',TRACE:'#1baf7a',ACK:'#eda100',TXT_MSG:'#e87ba4',REQ:'#008300',RESPONSE:'#4a3aa7',PATH:'#e34948'};\n"
"function statsIsLight(){ return document.documentElement.classList.contains('light'); }\n"
"function statsCategorical(){ return statsIsLight() ? STATS_CATEGORICAL_LIGHT : STATS_CATEGORICAL_DARK; }\n"
"function statsTypeColor(label){ const m = statsIsLight() ? STATS_TYPE_COLORS_LIGHT : STATS_TYPE_COLORS_DARK; return m[label] || STATS_OTHER_COLOR; }\n"
"function statsChannelLabel(row){ return row.label || row.channel_name || ('0x'+(row.channel_hash&0xff).toString(16).padStart(2,'0')); }\n"
/* renderDonut -- data is already top-7-plus-Other-folded by the C
 * layer: [{label,count},...]. colorFn(entry,index) picks a color for
 * every entry except the literal "Other" row, which always renders in
 * the fixed neutral gray so it never impersonates a real category.
 * Segments are plain <circle> elements (not <canvas>) so each one is a
 * real DOM node -- a <title> child gives every segment a native
 * hover/focus tooltip with zero pointer-tracking code, matching this
 * dashboard's existing level of interaction investment (nothing else
 * here, including the Topology tab's hand-rolled canvas graph, has a
 * custom tooltip layer either). Direct percentage labels are drawn on
 * the largest slices only (top 4, skipping any sliver under ~6%). */
"function renderDonut(containerEl, legendEl, tableEl, data, colorFn){\n"
"  containerEl.innerHTML = '';\n"
"  legendEl.innerHTML = '';\n"
"  if (tableEl) tableEl.querySelector('tbody').replaceChildren();\n"
"  const total = data.reduce((s,d)=>s+d.count,0);\n"
"  if (!total) { containerEl.innerHTML = '<div class=muted style=\"padding:20px 4px\">No data in this window</div>'; return; }\n"
"  const r = 50, cx = 60, cy = 60, sw = 18;\n"
"  const circumference = 2 * Math.PI * r;\n"
"  const svg = document.createElementNS('http://www.w3.org/2000/svg','svg');\n"
"  svg.setAttribute('viewBox','0 0 120 120');\n"
"  svg.setAttribute('width','140');\n"
"  svg.setAttribute('height','140');\n"
"  const g = document.createElementNS('http://www.w3.org/2000/svg','g');\n"
"  g.setAttribute('transform','rotate(-90 60 60)');\n"
"  svg.appendChild(g);\n"
"  let offset = 0;\n"
"  const directLabels = [];\n"
"  data.forEach((d,i)=>{\n"
"    const frac = d.count/total;\n"
"    const len = frac * circumference;\n"
"    const gap = data.length > 1 ? 2 : 0;\n"
"    const color = (d.label === 'Other') ? STATS_OTHER_COLOR : colorFn(d, i);\n"
"    const circle = document.createElementNS('http://www.w3.org/2000/svg','circle');\n"
"    circle.setAttribute('cx',cx); circle.setAttribute('cy',cy); circle.setAttribute('r',r);\n"
"    circle.setAttribute('fill','none');\n"
"    circle.setAttribute('stroke',color);\n"
"    circle.setAttribute('stroke-width',sw);\n"
"    circle.setAttribute('stroke-dasharray', Math.max(len-gap,0)+' '+(circumference-Math.max(len-gap,0)));\n"
"    circle.setAttribute('stroke-dashoffset', -offset);\n"
"    circle.setAttribute('tabindex','0');\n"
"    const pct = (frac*100).toFixed(1);\n"
"    const title = document.createElementNS('http://www.w3.org/2000/svg','title');\n"
"    title.textContent = d.label+': '+d.count+' ('+pct+'%)';\n"
"    circle.appendChild(title);\n"
"    g.appendChild(circle);\n"
"    const midFrac = (offset + len/2) / circumference;\n"
"    offset += len;\n"
"    if (i < 4 && frac > 0.06) {\n"
"      const rad = (-90 + midFrac*360) * Math.PI/180;\n"
"      const text = document.createElementNS('http://www.w3.org/2000/svg','text');\n"
"      text.setAttribute('x', cx + Math.cos(rad)*r);\n"
"      text.setAttribute('y', cy + Math.sin(rad)*r);\n"
"      text.setAttribute('text-anchor','middle');\n"
"      text.setAttribute('dominant-baseline','middle');\n"
"      text.setAttribute('font-size','9');\n"
"      text.setAttribute('fill','#fff');\n"
"      text.textContent = pct+'%';\n"
"      directLabels.push(text);\n"
"    }\n"
"    const row = document.createElement('div');\n"
"    row.innerHTML = '<span class=sw style=\"background:'+color+'\"></span>'+escHtml(d.label)+'<span class=cnt>'+d.count+' ('+pct+'%)</span>';\n"
"    legendEl.appendChild(row);\n"
"    if (tableEl) {\n"
"      const tr = document.createElement('tr');\n"
"      tr.innerHTML = '<td>'+escHtml(d.label)+'</td><td>'+d.count+'</td><td>'+pct+'%</td>';\n"
"      tableEl.querySelector('tbody').appendChild(tr);\n"
"    }\n"
"  });\n"
"  directLabels.forEach(t=>svg.appendChild(t));\n"
"  containerEl.appendChild(svg);\n"
"}\n"
/* renderCrcBar -- CRC state is a status (good/warning/critical)
 * semantic, not identity, so it deliberately reuses this dashboard's
 * EXISTING .crc-badge colors rather than the categorical palette
 * (status and categorical must never share a role -- see the dataviz
 * skill's collision rule). Three direct-labeled values already satisfy
 * the accessibility bar, so no table-view toggle here (unlike the
 * two donuts, which fold to opaque-color slices). */
"function renderCrcBar(barEl, legendEl, crc){\n"
"  barEl.innerHTML = '';\n"
"  legendEl.innerHTML = '';\n"
"  const total = (crc.ok||0) + (crc.corrected||0) + (crc.failed||0);\n"
"  if (!total) { legendEl.innerHTML = '<div class=muted>No CRC-bearing frames in this window</div>'; return; }\n"
"  const parts = [\n"
"    {label:'OK', count:crc.ok||0, color:'#064e3b', text:'#6ee7b7'},\n"
"    {label:'Corrected', count:crc.corrected||0, color:'#78350f', text:'#fcd34d'},\n"
"    {label:'Failed', count:crc.failed||0, color:'#450a0a', text:'#fca5a5'},\n"
"  ];\n"
"  parts.forEach(p=>{\n"
"    const pct = (p.count/total*100);\n"
"    if (p.count > 0) {\n"
"      const seg = document.createElement('div');\n"
"      seg.style.flexBasis = pct+'%';\n"
"      seg.style.background = p.color;\n"
"      seg.title = p.label+': '+p.count+' ('+pct.toFixed(1)+'%)';\n"
"      barEl.appendChild(seg);\n"
"    }\n"
"    const row = document.createElement('div');\n"
"    row.innerHTML = '<span class=sw style=\"background:'+p.color+'\"></span>'+p.label+'<span class=cnt>'+p.count+' ('+pct.toFixed(1)+'%)</span>';\n"
"    legendEl.appendChild(row);\n"
"  });\n"
"}\n"
"let statsWindow = '24h';\n"
"async function fetchStats(){\n"
"  const emptyEl = document.getElementById('stats-empty');\n"
"  const chartsEl = document.getElementById('stats-charts');\n"
"  try {\n"
"    const r = await fetch('/api/stats?window='+statsWindow);\n"
"    if (!r.ok) { chartsEl.style.display = 'none'; emptyEl.style.display = 'block'; return; }\n"
"    chartsEl.style.display = 'flex';\n"
"    emptyEl.style.display = 'none';\n"
"    const d = await r.json();\n"
"    renderDonut(\n"
"      document.getElementById('stats-donut-type'), document.getElementById('stats-legend-type'),\n"
"      document.getElementById('stats-table-type'),\n"
"      (d.by_type||[]).map(row=>({label:row.label, count:row.count})),\n"
"      (row)=>statsTypeColor(row.label)\n"
"    );\n"
"    renderDonut(\n"
"      document.getElementById('stats-donut-channel'), document.getElementById('stats-legend-channel'),\n"
"      document.getElementById('stats-table-channel'),\n"
"      (d.by_channel||[]).map(row=>({label:statsChannelLabel(row), count:row.count})),\n"
"      (row,i)=>statsCategorical()[i] || STATS_OTHER_COLOR\n"
"    );\n"
"    renderCrcBar(document.getElementById('stats-crcbar'), document.getElementById('stats-legend-crc'), d.crc||{});\n"
"  } catch(e) { chartsEl.style.display = 'none'; emptyEl.style.display = 'block'; }\n"
"}\n"
"document.querySelectorAll('.stats-window-btn').forEach(btn=>{\n"
"  btn.addEventListener('click', ()=>{\n"
"    document.querySelectorAll('.stats-window-btn').forEach(b=>b.classList.remove('active'));\n"
"    btn.classList.add('active');\n"
"    statsWindow = btn.dataset.window;\n"
"    fetchStats();\n"
"  });\n"
"});\n"
"document.querySelectorAll('.stats-table-toggle').forEach(btn=>{\n"
"  btn.addEventListener('click', ()=>{\n"
"    const target = document.getElementById('stats-table-'+btn.dataset.target);\n"
"    const showing = target.style.display !== 'none';\n"
"    target.style.display = showing ? 'none' : 'table';\n"
"    btn.textContent = showing ? 'View as table' : 'Hide table';\n"
"  });\n"
"});\n"
"</script></body></html>\n";

static int set_nonblock(int fd) {
    int f = fcntl(fd, F_GETFL, 0);
    return f < 0 ? -1 : fcntl(fd, F_SETFL, f | O_NONBLOCK);
}

static void send_all(int fd, const char *buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t r = send(fd, buf + sent, n - sent, MSG_NOSIGNAL);
        if (r <= 0) {
            if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            return;
        }
        sent += (size_t)r;
    }
}

static void serve_index(int fd) {
    char hdr[256];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Cache-Control: no-store\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n", sizeof(DASHBOARD_HTML) - 1);
    send_all(fd, hdr, (size_t)n);
    send_all(fd, DASHBOARD_HTML, sizeof(DASHBOARD_HTML) - 1);
    close(fd);
}

static void serve_404(int fd) {
    const char *r =
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Length: 9\r\nConnection: close\r\n\r\nnot found";
    send_all(fd, r, strlen(r));
    close(fd);
}

static void send_response(int fd, int code, const char *body)
{
    char hdr[256];
    size_t blen = body ? strlen(body) : 0;
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n\r\n",
        code, code == 200 ? "OK" : (code == 400 ? "Bad Request" : "Server Error"),
        blen);
    send_all(fd, hdr, (size_t)n);
    if (body) send_all(fd, body, blen);
    close(fd);
}

/* Find the body in an HTTP request that's already been recv'd. */
static const char *find_body(const char *buf)
{
    const char *p = strstr(buf, "\r\n\r\n");
    return p ? p + 4 : NULL;
}

/* Constant-time string compare for auth tokens. Returns 1 on match. */
static int ct_str_eq(const char *a, const char *b)
{
    if (!a || !b) return 0;
    size_t la = strlen(a), lb = strlen(b);
    /* Walk the longer of the two so a length mismatch doesn't short-circuit. */
    size_t n = la > lb ? la : lb;
    unsigned diff = (unsigned)la ^ (unsigned)lb;
    for (size_t i = 0; i < n; ++i) {
        unsigned ca = i < la ? (unsigned char)a[i] : 0;
        unsigned cb = i < lb ? (unsigned char)b[i] : 0;
        diff |= ca ^ cb;
    }
    return diff == 0;
}

/* Bearer-token auth check on POST /api endpoints.
 *
 * Returns 1 if the request is authorised (either no token is configured,
 * or the request carries the correct 'Authorization: Bearer SECRET' header).
 * On failure, sends a 401 response and returns 0; caller should `continue`.
 *
 * Header parsing is line-oriented: split on \r\n, find the line starting
 * with 'authorization:' (case-insensitive), then expect 'Bearer '. Tokens
 * with whitespace are unsupported.
 */
static int api_auth_ok(const char *buf, int fd)
{
    if (!opt_api_token) return 1; /* no auth configured -> allow */
    /* Search the request headers for an Authorization line. */
    const char *p = buf;
    const char *end = strstr(buf, "\r\n\r\n");
    if (!end) end = buf + strlen(buf);
    while (p < end) {
        const char *eol = strstr(p, "\r\n");
        if (!eol || eol >= end) break;
        /* Each header line: "Name: Value". Case-insensitive on the name. */
        if ((size_t)(eol - p) > 15 && !strncasecmp(p, "authorization:", 14)) {
            const char *v = p + 14;
            while (v < eol && (*v == ' ' || *v == '\t')) ++v;
            if ((size_t)(eol - v) > 7 && !strncasecmp(v, "Bearer ", 7)) {
                v += 7;
                while (v < eol && (*v == ' ' || *v == '\t')) ++v;
                size_t tlen = (size_t)(eol - v);
                char tok[256];
                if (tlen >= sizeof(tok)) tlen = sizeof(tok) - 1;
                memcpy(tok, v, tlen); tok[tlen] = 0;
                if (ct_str_eq(tok, opt_api_token)) return 1;
            }
        }
        p = eol + 2;
    }
    send_response(fd, 401,
        "{\"error\":\"missing or invalid Authorization: Bearer token\"}");
    return 0;
}

/* URL-decode in place. Returns new length. */
static size_t url_decode_inplace(char *s)
{
    char *r = s, *w = s;
    while (*r) {
        if (*r == '%' && r[1] && r[2]) {
            char h[3] = {r[1], r[2], 0};
            *w++ = (char)strtol(h, NULL, 16);
            r += 3;
        } else if (*r == '+') {
            *w++ = ' '; ++r;
        } else {
            *w++ = *r++;
        }
    }
    *w = 0;
    return (size_t)(w - s);
}

/* Tiny base64 lookup of one char, copied from keyset.c. */
static int b64v(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

/* meshtastic.org/e/ URLs are of the form:
 *   meshtastic.org/e/?#CgUYAyIBAQ           (single-channel base64-url)
 *   meshtastic.org/e/?#CHANNELSET=BASE64URL (also seen)
 * The base64-url payload is a protobuf ChannelSet { Channel channels = 1 }.
 *
 *   Channel { int32 index = 1; ChannelSettings settings = 2; Role role = 3; }
 *   ChannelSettings { uint32 channel_num = 1 [deprecated];
 *                     bytes psk = 2; string name = 3; ... }
 *
 * For each channel found, calls keyset_add(name, psk_bytes, psk_len).
 * Returns the number of channels added, or -1 on parse error. */
static int share_skip(const uint8_t **pp, const uint8_t *end, uint32_t wt)
{
    const uint8_t *p = *pp;
    if (wt == 0) {
        while (p < end && (*p++ & 0x80)) {}
    } else if (wt == 1) {
        if (end - p < 8) return -1;
        p += 8;
    } else if (wt == 2) {
        uint64_t l = 0; int sh = 0;
        while (p < end) {
            uint8_t b = *p++;
            l |= (uint64_t)(b & 0x7f) << sh;
            if (!(b & 0x80)) break;
            sh += 7;
        }
        if ((uint64_t)(end - p) < l) return -1;
        p += (size_t)l;
    } else if (wt == 5) {
        if (end - p < 4) return -1;
        p += 4;
    } else {
        return -1;
    }
    *pp = p;
    return 0;
}
/* Public wrapper so main.c can use the same decoder for --share-url. */
int web_decode_share_url(keyset_t *ks, const char *url) { extern int decode_channel_share(keyset_t *, const char *); return decode_channel_share(ks, url); }

int decode_channel_share(keyset_t *ks, const char *url_or_b64)
{
    if (!ks || !url_or_b64) return -1;
    /* Locate the base64 portion: after '#' or after '=' or whole string. */
    const char *p = url_or_b64;
    const char *hash = strchr(p, '#');
    if (hash) p = hash + 1;
    const char *eq = strchr(p, '=');
    if (eq) p = eq + 1;

    /* base64-url decode (with no required padding) */
    uint8_t buf[256]; size_t out = 0;
    uint32_t accum = 0; int bits = 0;
    for (; *p && out < sizeof(buf); ++p) {
        if (*p == '=' || *p == '&' || *p == ' ' || *p == '\r' || *p == '\n') break;
        int v = b64v(*p);
        if (v < 0) return -1;
        accum = (accum << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            buf[out++] = (uint8_t)((accum >> bits) & 0xff);
        }
    }
    if (out == 0) return -1;

    /* Parse ChannelSet protobuf:
     *   field 1: repeated Channel { settings (1) { psk (1, bytes), name (2, string), ... } }
     *   field 1 alt: also some firmware emits Channel directly.
     * Walk top-level fields; for each length-delimited field 1, parse
     * inner Channel; for inner field 1, parse Settings; pull psk + name. */
    int added = 0;
    const uint8_t *bp = buf, *bend = buf + out;
    while (bp < bend) {
        /* read tag */
        uint64_t tag = 0; int shift = 0;
        while (bp < bend) {
            uint8_t b = *bp++;
            tag |= (uint64_t)(b & 0x7f) << shift;
            if (!(b & 0x80)) break;
            shift += 7;
        }
        uint32_t fld = (uint32_t)(tag >> 3);
        uint32_t wt  = (uint32_t)(tag & 0x7);
        if (wt == 2) {
            /* length-delimited */
            uint64_t l = 0; shift = 0;
            while (bp < bend) {
                uint8_t b = *bp++;
                l |= (uint64_t)(b & 0x7f) << shift;
                if (!(b & 0x80)) break;
                shift += 7;
            }
            if ((uint64_t)(bend - bp) < l) break;
            const uint8_t *cp = bp; const uint8_t *cend = bp + l;
            bp += l;

            if (fld != 1) continue;  /* not a Channel */

            /* Parse Channel: look for field 2 (settings) submessage. */
            uint8_t  psk[32]; size_t psk_len = 0;
            char     name[32]; name[0] = 0;
            while (cp < cend) {
                uint64_t t2 = 0; int s2 = 0;
                while (cp < cend) {
                    uint8_t b = *cp++;
                    t2 |= (uint64_t)(b & 0x7f) << s2;
                    if (!(b & 0x80)) break;
                    s2 += 7;
                }
                uint32_t f2 = (uint32_t)(t2 >> 3);
                uint32_t w2 = (uint32_t)(t2 & 0x7);
                if (f2 != 2 || w2 != 2) {
                    if (share_skip(&cp, cend, w2) < 0) break;
                    continue;
                }
                uint64_t l2 = 0; s2 = 0;
                while (cp < cend) {
                    uint8_t b = *cp++;
                    l2 |= (uint64_t)(b & 0x7f) << s2;
                    if (!(b & 0x80)) break;
                    s2 += 7;
                }
                if ((uint64_t)(cend - cp) < l2) break;
                const uint8_t *sp = cp; const uint8_t *send = cp + l2; cp += l2;

                /* Parse ChannelSettings: field 2 = psk (bytes), field 3 = name (string). */
                while (sp < send) {
                    uint64_t t3 = 0; int s3 = 0;
                    while (sp < send) {
                        uint8_t b = *sp++;
                        t3 |= (uint64_t)(b & 0x7f) << s3;
                        if (!(b & 0x80)) break;
                        s3 += 7;
                    }
                    uint32_t f3 = (uint32_t)(t3 >> 3);
                    uint32_t w3 = (uint32_t)(t3 & 0x7);
                    if (w3 != 2) {
                        if (share_skip(&sp, send, w3) < 0) break;
                        continue;
                    }
                    uint64_t l3 = 0; s3 = 0;
                    while (sp < send) {
                        uint8_t b = *sp++;
                        l3 |= (uint64_t)(b & 0x7f) << s3;
                        if (!(b & 0x80)) break;
                        s3 += 7;
                    }
                    if ((uint64_t)(send - sp) < l3) break;
                    if (f3 == 2 && l3 <= sizeof(psk)) {        /* psk */
                        memcpy(psk, sp, l3); psk_len = (size_t)l3;
                    } else if (f3 == 3 && l3 < sizeof(name)) { /* name */
                        memcpy(name, sp, l3); name[l3] = 0;
                    }
                    sp += l3;
                }
            }

            if (psk_len > 0) {
                /* simpleN expansion: a one-byte psk N means simpleN. */
                if (psk_len == 1) {
                    extern const uint8_t MESH_DEFAULT_PSK[16];
                    uint8_t expanded[16];
                    memcpy(expanded, MESH_DEFAULT_PSK, 16);
                    expanded[15] = psk[0];
                    if (keyset_add(ks, name[0] ? name : NULL, expanded, 16) == 0) ++added;
                } else if (psk_len == 16 || psk_len == 32) {
                    if (keyset_add(ks, name[0] ? name : NULL, psk, psk_len) == 0) ++added;
                }
            }
        } else {
            /* skip non-length fields cheaply */
            if (wt == 0) { while (bp < bend && (*bp++ & 0x80)) {} }
            else if (wt == 1) bp += 8;
            else if (wt == 5) bp += 4;
        }
    }
    return added;
}

static void promote_to_sse(int fd) {
    const char *hdr =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: keep-alive\r\n"
        "Access-Control-Allow-Origin: *\r\n\r\n"
        "retry: 2000\n\n";
    send_all(fd, hdr, strlen(hdr));

    pthread_mutex_lock(&g_lock);
    /* Replay the history ring oldest-to-newest before going live, then
     * add to the broadcast list atomically -- so the new client doesn't
     * miss events published between replay-end and add-to-list. */
    int start = (g_history_count < HISTORY_RING_SIZE) ? 0 : g_history_head;
    static const char data_prefix[] = "data: ";
    for (int k = 0; k < g_history_count; ++k) {
        int idx = (start + k) % HISTORY_RING_SIZE;
        history_entry_t *e = &g_history[idx];
        if (!e->buf || e->len == 0) continue;
        /* Blocking sends here: the connection is fresh so the kernel buffer
         * is empty, and the dashboard JS handles dupes idempotently. If a
         * peer is genuinely slow we'll spend more time in the lock, but the
         * publishers (low-rate stats + per-frame events) tolerate it. */
        if (send(fd, data_prefix, 6, MSG_NOSIGNAL) < 0) break;
        if (send(fd, e->buf, e->len, MSG_NOSIGNAL) < 0) break;
        /* Two LFs: e->buf is stored trimmed of any trailing newline (see
         * web_publish_line), so this alone must supply the full blank-line
         * SSE terminator -- one '\n' here would reproduce the same
         * message-merging bug live publish just got fixed for. */
        if (send(fd, "\n\n", 2, MSG_NOSIGNAL) < 0) break;
    }
    set_nonblock(fd);
    if (g_sse_count < MAX_SSE_CLIENTS) {
        g_sse_fds[g_sse_count++] = fd;
        if (verbose) fprintf(stderr, "web: SSE client connected (%d total, replayed %d events)\n",
                             g_sse_count, g_history_count);
    } else {
        close(fd);
    }
    pthread_mutex_unlock(&g_lock);
}

/* Read an HTTP request fully: headers + (Content-Length-bound) body.
 * Returns total bytes in buf (NUL-terminated), or 0 on error. */
static size_t recv_full_request(int fd, char *buf, size_t cap)
{
    size_t got = 0;
    /* Read until we have headers ("\r\n\r\n"). */
    while (got < cap - 1) {
        ssize_t n = recv(fd, buf + got, cap - 1 - got, 0);
        if (n <= 0) return 0;
        got += (size_t)n;
        buf[got] = 0;
        if (strstr(buf, "\r\n\r\n")) break;
    }
    /* Parse Content-Length to know how much body we still need. */
    const char *cl = strstr(buf, "Content-Length:");
    if (!cl) cl = strstr(buf, "content-length:");
    if (cl) {
        cl = strchr(cl, ':');
        if (cl) {
            size_t need = (size_t)strtoul(cl + 1, NULL, 10);
            const char *body = strstr(buf, "\r\n\r\n");
            size_t header_len = body ? (size_t)((body + 4) - buf) : got;
            size_t have = got > header_len ? got - header_len : 0;
            while (have < need && got < cap - 1) {
                ssize_t n = recv(fd, buf + got, cap - 1 - got, 0);
                if (n <= 0) break;
                got += (size_t)n;
                have += (size_t)n;
                buf[got] = 0;
            }
        }
    }
    return got;
}

/* Extract the query-string of an HTTP request line (everything between
 * the first '?' and the following space) into out, NUL-terminated.
 * Returns false if there's no '?' before the request-line's end. */
static bool extract_query_string(const char *req, char *out, size_t outcap)
{
    const char *q = strchr(req, '?');
    if (!q) return false;
    ++q;
    const char *end = q;
    while (*end && *end != ' ' && *end != '\r' && *end != '\n') ++end;
    size_t len = (size_t)(end - q);
    if (len >= outcap) len = outcap - 1;
    memcpy(out, q, len);
    out[len] = 0;
    return true;
}

/* Find `key=value` in an already-extracted, '&'-joined query string;
 * url-decodes the value into out. Returns true if found. */
static bool query_get(const char *qs, const char *key, char *out, size_t outcap)
{
    size_t keylen = strlen(key);
    const char *p = qs;
    while (p && *p) {
        const char *amp = strchr(p, '&');
        size_t seglen = amp ? (size_t)(amp - p) : strlen(p);
        if (seglen > keylen && p[keylen] == '=' && strncmp(p, key, keylen) == 0) {
            size_t vlen = seglen - keylen - 1;
            if (vlen >= outcap) vlen = outcap - 1;
            memcpy(out, p + keylen + 1, vlen);
            out[vlen] = 0;
            url_decode_inplace(out);
            return true;
        }
        p = amp ? amp + 1 : NULL;
    }
    return false;
}

/* GET /api/messages?channel=<hash>&before=<ts>&limit=<n> -- on-demand
 * chat scroll-back, bypassing the SSE history ring entirely so depth is
 * bounded only by what's in the SQLite DB (see db_sqlite_query_messages_json). */
static void handle_api_messages(int fd, const char *req)
{
    char qs[512] = {0}, chbuf[32] = {0}, beforebuf[32] = {0}, limbuf[16] = {0};
    extract_query_string(req, qs, sizeof(qs));

    long channel_hash = -1;
    double before_ts = 0.0;
    long limit = API_MESSAGES_DEFAULT_LIMIT;
    if (query_get(qs, "channel", chbuf, sizeof(chbuf))) channel_hash = strtol(chbuf, NULL, 0);
    if (query_get(qs, "before", beforebuf, sizeof(beforebuf))) before_ts = atof(beforebuf);
    if (query_get(qs, "limit", limbuf, sizeof(limbuf))) limit = strtol(limbuf, NULL, 10);
    if (limit <= 0) limit = API_MESSAGES_DEFAULT_LIMIT;
    if (limit > API_MESSAGES_MAX_LIMIT) limit = API_MESSAGES_MAX_LIMIT;
    if (channel_hash < 0) { send_response(fd, 400, "{\"error\":\"missing channel\"}"); return; }

    char *body = db_sqlite_query_messages_json((uint32_t)channel_hash, before_ts, (int)limit);
    if (!body) { send_response(fd, 503, "{\"error\":\"sqlite not configured\"}"); return; }
    send_response(fd, 200, body);
    free(body);
}

/* GET /api/nodes -- dashboard bootstrap-on-load. Combines
 * db_sqlite_query_nodes_json() (names, from the `nodes` table) and
 * db_sqlite_query_positions_json() (each node's last known lat/lon,
 * from the `events` table) into one response, so a freshly-loaded
 * browser tab isn't blank after a sniffer restart even though the
 * live-traffic-only `nodes{}`/`markers{}` frontend state has nothing
 * yet. See db_sqlite.h for the exact per-array shapes. */
static void handle_api_nodes(int fd, const char *req)
{
    (void)req;
    char *nodes_json = db_sqlite_query_nodes_json();
    char *pos_json = db_sqlite_query_positions_json();
    if (!nodes_json || !pos_json) {
        free(nodes_json);
        free(pos_json);
        send_response(fd, 503, "{\"error\":\"sqlite not configured\"}");
        return;
    }
    size_t cap = strlen(nodes_json) + strlen(pos_json) + 32;
    char *body = malloc(cap);
    if (!body) {
        free(nodes_json);
        free(pos_json);
        send_response(fd, 500, "{\"error\":\"out of memory\"}");
        return;
    }
    snprintf(body, cap, "{\"nodes\":%s,\"positions\":%s}", nodes_json, pos_json);
    send_response(fd, 200, body);
    free(nodes_json);
    free(pos_json);
    free(body);
}

/* GET /api/meshcore-channels -- Channels-tab bootstrap-on-load, same
 * rationale as handle_api_nodes() above: the frontend's `channels{}`
 * state only ever grows from live SSE traffic (packet events,
 * MC_CHANNEL_DISCOVERED/MC_CHANNEL_ADDED), so a plain browser refresh
 * wipes every previously-learned channel_hash->name mapping until (if
 * ever) fresh traffic happens to arrive on that exact channel again.
 * db_sqlite_query_channel_names_json() reads the durable mapping
 * straight out of the events table instead. */
static void handle_api_meshcore_channels(int fd, const char *req)
{
    (void)req;
    char *json = db_sqlite_query_channel_names_json();
    if (!json) {
        send_response(fd, 503, "{\"error\":\"sqlite not configured\"}");
        return;
    }
    size_t cap = strlen(json) + 16;
    char *body = malloc(cap);
    if (!body) {
        free(json);
        send_response(fd, 500, "{\"error\":\"out of memory\"}");
        return;
    }
    snprintf(body, cap, "{\"channels\":%s}", json);
    send_response(fd, 200, body);
    free(json);
    free(body);
}

#define STATS_WINDOW_24H_SECS (24.0 * 3600.0)
#define STATS_WINDOW_1W_SECS  (7.0 * 24.0 * 3600.0)
#define STATS_WINDOW_1M_SECS  (30.0 * 24.0 * 3600.0) /* fixed 30-day window, not calendar-aware */

/* GET /api/stats?window=24h|1w|1m -- Statistics tab. Named presets
 * only (not an arbitrary ?hours=N) -- a closed 3-value whitelist needs
 * no numeric validation, unlike /api/messages' `limit` param. Combines
 * the three MeshCore-only aggregate queries (db_sqlite.h) into one
 * response; since_ts is computed here from the current wall clock, a
 * client never gets to supply its own timestamp. */
static void handle_api_stats(int fd, const char *req)
{
    char qs[128] = {0}, winbuf[8] = {0};
    extract_query_string(req, qs, sizeof(qs));

    double window_secs = STATS_WINDOW_24H_SECS;
    if (query_get(qs, "window", winbuf, sizeof(winbuf))) {
        if (!strcmp(winbuf, "1w")) window_secs = STATS_WINDOW_1W_SECS;
        else if (!strcmp(winbuf, "1m")) window_secs = STATS_WINDOW_1M_SECS;
        /* anything else (including "24h" or garbage) keeps the 24h default */
    }
    struct timespec ts_now;
    clock_gettime(CLOCK_REALTIME, &ts_now);
    double since_ts = (double)ts_now.tv_sec + (double)ts_now.tv_nsec / 1e9 - window_secs;

    char *by_type    = db_sqlite_query_stats_by_type_json(since_ts);
    char *by_channel = db_sqlite_query_stats_by_channel_json(since_ts);
    char *crc        = db_sqlite_query_stats_crc_json(since_ts);
    if (!by_type || !by_channel || !crc) {
        free(by_type);
        free(by_channel);
        free(crc);
        send_response(fd, 503, "{\"error\":\"sqlite not configured\"}");
        return;
    }
    size_t cap = strlen(by_type) + strlen(by_channel) + strlen(crc) + 64;
    char *body = malloc(cap);
    if (!body) {
        free(by_type);
        free(by_channel);
        free(crc);
        send_response(fd, 500, "{\"error\":\"out of memory\"}");
        return;
    }
    snprintf(body, cap, "{\"by_type\":%s,\"by_channel\":%s,\"crc\":%s}", by_type, by_channel, crc);
    send_response(fd, 200, body);
    free(by_type);
    free(by_channel);
    free(crc);
    free(body);
}

static void *web_thread(void *arg)
{
    (void)arg;
#if defined(__APPLE__)
    pthread_setname_np("web");
#elif defined(_GNU_SOURCE)
    pthread_setname_np(pthread_self(), "web");
#endif
    while (g_thread_running) {
        struct sockaddr_in peer;
        socklen_t peerlen = sizeof(peer);
        int fd = accept(g_listen_fd, (struct sockaddr *)&peer, &peerlen);
        if (fd < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            break;
        }

        /* 16 KB request buffer -- enough for hundreds of keys or a long share URL. */
        static __thread char buf[16384];
        size_t got = recv_full_request(fd, buf, sizeof(buf));
        if (!got) { close(fd); continue; }

        if (strncmp(buf, "GET / ",        6) == 0 ||
            strncmp(buf, "GET /\r",       6) == 0 ||
            strncmp(buf, "GET /index",   10) == 0) serve_index(fd);
        else if (strncmp(buf, "GET /events", 11) == 0) promote_to_sse(fd);
        else if (strncmp(buf, "GET /api/messages", 17) == 0) handle_api_messages(fd, buf);
        else if (strncmp(buf, "GET /api/nodes", 14) == 0) handle_api_nodes(fd, buf);
        else if (strncmp(buf, "GET /api/meshcore-channels", 26) == 0) handle_api_meshcore_channels(fd, buf);
        else if (strncmp(buf, "GET /api/stats", 14) == 0) handle_api_stats(fd, buf);
        else if (strncmp(buf, "POST /api/keys", 14) == 0) {
            if (!api_auth_ok(buf, fd)) { close(fd); continue; }
            c2_response_t r;
            c2_keys_add(find_body(buf), &r);
            send_response(fd, r.status, r.body);
        }
        else if (strncmp(buf, "POST /api/share-url", 19) == 0) {
            if (!api_auth_ok(buf, fd)) { close(fd); continue; }
            const char *body = find_body(buf);
            c2_response_t r;
            /* HTTP-form bodies arrive URL-encoded; decode before dispatch.
             * The share-URL parser itself is transport-agnostic in c2.c. */
            if (!body) { c2_share_url(NULL, &r); }
            else {
                char dec[1024];
                size_t bl = strlen(body);
                if (bl >= sizeof(dec)) bl = sizeof(dec) - 1;
                memcpy(dec, body, bl); dec[bl] = 0;
                url_decode_inplace(dec);
                c2_share_url(dec, &r);
            }
            send_response(fd, r.status, r.body);
        }
        else if (strncmp(buf, "POST /api/extra-freq", 20) == 0) {
            if (!api_auth_ok(buf, fd)) { close(fd); continue; }
            c2_response_t r;
            c2_extra_freq(find_body(buf), &r);
            send_response(fd, r.status, r.body);
        }
        else if (strncmp(buf, "POST /api/cot-multicast", 23) == 0) {
            if (!api_auth_ok(buf, fd)) { close(fd); continue; }
            c2_response_t r;
            c2_cot_multicast(find_body(buf), &r);
            send_response(fd, r.status, r.body);
        }
        else if (strncmp(buf, "POST /api/meshcore-channel", 26) == 0) {
            if (!api_auth_ok(buf, fd)) { close(fd); continue; }
            c2_response_t r;
            c2_meshcore_channel_add(find_body(buf), &r);
            send_response(fd, r.status, r.body);
        }
        else serve_404(fd);
    }
    return NULL;
}

void web_init(int port)
{
    if (port <= 0) return;

    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_fd < 0) { perror("web: socket"); return; }
    int one = 1;
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);
    if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("web: bind"); close(g_listen_fd); g_listen_fd = -1; return;
    }
    if (listen(g_listen_fd, 16) < 0) {
        perror("web: listen"); close(g_listen_fd); g_listen_fd = -1; return;
    }

    g_thread_running = 1;
    if (pthread_create(&g_thread, NULL, web_thread, NULL) != 0) {
        close(g_listen_fd); g_listen_fd = -1; g_thread_running = 0; return;
    }
    fprintf(stderr, "web: listening on port %d\n", port);
}

void web_publish_line(const char *json, size_t len)
{
    if (!json || len == 0) return;

    /* Callers vary: STATS/CHAN_SNR are built with raw snprintf format
     * strings that already end in "}\n", but the jw.c-based per-event
     * serializer (feed.c / feed_meshcore_json.c) does NOT append a
     * trailing newline -- jw_close() only writes '}'. Strip whatever
     * trailing CR/LF the caller happened to include so every caller
     * is normalized the same way before we add our own terminator. */
    while (len > 0 && (json[len - 1] == '\n' || json[len - 1] == '\r')) --len;
    if (len == 0) return;

    /* Assemble "data: <json>\n\n" into one buffer and write it with a
     * single send(). The SSE spec requires a blank line (two LFs) to
     * terminate an event -- a single trailing '\n' is NOT enough; the
     * browser's EventSource then treats the next published line as a
     * continuation of the same (still-open) event, silently merging
     * two unrelated JSON payloads into one e.data string joined by a
     * bare '\n', which fails JSON.parse and gets dropped by the
     * dashboard's top-level `catch(_){return;}`. This is what was
     * happening to essentially every mesh-event message before this
     * fix (STATS/CHAN_SNR happened to already end in "}\n" from their
     * own format strings, so they -- coincidentally -- always framed
     * correctly and never demonstrated the bug on their own).
     *
     * Splitting into multiple send() calls would let a slow browser
     * take part of the frame, return EAGAIN on the rest, and keep the
     * FD open mid-frame -- the next event then appends on top of the
     * half-written one and corrupts every subsequent message on that
     * client -- so this stays one single send() of the whole frame. */
    static const char HDR[] = "data: ";
    const size_t hdrlen = sizeof(HDR) - 1;
    const size_t total  = hdrlen + len + 2;

    char  stackbuf[4096];
    char *buf = stackbuf;
    if (total > sizeof(stackbuf)) {
        buf = malloc(total);
        if (!buf) return;
    }
    memcpy(buf, HDR, hdrlen);
    memcpy(buf + hdrlen, json, len);
    buf[hdrlen + len]     = '\n';
    buf[hdrlen + len + 1] = '\n';

    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_sse_count; ) {
        int fd = g_sse_fds[i];
        ssize_t w = send(fd, buf, total, MSG_NOSIGNAL | MSG_DONTWAIT);
        /* Any short write or EAGAIN means we cannot keep this client
         * framed -- close it. A reload reconnects fresh and replays
         * from g_history. */
        if (w < (ssize_t)total) {
            close(fd);
            g_sse_fds[i] = g_sse_fds[--g_sse_count];
            continue;
        }
        ++i;
    }
    /* Push into the history ring so a browser refresh / late-joining tab
     * can reconstruct dashboard state without waiting for new traffic.
     * Same lock as the broadcast list -- atomicity matters: the new
     * client's replay (under this lock) must not miss events published
     * between replay-start and add-to-list. */
    history_entry_t *e = &g_history[g_history_head];
    free(e->buf); /* free(NULL) is a no-op for slots not yet written */
    e->buf = malloc(len);
    if (e->buf) {
        memcpy(e->buf, json, len);
        e->len = len;
        g_history_head = (g_history_head + 1) % HISTORY_RING_SIZE;
        if (g_history_count < HISTORY_RING_SIZE) ++g_history_count;
    } else {
        e->buf = NULL; e->len = 0; /* malloc fail: slot empty, ring intact */
    }
    pthread_mutex_unlock(&g_lock);

    if (buf != stackbuf) free(buf);
}

void web_shutdown(void)
{
    if (g_thread_running) {
        g_thread_running = 0;
        if (g_listen_fd >= 0) shutdown(g_listen_fd, SHUT_RDWR);
        pthread_join(g_thread, NULL);
    }
    if (g_listen_fd >= 0) { close(g_listen_fd); g_listen_fd = -1; }
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_sse_count; ++i) close(g_sse_fds[i]);
    g_sse_count = 0;
    /* Release the history ring so leak detectors don't flag exit-time bytes. */
    for (int i = 0; i < HISTORY_RING_SIZE; ++i) {
        free(g_history[i].buf);
        g_history[i].buf = NULL;
        g_history[i].len = 0;
    }
    g_history_head = g_history_count = 0;
    pthread_mutex_unlock(&g_lock);
}
