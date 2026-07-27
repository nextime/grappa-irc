// Shottino, a standalone terminal client for grappa.
//
// Contract: authenticate against grappa's REST API, read scrollback via REST,
// send PRIVMSG/JOIN/PART via REST, and subscribe to Phoenix Channels for live
// typed JSON events. The client never parses IRC framing.

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <netdb.h>
#include <ncurses.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <limits.h>

#include "alias.h"
#include "http.h"
#include "json.h"
#include "media.h"
#include "mirc.h"
#include "termcolor.h"
#include "wire.h"

#define MAX_TOKEN 4096
#define MAX_SUBJECT 512
#define MAX_NETWORKS 32
#define MAX_WINDOWS 128
#define MAX_CHANNEL 256
#define MAX_SLUG 128
#define MAX_LINE 1024
#define MAX_TOPIC 4096
#define LOG_LINES 2000
#define HTTP_MAX (4 * 1024 * 1024)
#define WS_MAX_PAYLOAD (1024 * 1024)
#define JOB_QUEUE 256
#define SEEN_MESSAGES 12000
#define INPUT_HISTORY 200
#define PANEL_LINES 256
#define MAX_LINK_REGIONS 256
/* How many decoded inline images to keep resident. Scrollback is long;
 * pictures are not, and each holds either a protocol payload or a pixel
 * buffer. Oldest slot is recycled. */
#define MAX_INLINE_MEDIA 24
/* Sentinel slot id for the full-screen preview, distinct from the inline
 * pool indices the decode job otherwise receives. */
#define MEDIA_SLOT_PREVIEW (-2)
#define INLINE_MAX_ROWS 14
/* #451/#324 — cap on the deployment's HTTP host aliases retained from
 * /api/server-settings for first-party media classification. */
#define MAX_HTTP_ALIASES 16

enum color_pair {
    CP_MAIN = 1,
    CP_ALT,
    CP_BORDER,
    CP_ACCENT,
    CP_MUTED,
    CP_MENTION,
    CP_ERROR,
    CP_INPUT,
    CP_SELECTED,
    CP_NICK0,
    CP_NICK1,
    CP_NICK2,
    CP_NICK3,
    CP_NICK4,
    CP_NICK5,
    CP_NICK6,
    CP_NICK7,
    CP_NICK8,
    CP_NICK9,
    CP_NICK10,
    CP_NICK11,
    CP_NICK12,
    CP_NICK13,
    CP_NICK14,
    CP_NICK15
};

enum theme_color {
    TC_BG = 16,
    TC_BG_ALT,
    TC_FG,
    TC_ACCENT,
    TC_MUTED,
    TC_BORDER,
    TC_MENTION,
    TC_ERROR,
    TC_NICK0,
    TC_NICK1,
    TC_NICK2,
    TC_NICK3,
    TC_NICK4,
    TC_NICK5,
    TC_NICK6,
    TC_NICK7,
    TC_NICK8,
    TC_NICK9,
    TC_NICK10,
    TC_NICK11,
    TC_NICK12,
    TC_NICK13,
    TC_NICK14,
    TC_NICK15
};

struct url {
    bool tls;
    char host[256];
    char port[16];
    char base[512];
};

struct http_response {
    int status;
    char *body;
    size_t body_len;
};

struct tls_conn {
    int fd;
    bool tls;
    SSL *ssl;
};

struct network {
    int id;
    char slug[MAX_SLUG];
    char nick[MAX_CHANNEL];
    /* ISUPPORT PREFIX, as parallel arrays: prefix_letters[i] is the mode
     * letter whose sigil is prefix_sigils[i], highest rank first. Empty
     * until the network sends 005, so the draw path falls back to the
     * conventional (qaohv) mapping rather than showing nothing. */
    char prefix_letters[16];
    char prefix_sigils[16];
    size_t prefix_count;
    /* Live per-session state mirrored off the user topic. */
    char umodes[32];
    bool away;
    char away_reason[MAX_LINE];
    wire_connection_state conn_state;
    bool conn_known;
    bool connecting;
};

/* Server-owned window state. Grappa owns this state machine; shottino
 * MIRRORS it and never originates a transition — same contract cicchetto
 * is held to. Adding a state here without a server change would be a
 * parallel client-side state machine, which is exactly what the project
 * invariant forbids.
 *
 *   pending  — JOIN sent, no terminal reply yet
 *   invited  — inbound INVITE we did not request; not joined, greyed
 *   joined   — in the channel
 *   failed   — JOIN rejected (reason + numeric explain why)
 *   kicked   — removed by an op (by + reason)
 *   parked   — the network itself is not connected
 */
enum window_state {
    WS_UNKNOWN = 0,
    WS_PENDING,
    WS_INVITED,
    WS_JOINED,
    WS_FAILED,
    WS_KICKED,
    WS_PARKED
};

struct member {
    char nick[MAX_CHANNEL];
    char modes[8]; /* mode letters (o, v, h...) — sigil resolved at draw */
};

struct window {
    char network[MAX_SLUG];
    char channel[MAX_CHANNEL];
    char topic[MAX_TOPIC];
    struct member members[512];
    size_t member_count;
    long last_id;
    unsigned unread;
    bool joined_ws;
    /* Mirrored window state + the metadata that explains a terminal one,
     * so the status line can say WHY a tab is dead rather than just
     * greying it. */
    enum window_state state;
    char state_detail[MAX_LINE];
    long failure_numeric;
    /* Server-owned read cursor for this (subject, network, channel). */
    long last_read_id;
    unsigned mentions;
    wire_counts_severity severity;
};

enum job_kind {
    JOB_FETCH,
    JOB_SEND,
    JOB_JOIN,
    JOB_PART,
    JOB_NICK,
    JOB_NETWORK_STATE,
    JOB_TOPIC,
    JOB_MEMBERS,
    JOB_CLOSE_QUERY,
    JOB_READ_CURSOR,
    JOB_MEDIA
};

struct job {
    enum job_kind kind;
    char network[MAX_SLUG];
    char channel[MAX_CHANNEL];
    char arg1[MAX_LINE];
    char arg2[MAX_LINE];
};

struct seen_message {
    long id;
    char network[MAX_SLUG];
    char channel[MAX_CHANNEL];
};


struct pending_echo {
    unsigned long id;
    char network[MAX_SLUG];
    char channel[MAX_CHANNEL];
    char body[MAX_LINE];
};

enum panel_kind {
    PANEL_CHAT,
    PANEL_ARCHIVE,
    PANEL_SETTINGS,
    PANEL_ADMIN
};

/* An image attached to a scrollback row.
 *
 * Lifecycle is explicit because decoding is ASYNC: the UI thread never
 * waits on ffmpeg. A row starts IDLE, the draw path promotes it to
 * FETCHING when it first becomes visible (so we decode what is on screen
 * rather than everything ever linked), the worker fills it and marks it
 * READY or FAILED.
 *
 * `payload` holds a ready-to-write terminal escape when a graphics
 * protocol is in use; `rgb` holds pixels when falling back to character
 * art. Exactly one is populated. */
enum inline_state { IM_IDLE = 0, IM_FETCHING, IM_READY, IM_FAILED };

struct inline_media {
    char url[MAX_LINE];
    bool is_video;
    enum inline_state state;
    bool force_ascii;        /* /preview-ascii: skip any graphics protocol */
    int cols, rows;          /* cell box the image occupies */
    char *payload;           /* protocol escape bytes, or NULL */
    size_t payload_len;
    unsigned char *rgb;      /* art path: cols x (rows*2) RGB24, or NULL */
    /* Where it was last drawn, so a protocol image is re-emitted only
     * when its position actually moves. Re-emitting a multi-KB sixel
     * every 50 ms frame would saturate the tty for no benefit. */
    int drawn_y, drawn_x;
    bool drawn;
};

/* A clickable media link rendered in the chat area. Recorded each draw()
 * frame (cleared at frame start) so mouse coordinates can be mapped back to
 * the URL under the cursor without re-deriving the wrapped layout. */
struct link_region {
    int y0;
    int y1;
    int x0;
    int x1;
    bool is_video;
    char url[MAX_LINE];
};

struct app {
    struct url url;
    char token[MAX_TOKEN];
    char token_path[PATH_MAX];
    char subject[MAX_SUBJECT];
    char login_nick[MAX_CHANNEL];
    struct network networks[MAX_NETWORKS];
    size_t network_count;
    struct window windows[MAX_WINDOWS];
    size_t window_count;
    size_t current;
    char *log[LOG_LINES];
    bool log_mentions[LOG_LINES];
    bool log_pending[LOG_LINES];
    /* Scrollback id per log row (0 = not a scrollback message). Lets the
     * unread divider be placed at the exact row the server's read cursor
     * points at, rather than guessed from position. */
    long log_ids[LOG_LINES];
    size_t log_count;
    struct pending_echo pending[256];
    size_t pending_count;
    unsigned long next_pending_id;
    enum panel_kind panel;
    char *panel_lines[PANEL_LINES];
    size_t panel_line_count;
    struct seen_message seen[SEEN_MESSAGES];
    size_t seen_count;
    size_t seen_next;
    size_t scrollback_offset;
    bool scrollback_pinned;
    char input[MAX_LINE];
    size_t input_len;
    char last_url[MAX_LINE];
    /* Most recent IMAGE/VIDEO link, for keyboard-driven /preview. */
    char last_media_url[MAX_LINE];
    bool last_media_is_video;
    char hover_url[MAX_LINE];
    struct link_region link_regions[MAX_LINK_REGIONS];
    size_t link_region_count;
    struct inline_media media[MAX_INLINE_MEDIA];
    /* The full-screen preview gets its OWN slot so opening one never
     * evicts an inline image that is currently on screen. */
    struct inline_media preview;
    bool preview_pending;
    size_t media_count;
    size_t media_next;              /* recycle cursor */
    /* Index into `media` per log row, or -1. Parallel to log[] like the
     * mention/pending/id arrays. */
    int log_media[LOG_LINES];
    media_protocol proto;           /* detected once, before ncurses */
    bool inline_media_enabled;
    /* #451/#324 — this deployment's HTTP host aliases (from
     * /api/server-settings). With app->url.host they define which
     * /uploads/ links are first-party and may auto-render inline; every
     * other peer URL stays click-to-preview. Empty = restrictive (only
     * the connect host). The shottino twin of cic's mediaLink.ts set. */
    char http_host_aliases[MAX_HTTP_ALIASES][256];
    size_t http_host_alias_count;
    char history[INPUT_HISTORY][MAX_LINE];
    size_t history_count;
    size_t history_pos;
    struct alias_table aliases;
    /* Mouse tracking preference. OFF by default: tracking necessarily
     * suppresses the terminal's own copy/paste selection, and for a
     * terminal client selection matters far more day-to-day than
     * click-to-preview — which `/preview` provides from the keyboard
     * anyway. `/mouse on` opts back in. */
    bool mouse_enabled;
    bool running;
    pthread_mutex_t lock;
    pthread_mutex_t jobs_lock;
    pthread_cond_t jobs_cond;
    pthread_t worker;
    struct job jobs[JOB_QUEUE];
    size_t jobs_head;
    size_t jobs_tail;
    bool worker_stop;
    struct tls_conn ws;
    bool ws_connected;
    unsigned long ws_ref;
    time_t next_heartbeat;
    /* Reconnect state: current backoff in seconds (0 = healthy) and the
     * earliest time the next attempt may run. */
    int ws_backoff;
    time_t ws_retry_at;
    SSL_CTX *ssl_ctx;
};

static void die(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void startup(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

static void startup(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("shottino: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    fflush(stderr);
    va_end(ap);
}

static char *xasprintf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static char *xasprintf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) die("format failed");
    char *s = malloc((size_t)n + 1);
    if (!s) die("out of memory");
    vsnprintf(s, (size_t)n + 1, fmt, ap2);
    va_end(ap2);
    return s;
}

static void log_line(struct app *app, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void log_line_mention(struct app *app, bool mention, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

static void log_line(struct app *app, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    char *s = malloc((size_t)n + 1);
    if (!s) return;
    vsnprintf(s, (size_t)n + 1, fmt, ap2);
    va_end(ap2);

    pthread_mutex_lock(&app->lock);
    if (app->log_count == LOG_LINES) {
        free(app->log[0]);
        memmove(app->log, app->log + 1, sizeof(app->log[0]) * (LOG_LINES - 1));
        memmove(app->log_mentions, app->log_mentions + 1, sizeof(app->log_mentions[0]) * (LOG_LINES - 1));
        memmove(app->log_pending, app->log_pending + 1, sizeof(app->log_pending[0]) * (LOG_LINES - 1));
        memmove(app->log_ids, app->log_ids + 1, sizeof(app->log_ids[0]) * (LOG_LINES - 1));
        memmove(app->log_media, app->log_media + 1, sizeof(app->log_media[0]) * (LOG_LINES - 1));
        app->log_count--;
    }
    app->log[app->log_count] = s;
    app->log_mentions[app->log_count] = false;
    app->log_pending[app->log_count] = false;
    app->log_ids[app->log_count] = 0;
    app->log_media[app->log_count] = -1;
    app->log_count++;
    pthread_mutex_unlock(&app->lock);
}

static void log_line_mention(struct app *app, bool mention, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    char *s = malloc((size_t)n + 1);
    if (!s) return;
    vsnprintf(s, (size_t)n + 1, fmt, ap2);
    va_end(ap2);

    pthread_mutex_lock(&app->lock);
    if (app->log_count == LOG_LINES) {
        free(app->log[0]);
        memmove(app->log, app->log + 1, sizeof(app->log[0]) * (LOG_LINES - 1));
        memmove(app->log_mentions, app->log_mentions + 1, sizeof(app->log_mentions[0]) * (LOG_LINES - 1));
        memmove(app->log_pending, app->log_pending + 1, sizeof(app->log_pending[0]) * (LOG_LINES - 1));
        memmove(app->log_ids, app->log_ids + 1, sizeof(app->log_ids[0]) * (LOG_LINES - 1));
        memmove(app->log_media, app->log_media + 1, sizeof(app->log_media[0]) * (LOG_LINES - 1));
        app->log_count--;
    }
    app->log[app->log_count] = s;
    app->log_mentions[app->log_count] = mention;
    app->log_pending[app->log_count] = false;
    app->log_ids[app->log_count] = 0;
    app->log_media[app->log_count] = -1;
    app->log_count++;
    pthread_mutex_unlock(&app->lock);
}

static void add_pending_echo(struct app *app, const char *network, const char *channel, const char *sender, const char *body) {
    char clock[16];
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(clock, sizeof(clock), "%H:%M", &tm);
    char *line = xasprintf("[%s/%s] %s <%s> %s", network, channel, clock, sender && sender[0] ? sender : "me", body);
    pthread_mutex_lock(&app->lock);
    if (app->log_count == LOG_LINES) {
        free(app->log[0]);
        memmove(app->log, app->log + 1, sizeof(app->log[0]) * (LOG_LINES - 1));
        memmove(app->log_mentions, app->log_mentions + 1, sizeof(app->log_mentions[0]) * (LOG_LINES - 1));
        memmove(app->log_pending, app->log_pending + 1, sizeof(app->log_pending[0]) * (LOG_LINES - 1));
        memmove(app->log_ids, app->log_ids + 1, sizeof(app->log_ids[0]) * (LOG_LINES - 1));
        memmove(app->log_media, app->log_media + 1, sizeof(app->log_media[0]) * (LOG_LINES - 1));
        app->log_count--;
    }
    app->log[app->log_count] = line;
    app->log_mentions[app->log_count] = false;
    app->log_pending[app->log_count] = true;
    app->log_ids[app->log_count] = 0;
    app->log_media[app->log_count] = -1;
    app->log_count++;
    if (app->pending_count < sizeof(app->pending) / sizeof(app->pending[0])) {
        struct pending_echo *p = &app->pending[app->pending_count++];
        p->id = ++app->next_pending_id;
        snprintf(p->network, sizeof(p->network), "%s", network);
        snprintf(p->channel, sizeof(p->channel), "%s", channel);
        snprintf(p->body, sizeof(p->body), "%s", body);
    }
    app->scrollback_offset = 0;
    app->scrollback_pinned = false;
    pthread_mutex_unlock(&app->lock);
}

static void clear_matching_pending_echo(struct app *app, const char *network, const char *channel, const char *body) {
    pthread_mutex_lock(&app->lock);
    for (size_t i = 0; i < app->log_count; i++) {
        if (!app->log_pending[i]) continue;
        if (strstr(app->log[i], body) && strstr(app->log[i], network) && strstr(app->log[i], channel)) {
            free(app->log[i]);
            memmove(app->log + i, app->log + i + 1, sizeof(app->log[0]) * (app->log_count - i - 1));
            memmove(app->log_mentions + i, app->log_mentions + i + 1, sizeof(app->log_mentions[0]) * (app->log_count - i - 1));
            memmove(app->log_pending + i, app->log_pending + i + 1, sizeof(app->log_pending[0]) * (app->log_count - i - 1));
            app->log_count--;
            break;
        }
    }
    for (size_t i = 0; i < app->pending_count; i++) {
        if (strcmp(app->pending[i].network, network) == 0 && strcmp(app->pending[i].channel, channel) == 0 && strcmp(app->pending[i].body, body) == 0) {
            memmove(app->pending + i, app->pending + i + 1, sizeof(app->pending[0]) * (app->pending_count - i - 1));
            app->pending_count--;
            break;
        }
    }
    pthread_mutex_unlock(&app->lock);
}

/* Caller holds app->lock. */
static void clear_panel_lines_locked(struct app *app) {
    for (size_t i = 0; i < app->panel_line_count; i++) free(app->panel_lines[i]);
    app->panel_line_count = 0;
}

static void panel_line(struct app *app, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

/* Appends one panel row. Takes the lock itself: panel population runs on
 * the command thread and issues blocking HTTP between rows, so it cannot
 * hold the lock across the whole build — the draw thread would stall for
 * the duration of every request. Locking per row means a panel paints
 * progressively instead, which is also the better behaviour. */
static void panel_line(struct app *app, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    char *s = malloc((size_t)n + 1);
    if (!s) return;
    vsnprintf(s, (size_t)n + 1, fmt, ap2);
    va_end(ap2);
    pthread_mutex_lock(&app->lock);
    if (app->panel_line_count < PANEL_LINES) app->panel_lines[app->panel_line_count++] = s;
    else free(s);
    pthread_mutex_unlock(&app->lock);
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static short rgb_component(int hex, int shift) {
    return (short)((((hex >> shift) & 0xff) * 1000) / 255);
}

static void define_color(short id, int hex) {
    if (can_change_color()) init_color(id, rgb_component(hex, 16), rgb_component(hex, 8), rgb_component(hex, 0));
}

static void init_theme(void) {
    if (!has_colors()) return;
    start_color();
    use_default_colors();

    define_color(TC_BG, 0x0a0a0a);
    define_color(TC_BG_ALT, 0x111111);
    define_color(TC_FG, 0xe0e0e0);
    define_color(TC_ACCENT, 0x5fafd7);
    define_color(TC_MUTED, 0x707070);
    define_color(TC_BORDER, 0x1f1f1f);
    define_color(TC_MENTION, 0x2a1f00);
    define_color(TC_ERROR, 0xd77070);
    define_color(TC_NICK0, 0xff8c8c);
    define_color(TC_NICK1, 0xffb060);
    define_color(TC_NICK2, 0xffd060);
    define_color(TC_NICK3, 0xd8e060);
    define_color(TC_NICK4, 0x90d870);
    define_color(TC_NICK5, 0x60d8a8);
    define_color(TC_NICK6, 0x60d8d8);
    define_color(TC_NICK7, 0x60b8e8);
    define_color(TC_NICK8, 0x88a8ff);
    define_color(TC_NICK9, 0xb890ff);
    define_color(TC_NICK10, 0xe088e0);
    define_color(TC_NICK11, 0xff90c0);
    define_color(TC_NICK12, 0xe0a888);
    define_color(TC_NICK13, 0xc0c0c0);
    define_color(TC_NICK14, 0xa0e8b8);
    define_color(TC_NICK15, 0xf0d090);

    init_pair(CP_MAIN, TC_FG, TC_BG);
    init_pair(CP_ALT, TC_FG, TC_BG_ALT);
    init_pair(CP_BORDER, TC_BORDER, TC_BG);
    init_pair(CP_ACCENT, TC_ACCENT, TC_BG);
    init_pair(CP_MUTED, TC_MUTED, TC_BG);
    init_pair(CP_MENTION, TC_FG, TC_MENTION);
    init_pair(CP_ERROR, TC_ERROR, TC_BG);
    init_pair(CP_INPUT, TC_FG, TC_BG);
    init_pair(CP_SELECTED, TC_ACCENT, TC_BORDER);
    for (short i = 0; i < 16; i++) init_pair((short)(CP_NICK0 + i), (short)(TC_NICK0 + i), TC_BG);
    bkgd(COLOR_PAIR(CP_MAIN));
}

static unsigned long djb2(const char *s) {
    unsigned long hash = 5381;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) hash = ((hash << 5) + hash) + *p;
    return hash;
}

static int nick_pair(const char *nick) {
    return CP_NICK0 + (int)(djb2(nick) % 16);
}

static char *url_encode(const char *s) {
    static const char *hex = "0123456789ABCDEF";
    size_t len = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (isalnum(*p) || *p == '-' || *p == '_' || *p == '.' || *p == '~') len++;
        else len += 3;
    }
    char *out = malloc(len + 1);
    if (!out) die("out of memory");
    char *w = out;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (isalnum(*p) || *p == '-' || *p == '_' || *p == '.' || *p == '~') {
            *w++ = (char)*p;
        } else {
            *w++ = '%';
            *w++ = hex[*p >> 4];
            *w++ = hex[*p & 15];
        }
    }
    *w = 0;
    return out;
}

static char *url_decode(const char *s) {
    size_t n = strlen(s);
    char *out = malloc(n + 1);
    if (!out) die("out of memory");
    size_t j = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '%' && i + 2 < n && isxdigit((unsigned char)s[i + 1]) && isxdigit((unsigned char)s[i + 2])) {
            out[j++] = (char)((hexval(s[i + 1]) << 4) | hexval(s[i + 2]));
            i += 2;
        } else {
            out[j++] = s[i];
        }
    }
    out[j] = 0;
    return out;
}

static char *dup_range(const char *s, size_t len) {
    char *out = malloc(len + 1);
    if (!out) die("out of memory");
    memcpy(out, s, len);
    out[len] = 0;
    return out;
}

// Split a share link `https://host[:port]/share/<token>` (the URL cic mints,
// `${origin}/share/${token}`) into its base origin and the percent-decoded
// token. Tolerates a hash-router artifact (`.../#/share/<token>`) and trailing
// query/fragment after the token. Returns false if no `/share/` segment.
static bool split_share_url(const char *url, char **base_out, char **token_out) {
    const char *marker = strstr(url, "/share/");
    if (!marker) return false;
    const char *tok = marker + 7; // strlen("/share/")
    size_t toklen = strcspn(tok, "?#");
    if (toklen == 0) return false;
    char *raw = dup_range(tok, toklen);
    *token_out = url_decode(raw);
    free(raw);
    size_t baselen = (size_t)(marker - url);
    if (baselen >= 2 && strncmp(marker - 2, "/#", 2) == 0) baselen -= 2; // strip hash-router "/#"
    *base_out = dup_range(url, baselen);
    return true;
}

static char *json_escape(const char *s) {
    size_t len = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
        case '"': case '\\': case '\b': case '\f': case '\n': case '\r': case '\t': len += 2; break;
        default: len += (*p < 0x20) ? 6 : 1; break;
        }
    }
    char *out = malloc(len + 1);
    if (!out) die("out of memory");
    char *w = out;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
        case '"': *w++ = '\\'; *w++ = '"'; break;
        case '\\': *w++ = '\\'; *w++ = '\\'; break;
        case '\b': *w++ = '\\'; *w++ = 'b'; break;
        case '\f': *w++ = '\\'; *w++ = 'f'; break;
        case '\n': *w++ = '\\'; *w++ = 'n'; break;
        case '\r': *w++ = '\\'; *w++ = 'r'; break;
        case '\t': *w++ = '\\'; *w++ = 't'; break;
        default:
            if (*p < 0x20) {
                sprintf(w, "\\u%04x", *p);
                w += 6;
            } else {
                *w++ = (char)*p;
            }
        }
    }
    *w = 0;
    return out;
}

static bool parse_url(const char *raw, struct url *out) {
    memset(out, 0, sizeof(*out));
    const char *p = raw;
    if (strncmp(p, "https://", 8) == 0) {
        out->tls = true;
        p += 8;
        strcpy(out->port, "443");
    } else if (strncmp(p, "http://", 7) == 0) {
        out->tls = false;
        p += 7;
        strcpy(out->port, "80");
    } else {
        return false;
    }

    const char *slash = strchr(p, '/');
    const char *end = slash ? slash : p + strlen(p);
    const char *colon = memchr(p, ':', (size_t)(end - p));
    size_t host_len = colon ? (size_t)(colon - p) : (size_t)(end - p);
    if (host_len == 0 || host_len >= sizeof(out->host)) return false;
    memcpy(out->host, p, host_len);
    out->host[host_len] = 0;
    if (colon) {
        size_t port_len = (size_t)(end - colon - 1);
        if (port_len == 0 || port_len >= sizeof(out->port)) return false;
        memcpy(out->port, colon + 1, port_len);
        out->port[port_len] = 0;
    }
    snprintf(out->base, sizeof(out->base), "%s://%s%s%s",
             out->tls ? "https" : "http", out->host,
             (strcmp(out->port, out->tls ? "443" : "80") == 0) ? "" : ":",
             (strcmp(out->port, out->tls ? "443" : "80") == 0) ? "" : out->port);
    return true;
}

static int connect_tcp(const char *host, const char *port) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    struct addrinfo *res = NULL;
    int err = getaddrinfo(host, port, &hints, &res);
    if (err != 0) return -1;
    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static bool conn_open(struct app *app, struct tls_conn *conn) {
    memset(conn, 0, sizeof(*conn));
    conn->fd = connect_tcp(app->url.host, app->url.port);
    if (conn->fd < 0) return false;
    conn->tls = app->url.tls;
    if (conn->tls) {
        conn->ssl = SSL_new(app->ssl_ctx);
        if (!conn->ssl) return false;
        SSL_set_fd(conn->ssl, conn->fd);
        SSL_set_tlsext_host_name(conn->ssl, app->url.host);
        /* SNI (above) only NAMES the host in the ClientHello — it does not
         * make OpenSSL verify anything. SSL_VERIFY_PEER (see ssl_ctx setup)
         * validates the certificate CHAIN but NOT that the cert belongs to
         * this host, so without binding the expected name any CA-signed cert
         * for ANY domain passes: an active MITM could present a valid cert
         * for attacker.example and read the bearer token we send on this
         * connection. SSL_set1_host makes the handshake fail on a hostname
         * mismatch — the client twin of the server's #89 hostname check. */
        if (SSL_set1_host(conn->ssl, app->url.host) != 1) return false;
        if (SSL_connect(conn->ssl) != 1) return false;
    }
    return true;
}

static void conn_close(struct tls_conn *conn) {
    if (conn->ssl) {
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
    }
    if (conn->fd >= 0) close(conn->fd);
    memset(conn, 0, sizeof(*conn));
    conn->fd = -1;
}

static ssize_t conn_write(struct tls_conn *conn, const void *buf, size_t len) {
    if (conn->tls) return SSL_write(conn->ssl, buf, (int)len);
    return write(conn->fd, buf, len);
}

static ssize_t conn_read(struct tls_conn *conn, void *buf, size_t len) {
    if (conn->tls) return SSL_read(conn->ssl, buf, (int)len);
    return read(conn->fd, buf, len);
}

static bool conn_write_all(struct tls_conn *conn, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = conn_write(conn, buf + off, len - off);
        if (n <= 0) return false;
        off += (size_t)n;
    }
    return true;
}

static char *read_all(struct tls_conn *conn, size_t *out_len) {
    size_t cap = 8192;
    size_t len = 0;
    char *buf = malloc(cap + 1);
    if (!buf) die("out of memory");
    for (;;) {
        if (len == cap) {
            cap *= 2;
            if (cap > HTTP_MAX) die("HTTP response too large");
            buf = realloc(buf, cap + 1);
            if (!buf) die("out of memory");
        }
        ssize_t n = conn_read(conn, buf + len, cap - len);
        if (n <= 0) break;
        len += (size_t)n;
    }
    buf[len] = 0;
    *out_len = len;
    return buf;
}

/* Generalised request: an explicit content type and an explicit body
 * length, so a body containing NUL bytes (a file upload) survives. The
 * JSON wrapper below is the common case and keeps its old signature. */
static struct http_response http_request_raw(struct app *app, const char *method, const char *path,
                                             const char *body, size_t body_len,
                                             const char *content_type) {
    struct tls_conn conn;
    if (!conn_open(app, &conn)) die("failed to connect to %s:%s", app->url.host, app->url.port);
    char auth[MAX_TOKEN + 64] = "";
    if (app->token[0]) snprintf(auth, sizeof(auth), "Authorization: Bearer %s\r\n", app->token);
    char *head = xasprintf(
        "%s %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: shottino/0.1\r\n"
        "Accept: application/json\r\n"
        "Content-Type: %s\r\n"
        "%s"
        "Connection: close\r\n"
        "Content-Length: %zu\r\n\r\n",
        method, path, app->url.host, content_type, auth, body_len);
    bool ok = conn_write_all(&conn, head, strlen(head));
    free(head);
    /* Body written separately — it is binary and must not go through a
     * format string. */
    if (ok && body_len) ok = conn_write_all(&conn, body, body_len);
    if (!ok) die("HTTP write failed");
    size_t raw_len = 0;
    char *raw = read_all(&conn, &raw_len);
    conn_close(&conn);

    char *sep = strstr(raw, "\r\n\r\n");
    if (!sep) die("bad HTTP response");
    *sep = 0;
    char *statusp = strchr(raw, ' ');
    int status = statusp ? atoi(statusp + 1) : 0;
    char *body_start = sep + 4;
    size_t hdr_len = (size_t)(body_start - raw);
    size_t blen = raw_len >= hdr_len ? raw_len - hdr_len : 0;
    char *payload = NULL;
    size_t payload_len = 0;
    if (strcasestr(raw, "Transfer-Encoding: chunked")) {
        payload = http_decode_chunked(body_start, blen, &payload_len);
        if (!payload) die("out of memory");
    } else {
        payload = malloc(blen + 1);
        if (!payload) die("out of memory");
        memcpy(payload, body_start, blen);
        payload[blen] = 0;
        payload_len = blen;
    }
    free(raw);
    return (struct http_response){ .status = status, .body = payload, .body_len = payload_len };
}

static struct http_response http_request(struct app *app, const char *method, const char *path, const char *body) {
    return http_request_raw(app, method, path, body, body ? strlen(body) : 0, "application/json");
}

/* Read one top-level string out of a small REST response body.
 *
 * Replaces the old `json_find_string`, which searched for a key ANYWHERE
 * in the buffer at ANY depth and decoded `\uXXXX` as a literal '?'. Here
 * the lookup is anchored to the top-level object and the shared reader
 * does the unescaping, so a token containing a non-ASCII character is no
 * longer silently corrupted. */
static bool json_top_string(const char *body, size_t len, const char *key, char *out,
                            size_t out_sz) {
    json_doc *doc = json_parse(body, len, NULL, 0);
    if (!doc) return false;
    const char *s = NULL;
    bool found = json_str_req(json_root(doc), key, &s);
    if (found) snprintf(out, out_sz, "%s", s);
    json_free(doc);
    return found;
}

/* Thin wrapper: parse the body, hand the root to the tested resolver in
 * wire.[ch]. The shape handling lives there so it is covered by tests —
 * this used to read only the ROOT, which broke login (the subject is
 * nested under `subject` there, flat only on /me). */
static void parse_subject(const char *json, size_t len, char *out, size_t out_sz) {
    if (out_sz) out[0] = '\0';
    json_doc *doc = json_parse(json, len, NULL, 0);
    if (!doc) return;
    wire_subject_key(json_root(doc), out, out_sz);
    json_free(doc);
}

static void parse_networks(struct app *app, const char *json, size_t len) {
    app->network_count = 0;
    json_doc *doc = json_parse(json, len, NULL, 0);
    if (!doc) return;
    const json_value *list = json_root(doc);
    for (size_t i = 0; i < json_len(list) && app->network_count < MAX_NETWORKS; i++) {
        const json_value *row = json_at(list, i);
        const char *slug = json_string(json_get(row, "slug"));
        if (!slug || !slug[0]) continue;
        struct network *n = &app->networks[app->network_count];
        memset(n, 0, sizeof(*n));
        long id = 0;
        json_long(json_get(row, "id"), &id);
        n->id = (int)id;
        snprintf(n->slug, sizeof(n->slug), "%s", slug);
        const char *nick = json_string(json_get(row, "nick"));
        if (nick) snprintf(n->nick, sizeof(n->nick), "%s", nick);
        /* The listing carries the DB-canonical connection state; seeding
         * it here means a parked network is greyed from the first frame
         * rather than only after its first state-change event. */
        const char *state = json_string(json_get(row, "connection_state"));
        n->conn_known = true;
        if (state && strcmp(state, "connected") == 0) n->conn_state = CONN_CONNECTED;
        else if (state && strcmp(state, "parked") == 0) n->conn_state = CONN_PARKED;
        else if (state && strcmp(state, "failed") == 0) n->conn_state = CONN_FAILED;
        else n->conn_known = false;
        app->network_count++;
    }
    json_free(doc);
}

static void add_window_ex(struct app *app, const char *network, const char *channel, bool focus) {
    pthread_mutex_lock(&app->lock);
    for (size_t i = 0; i < app->window_count; i++) {
        if (strcmp(app->windows[i].network, network) == 0 && strcmp(app->windows[i].channel, channel) == 0) {
            if (focus) app->current = i;
            pthread_mutex_unlock(&app->lock);
            return;
        }
    }
    if (app->window_count == MAX_WINDOWS) {
        pthread_mutex_unlock(&app->lock);
        return;
    }
    struct window *w = &app->windows[app->window_count++];
    memset(w, 0, sizeof(*w));
    snprintf(w->network, sizeof(w->network), "%s", network);
    snprintf(w->channel, sizeof(w->channel), "%s", channel);
    w->last_id = 0;
    if (focus) app->current = app->window_count - 1;
    pthread_mutex_unlock(&app->lock);
}

static void add_window(struct app *app, const char *network, const char *channel) {
    add_window_ex(app, network, channel, true);
}

static void remove_window(struct app *app, const char *network, const char *channel) {
    pthread_mutex_lock(&app->lock);
    for (size_t i = 0; i < app->window_count; i++) {
        if (strcmp(app->windows[i].network, network) == 0 && strcmp(app->windows[i].channel, channel) == 0) {
            memmove(app->windows + i, app->windows + i + 1, sizeof(app->windows[0]) * (app->window_count - i - 1));
            app->window_count--;
            if (app->window_count == 0) {
                app->current = 0;
            } else if (app->current >= app->window_count) {
                app->current = app->window_count - 1;
            } else if (app->current > i) {
                app->current--;
            }
            if (app->current < app->window_count) app->windows[app->current].unread = 0;
            break;
        }
    }
    pthread_mutex_unlock(&app->lock);
}

static void parse_channels(struct app *app, const char *network, const char *json, size_t len) {
    json_doc *doc = json_parse(json, len, NULL, 0);
    if (!doc) return;
    const json_value *list = json_root(doc);
    for (size_t i = 0; i < json_len(list); i++) {
        const char *name = json_string(json_get(json_at(list, i), "name"));
        if (name && name[0]) add_window(app, network, name);
    }
    json_free(doc);
}

static void enqueue_fetch(struct app *app, const char *network, const char *channel);
static void ws_join(struct app *app, const char *topic);

static const char *network_slug_by_id(struct app *app, int id) {
    for (size_t i = 0; i < app->network_count; i++) {
        if (app->networks[i].id == id) return app->networks[i].slug;
    }
    return NULL;
}

/* Open a DM window per query the server knows about.
 *
 * The payload is a map keyed by NICK whose values are arrays of
 * {network_id, target_nick, opened_at}. The old reader scanned the raw
 * buffer for `"target_nick"` between bracket positions and read the
 * network id by assuming the first digit after a quote belonged to the
 * key — which broke as soon as a nick contained a digit or the encoder
 * reordered keys. The authoritative id lives on each ENTRY, so that is
 * where it is read from now. */
static void apply_query_windows(struct app *app, const struct wire_event *ev) {
    const json_value *windows = ev->u.query_windows.windows;
    for (size_t i = 0; i < ev->u.query_windows.nick_count; i++) {
        const json_value *entries = json_value_at(windows, i);
        for (size_t j = 0; j < json_len(entries); j++) {
            const json_value *entry = json_at(entries, j);
            long network_id = 0;
            const char *nick = NULL;
            if (!json_long_req(entry, "network_id", &network_id)) continue;
            if (!json_str_req(entry, "target_nick", &nick)) continue;
            const char *slug = network_slug_by_id(app, (int)network_id);
            if (!slug || !nick[0]) continue;
            add_window_ex(app, slug, nick, false);
            enqueue_fetch(app, slug, nick);
            if (app->ws_connected) {
                char *topic = xasprintf("grappa:user:%s/network:%s/channel:%s", app->subject, slug, nick);
                ws_join(app, topic);
                free(topic);
            }
        }
    }
}

static void enqueue_read_cursor(struct app *app, const char *network, const char *channel,
                                long message_id);

/* Focus landed on a window: clear its local badge AND tell the server how
 * far we have read, so the cursor follows the user to their other
 * devices. The HTTP write is queued rather than done inline — this runs
 * on the UI thread, holding the app lock, and a blocking POST here would
 * stall every keystroke. */
static void clear_current_unread_locked(struct app *app) {
    if (app->current >= app->window_count) return;
    struct window *w = &app->windows[app->current];
    w->unread = 0;
    w->mentions = 0;
    w->severity = COUNTS_NONE;
    if (w->last_id > w->last_read_id) {
        w->last_read_id = w->last_id;
        enqueue_read_cursor(app, w->network, w->channel, w->last_id);
    }
}

static void clear_active_window_log(struct app *app) {
    pthread_mutex_lock(&app->lock);
    if (app->current >= app->window_count) {
        pthread_mutex_unlock(&app->lock);
        return;
    }
    char key[MAX_SLUG + MAX_CHANNEL + 8];
    snprintf(key, sizeof(key), "[%s/%s]", app->windows[app->current].network, app->windows[app->current].channel);
    size_t write_i = 0;
    for (size_t read_i = 0; read_i < app->log_count; read_i++) {
        if (strncmp(app->log[read_i], key, strlen(key)) == 0) {
            free(app->log[read_i]);
            continue;
        }
        if (write_i != read_i) {
            app->log[write_i] = app->log[read_i];
            app->log_mentions[write_i] = app->log_mentions[read_i];
            app->log_pending[write_i] = app->log_pending[read_i];
            /* These two were missed when the parallel arrays were added:
             * compacting the log without them left the unread divider and
             * the inline images bound to the WRONG rows after a /clear. */
            app->log_ids[write_i] = app->log_ids[read_i];
            app->log_media[write_i] = app->log_media[read_i];
        }
        write_i++;
    }
    app->log_count = write_i;
    app->scrollback_offset = 0;
    app->scrollback_pinned = false;
    clear_current_unread_locked(app);
    pthread_mutex_unlock(&app->lock);
}

static void set_window_members(struct app *app, const char *network, const char *channel, const struct member *members, size_t count) {
    pthread_mutex_lock(&app->lock);
    for (size_t i = 0; i < app->window_count; i++) {
        if (strcmp(app->windows[i].network, network) == 0 && strcmp(app->windows[i].channel, channel) == 0) {
            app->windows[i].member_count = count > 512 ? 512 : count;
            for (size_t j = 0; j < app->windows[i].member_count; j++) app->windows[i].members[j] = members[j];
            break;
        }
    }
    pthread_mutex_unlock(&app->lock);
}

/* Rank a member for roster ordering: ops first, then halfops, voiced,
 * plain. Mode LETTERS come off the wire (o/h/v), not sigils — the sigil is
 * a display concern resolved from the network's ISUPPORT PREFIX map. */
static int member_rank(const char *modes) {
    if (strchr(modes, 'q') || strchr(modes, 'a') || strchr(modes, 'o')) return 0;
    if (strchr(modes, 'h')) return 1;
    if (strchr(modes, 'v')) return 2;
    return 3;
}

/* Sigil for the highest-ranked mode a member holds. Defaults match the
 * near-universal PREFIX=(qaohv)~&@%+ ordering; a network that advertises
 * something else is handled by isupport_prefix below. */
static char member_sigil(struct app *app, const char *network, const char *modes);

static void maybe_mark_unread(struct app *app, const char *network, const char *channel, bool live) {
    if (!live || !network[0] || !channel[0]) return;
    pthread_mutex_lock(&app->lock);
    for (size_t i = 0; i < app->window_count; i++) {
        if (strcmp(app->windows[i].network, network) == 0 && strcmp(app->windows[i].channel, channel) == 0) {
            if (i != app->current || app->panel != PANEL_CHAT) app->windows[i].unread++;
            break;
        }
    }
    pthread_mutex_unlock(&app->lock);
}

static void set_window_topic(struct app *app, const char *network, const char *channel, const char *text) {
    pthread_mutex_lock(&app->lock);
    for (size_t i = 0; i < app->window_count; i++) {
        if (strcmp(app->windows[i].network, network) == 0 && strcmp(app->windows[i].channel, channel) == 0) {
            snprintf(app->windows[i].topic, sizeof(app->windows[i].topic), "%s", text && text[0] ? text : "no topic set");
            break;
        }
    }
    pthread_mutex_unlock(&app->lock);
}

static void remember_url(struct app *app, const char *body);
static const char *find_url(const char *s);
static size_t copy_url_token(const char *url, char *out, size_t out_size);
/* Defined here rather than beside media_kind_of(): the scrollback attach
 * path needs the complete type, and a forward declaration cannot give it
 * a size. */
enum media_kind { MEDIA_NONE = 0, MEDIA_IMAGE, MEDIA_VIDEO };
static enum media_kind media_kind_of(const char *url);
static int media_claim_locked(struct app *app, const char *url, bool is_video);
static bool message_mentions_me(struct app *app, const char *network, const char *sender, const char *body);
static bool nick_case_equal(const char *a, const char *b);
static const char *own_nick_for_network(struct app *app, const char *network);

/* Adapter: classify `url` against this deployment's host set (connect
 * host + server aliases). The classification LOGIC is the tested pure
 * media_url_is_first_party in media.c; this only marshals app state to it
 * (the 2-D alias store into a pointer array). */
static bool url_is_first_party(struct app *app, const char *url) {
    const char *ptrs[MAX_HTTP_ALIASES];
    for (size_t i = 0; i < app->http_host_alias_count; i++)
        ptrs[i] = app->http_host_aliases[i];
    return media_url_is_first_party(url, app->url.host, ptrs, app->http_host_alias_count);
}

/* Render one scrollback row.
 *
 * Presence kinds (join/part/quit/nick_change/mode/kick/topic/server_event)
 * carry a NULL body — the event IS the row. The old reader bailed on an
 * empty body, so shottino showed no joins, parts, quits or nick changes at
 * all; they were parsed and thrown away. Each kind now gets its own line
 * shape, marked with a leading sigil so presence noise is visually
 * separable from conversation. */
static void format_presence_line(wire_message_kind kind, const char *sender, const char *body,
                                 char *out, size_t out_sz) {
    switch (kind) {
    case MSG_JOIN:
        snprintf(out, out_sz, "--> %s has joined", sender);
        break;
    case MSG_PART:
        if (body && body[0]) snprintf(out, out_sz, "<-- %s has left (%s)", sender, body);
        else snprintf(out, out_sz, "<-- %s has left", sender);
        break;
    case MSG_QUIT:
        if (body && body[0]) snprintf(out, out_sz, "<-- %s has quit (%s)", sender, body);
        else snprintf(out, out_sz, "<-- %s has quit", sender);
        break;
    case MSG_NICK_CHANGE:
        snprintf(out, out_sz, "--- %s is now known as %s", sender, body ? body : "?");
        break;
    case MSG_MODE:
        snprintf(out, out_sz, "--- %s sets mode %s", sender, body ? body : "");
        break;
    case MSG_KICK:
        snprintf(out, out_sz, "<-- %s was kicked%s%s", body ? body : "?", sender[0] ? " by " : "",
                 sender[0] ? sender : "");
        break;
    case MSG_TOPIC:
        if (body && body[0]) snprintf(out, out_sz, "--- %s changed the topic to: %s", sender, body);
        else snprintf(out, out_sz, "--- %s cleared the topic", sender);
        break;
    case MSG_SERVER_EVENT:
        snprintf(out, out_sz, "--- %s", body ? body : "");
        break;
    default:
        out[0] = '\0';
        break;
    }
}

static void render_message(struct app *app, const struct wire_scrollback_message *m, bool live) {
    long id = m->id;
    long server_time = m->server_time;
    const char *network = m->network;
    const char *channel = m->channel;
    const char *sender = m->sender ? m->sender : "";
    const char *body = m->body ? m->body : "";

    /* A conversation row with no body is nothing to show; a PRESENCE row
     * with no body is the whole point, so only the former is dropped. */
    bool conversational =
        m->kind == MSG_PRIVMSG || m->kind == MSG_NOTICE || m->kind == MSG_ACTION;
    if (conversational && !body[0]) return;

    char display_channel[MAX_CHANNEL];
    snprintf(display_channel, sizeof(display_channel), "%s", channel);
    const char *own_nick = own_nick_for_network(app, network);
    if (live && own_nick && nick_case_equal(channel, own_nick) && sender[0] && !nick_case_equal(sender, own_nick)) {
        snprintf(display_channel, sizeof(display_channel), "%s", sender);
        add_window_ex(app, network, display_channel, false);
    }

    /* Dedup by ID, BEFORE mutating anything.
     *
     * Every message we send arrives TWICE: once as the POST /messages
     * response (worker thread), once as the `message` wire event
     * (socket). Both carry the same scrollback id, so the id IS the
     * identity — and the check has to come first.
     *
     * The previous order cleared a matching pending echo and only THEN
     * discovered the row was a duplicate, returning without rendering.
     * Because the echo was matched by BODY TEXT, the second delivery of
     * one message deleted the "[sending]" line of a DIFFERENT message
     * that merely said the same thing. Send "ok" twice and the second
     * vanished, reappearing only when some later delivery happened to
     * land — which is exactly "I don't see my message until another one
     * arrives".
     *
     * A duplicate delivery must be inert. */
    if (id > 0 && network[0] && channel[0]) {
        pthread_mutex_lock(&app->lock);
        for (size_t i = 0; i < app->seen_count; i++) {
            if (app->seen[i].id == id && strcmp(app->seen[i].network, network) == 0 && strcmp(app->seen[i].channel, channel) == 0) {
                pthread_mutex_unlock(&app->lock);
                return;
            }
        }
        struct seen_message *seen = &app->seen[app->seen_next];
        seen->id = id;
        snprintf(seen->network, sizeof(seen->network), "%s", network);
        snprintf(seen->channel, sizeof(seen->channel), "%s", channel);
        app->seen_next = (app->seen_next + 1) % SEEN_MESSAGES;
        if (app->seen_count < SEEN_MESSAGES) app->seen_count++;
        pthread_mutex_unlock(&app->lock);
    }

    /* Only now that the row is known to be NEW, retire its optimistic
     * echo. Matching by text is still imprecise when two pending messages
     * say the same thing, but it can no longer delete a line without
     * putting the confirmed one in its place. */
    clear_matching_pending_echo(app, network, display_channel, body);

    pthread_mutex_lock(&app->lock);
    for (size_t i = 0; i < app->window_count; i++) {
        if (network[0] && display_channel[0] && strcmp(app->windows[i].network, network) == 0 && strcmp(app->windows[i].channel, display_channel) == 0 && id > app->windows[i].last_id) app->windows[i].last_id = id;
    }
    pthread_mutex_unlock(&app->lock);
    remember_url(app, body);
    /* Presence rows are ambient: they must not bump the unread badge or
     * they drown the count that signals someone actually spoke. */
    if (conversational) maybe_mark_unread(app, network, display_channel, live);
    bool mention = conversational && message_mentions_me(app, network, sender, body);
    char clock[16];
    time_t ts = server_time > 100000000000L ? (time_t)(server_time / 1000) : time(NULL);
    struct tm tm;
    localtime_r(&ts, &tm);
    strftime(clock, sizeof(clock), "%H:%M", &tm);
    switch (m->kind) {
    case MSG_ACTION:
        log_line_mention(app, mention, "[%s/%s] %s * %s %s", network, display_channel, clock, sender, body);
        break;
    case MSG_NOTICE:
        log_line_mention(app, mention, "[%s/%s] %s -%s- %s", network, display_channel, clock, sender, body);
        break;
    case MSG_PRIVMSG:
        log_line_mention(app, mention, "[%s/%s] %s <%s> %s", network, display_channel, clock, sender, body);
        break;
    default: {
        char line[MAX_LINE];
        format_presence_line(m->kind, sender, m->body, line, sizeof(line));
        if (line[0]) log_line_mention(app, false, "[%s/%s] %s %s", network, display_channel, clock, line);
        break;
    }
    }

    pthread_mutex_lock(&app->lock);
    /* Stamp the row just appended with its scrollback id, so the unread
     * divider lands on the exact row the server's cursor names rather
     * than being guessed from position. */
    if (app->log_count > 0) app->log_ids[app->log_count - 1] = id;
    /* Attach an image slot when the row carries one. Claiming is cheap —
     * DECODING is deferred until the row is actually on screen. */
    if (app->log_count > 0 && conversational) {
        const char *u = find_url(body);
        if (u) {
            char tok[MAX_LINE];
            copy_url_token(u, tok, sizeof(tok));
            enum media_kind mk = media_kind_of(tok);
            /* #451: auto-render inline ONLY for first-party /uploads/
             * links — grappa's own store (host in {connect host} ∪ the
             * server alias set, the same rule as cic's mediaLink.ts).
             * Every other peer http(s) URL stays click-to-preview: no
             * automatic ffmpeg fetch on scroll (the H1 fix). */
            if (mk != MEDIA_NONE && url_is_first_party(app, tok))
                app->log_media[app->log_count - 1] =
                    media_claim_locked(app, tok, mk == MEDIA_VIDEO);
        }
    }
    if (!app->scrollback_pinned) app->scrollback_offset = 0;
    pthread_mutex_unlock(&app->lock);
}

static const char *find_url(const char *s) {
    const char *http = strstr(s, "http://");
    const char *https = strstr(s, "https://");
    if (!http) return https;
    if (!https) return http;
    return http < https ? http : https;
}

/* Copy the leading non-whitespace token of `url` into `out` (case preserved).
 * Returns the token length. Shared by URL remembering, link-region recording,
 * and the lowercasing classifier so the token-boundary rule stays in one place. */
static size_t copy_url_token(const char *url, char *out, size_t out_size) {
    size_t n = 0;
    while (url[n] && !isspace((unsigned char)url[n]) && n + 1 < out_size) {
        out[n] = url[n];
        n++;
    }
    out[n] = 0;
    return n;
}

/* Lowercased copy of the leading URL token with any `?query` stripped, so
 * extension matching ignores case and `?sig=...` suffixes. */
static void url_token_lower(const char *url, char *out, size_t out_size) {
    copy_url_token(url, out, out_size);
    for (char *p = out; *p; p++) *p = (char)tolower((unsigned char)*p);
    char *q = strchr(out, '?');
    if (q) *q = 0;
}

static bool token_has_suffix(const char *token, const char *const *exts) {
    for (size_t i = 0; exts[i]; i++) {
        if (strstr(token, exts[i])) return true;
    }
    return false;
}

/* Classify a URL by extension (and grappa's /uploads/ image convention) in a
 * single lowercasing pass. Video is checked first so an extension wins over the
 * /uploads/ heuristic. */
static enum media_kind media_kind_of(const char *url) {
    static const char *const img[] = {".jpg", ".jpeg", ".png", ".gif",
                                      ".webp", ".bmp", NULL};
    static const char *const vid[] = {".mp4", ".m4v", ".webm", ".mkv", ".mov",
                                      ".avi", ".ogv", ".flv", ".wmv", ".mpg",
                                      ".mpeg", NULL};
    char lower[MAX_LINE];
    url_token_lower(url, lower, sizeof(lower));
    if (token_has_suffix(lower, vid)) return MEDIA_VIDEO;
    if (token_has_suffix(lower, img) || strstr(lower, "/uploads/")) return MEDIA_IMAGE;
    return MEDIA_NONE;
}

static bool contains_ci(const char *haystack, const char *needle) {
    if (!needle || !needle[0]) return false;
    size_t nlen = strlen(needle);
    for (const char *p = haystack; *p; p++) {
        size_t i = 0;
        while (i < nlen && p[i] && tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) i++;
        if (i == nlen) return true;
    }
    return false;
}

static bool nick_case_equal(const char *a, const char *b) {
    return a && b && strcasecmp(a, b) == 0;
}

static bool message_mentions_me(struct app *app, const char *network, const char *sender, const char *body) {
    for (size_t i = 0; i < app->network_count; i++) {
        if (strcmp(app->networks[i].slug, network) == 0 && app->networks[i].nick[0]) {
            if (contains_ci(sender, app->networks[i].nick)) return false;
            return contains_ci(body, app->networks[i].nick);
        }
    }
    const char *colon = strchr(app->subject, ':');
    const char *subject_name = colon ? colon + 1 : app->subject;
    if (contains_ci(sender, subject_name)) return false;
    return contains_ci(body, subject_name);
}

static void remember_url(struct app *app, const char *body) {
    const char *url = find_url(body);
    if (!url) return;
    char token[MAX_LINE];
    copy_url_token(url, token, sizeof(token));
    enum media_kind kind = media_kind_of(token);
    pthread_mutex_lock(&app->lock);
    snprintf(app->last_url, sizeof(app->last_url), "%s", token);
    /* Tracked separately from last_url so `/preview` targets the last
     * IMAGE OR VIDEO rather than whatever link happened to arrive most
     * recently — a plain link after a picture must not shadow it. This is
     * what makes previews reachable without the mouse. */
    if (kind != MEDIA_NONE) {
        snprintf(app->last_media_url, sizeof(app->last_media_url), "%s", token);
        app->last_media_is_video = (kind == MEDIA_VIDEO);
    }
    pthread_mutex_unlock(&app->lock);
}

/* Echo the row POST /messages just created (a single object, not a page). */
static void render_created_message(struct app *app, const char *json, size_t len) {
    char err[160];
    json_doc *doc = json_parse(json, len, err, sizeof(err));
    if (!doc) return;
    struct wire_scrollback_message m;
    if (wire_narrow_message(json_root(doc), &m)) render_message(app, &m, false);
    json_free(doc);
}

/* Ingest a REST scrollback page.
 *
 * Two fixes over the previous reader. It located rows by scanning for
 * `"body"` and then walking BACKWARDS to the nearest `{` — which lands
 * inside `meta` whenever meta is non-empty, and misses any row whose body
 * is null (every join/part/quit). And it appended in buffer order: the
 * endpoint returns DESC (newest first, `Scrollback.fetch/6`), so replayed
 * scrollback rendered upside down. cicchetto reverses on ingestion; this
 * now does the same. */
static void parse_messages(struct app *app, const char *json, size_t len) {
    char err[160];
    json_doc *doc = json_parse(json, len, err, sizeof(err));
    if (!doc) {
        log_line(app, "malformed scrollback response: %s", err);
        return;
    }
    const json_value *list = json_root(doc);
    if (json_type_of(list) != JSON_ARRAY) {
        json_free(doc);
        return;
    }
    size_t n = json_len(list);
    for (size_t i = n; i > 0; i--) {
        struct wire_scrollback_message m;
        if (wire_narrow_message(json_at(list, i - 1), &m)) render_message(app, &m, false);
    }
    json_free(doc);
}

static void draw_fill(int y, int x, int n, int pair) {
    attron(COLOR_PAIR(pair));
    for (int i = 0; i < n; i++) mvaddch(y, x + i, ' ');
    attroff(COLOR_PAIR(pair));
}

static void draw_text(int y, int x, int max, int pair, attr_t attrs, const char *fmt, ...) __attribute__((format(printf, 6, 7)));
static int split_message_line(const char *line, char *prefix, size_t prefix_sz, char *nick, size_t nick_sz, const char **body);

static void draw_text(int y, int x, int max, int pair, attr_t attrs, const char *fmt, ...) {
    if (max <= 0) return;
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    attron(COLOR_PAIR(pair) | attrs);
    mvprintw(y, x, "%.*s", max, buf);
    attroff(COLOR_PAIR(pair) | attrs);
}

static int wrapped_text_lines(const char *s, int width) {
    if (width <= 0) return 0;
    int lines = 1;
    int col = 0;
    for (const char *p = s; *p; p++) {
        if (*p == '\n' || *p == '\r') {
            lines++;
            col = 0;
            if (*p == '\r' && p[1] == '\n') p++;
            continue;
        }
        if (col >= width) {
            lines++;
            col = 0;
        }
        col++;
    }
    return lines;
}

/* Wrapped height of a body, measured on its VISIBLE text.
 *
 * Control bytes occupy no cells, so measuring the raw string over-counts
 * the height of any formatted message — the layout then reserves rows the
 * text does not fill, leaving gaps in the scrollback. Strip first when the
 * body carries formatting; skip the copy when it does not. */
static int wrapped_text_lines_visible(const char *s, int width) {
    if (!mirc_has_formatting(s)) return wrapped_text_lines(s, width);
    char stripped[MAX_LINE * 2];
    mirc_strip(s, stripped, sizeof(stripped));
    return wrapped_text_lines(stripped, width);
}

/* ── mIRC colour → terminal colour ─────────────────────────────────────
 *
 * mIRC's palette is 99 RGB values and \x04 can name any RGB at all;
 * terminals offer 8, 16 or 256 indexed colours. Everything is therefore
 * mapped to the nearest xterm-256 index (or nearest basic-16 on a poorer
 * terminal), which is what every other terminal IRC client does and works
 * without requiring can_change_color().
 *
 * Colour PAIRS are the scarce resource: ncurses wants a pair per (fg, bg)
 * combination and a terminal typically offers 256. They are allocated
 * lazily from a pool above the theme's fixed pairs and cached, so a
 * channel full of colourful bots settles on a small working set instead
 * of exhausting the table on the first screenful. */
#define CP_MIRC_BASE 40

#define MIRC_PAIR_POOL 4096
static struct {
    short fg;
    short bg;
    short pair;
} mirc_pairs[MIRC_PAIR_POOL];
static size_t mirc_pair_count;
static short mirc_pair_next = CP_MIRC_BASE;
static short mirc_pair_limit;

static void mirc_colors_init(void) {
    /* Leave headroom below the cap: exhausting COLOR_PAIRS makes
     * init_pair fail silently and text renders in the last pair set. */
    /* Inline image art needs one pair per (top,bottom) colour pair in the
     * picture, which is far more than coloured TEXT ever asks for. A
     * 256-colour terminal reports COLOR_PAIRS in the tens of thousands, so
     * the old 256 cap was needlessly tight and would have made every
     * image collapse onto the fallback pair after the first few rows. */
    long cap = COLOR_PAIRS > 0 ? COLOR_PAIRS - 1 : 0;
    if (cap > CP_MIRC_BASE + MIRC_PAIR_POOL) cap = CP_MIRC_BASE + MIRC_PAIR_POOL;
    if (cap > 32000) cap = 32000; /* short */
    mirc_pair_limit = (short)cap;
}

/* Quantisation lives in termcolor.[ch]; the choice of WHICH quantiser is
 * a curses-runtime question (COLORS), so it stays here. */
static short mirc_terminal_color(long rgb) {
    if (rgb < 0) return -1;
    return (short)(COLORS >= 256 ? termcolor_xterm256(rgb) : termcolor_basic8(rgb));
}

/* Resolve a run's colour spec to an RGB, or -1 for "inherit". */
static long mirc_run_rgb(int value, bool is_rgb) {
    if (value == MIRC_COLOR_DEFAULT) return -1;
    return is_rgb ? (long)value : mirc_palette_rgb(value);
}

/* A colour pair for (fg, bg), reusing one if already allocated. Returns 0
 * (meaning "use the caller's pair") when the pool is exhausted or the run
 * asks for no colour at all. */
static int mirc_pair_for(long fg_rgb, long bg_rgb, int fallback_pair) {
    if (fg_rgb < 0 && bg_rgb < 0) return fallback_pair;
    if (!has_colors()) return fallback_pair;
    short fg = fg_rgb < 0 ? (short)-1 : mirc_terminal_color(fg_rgb);
    short bg = bg_rgb < 0 ? (short)-1 : mirc_terminal_color(bg_rgb);
    for (size_t i = 0; i < mirc_pair_count; i++)
        if (mirc_pairs[i].fg == fg && mirc_pairs[i].bg == bg) return mirc_pairs[i].pair;
    if (mirc_pair_next >= mirc_pair_limit || mirc_pair_count >= MIRC_PAIR_POOL) return fallback_pair;
    short pair = mirc_pair_next++;
    if (init_pair(pair, fg, bg) == ERR) return fallback_pair;
    mirc_pairs[mirc_pair_count].fg = fg;
    mirc_pairs[mirc_pair_count].bg = bg;
    mirc_pairs[mirc_pair_count].pair = pair;
    mirc_pair_count++;
    return pair;
}

static attr_t mirc_run_attrs(const struct mirc_run *r, attr_t base) {
    attr_t a = base;
    if (r->bold) a |= A_BOLD;
    if (r->underline) a |= A_UNDERLINE;
    if (r->reverse) a |= A_REVERSE;
    /* ncurses has no strikethrough and A_ITALIC is not universal; both
     * degrade to dim rather than being dropped, so the emphasis survives
     * even where the exact style cannot. */
    if (r->italic || r->strikethrough) a |= A_DIM;
    return a;
}

static void draw_wrapped_text(int y, int x, int width, int max_lines, int pair, attr_t attrs, const char *s) {
    if (width <= 0 || max_lines <= 0) return;
    int line = 0;
    int col = 0;

    /* Fast path: the overwhelming majority of messages carry no control
     * bytes, and parsing runs for them would be pure overhead. */
    if (!mirc_has_formatting(s)) {
        attron(COLOR_PAIR(pair) | attrs);
        move(y, x);
        for (const char *p = s; *p && line < max_lines; p++) {
            if (*p == '\r') {
                if (p[1] == '\n') p++;
                line++;
                col = 0;
                if (line < max_lines) move(y + line, x);
                continue;
            }
            if (*p == '\n') {
                line++;
                col = 0;
                if (line < max_lines) move(y + line, x);
                continue;
            }
            if (col >= width) {
                line++;
                col = 0;
                if (line >= max_lines) break;
                move(y + line, x);
            }
            addch((unsigned char)*p);
            col++;
        }
        attroff(COLOR_PAIR(pair) | attrs);
        return;
    }

    struct mirc_run runs[MIRC_MAX_RUNS];
    size_t nruns = mirc_parse(s, runs, MIRC_MAX_RUNS);
    move(y, x);
    for (size_t i = 0; i < nruns && line < max_lines; i++) {
        const struct mirc_run *r = &runs[i];
        long fg = mirc_run_rgb(r->fg, r->fg_is_rgb);
        long bg = mirc_run_rgb(r->bg, r->bg_is_rgb);
        int run_pair = mirc_pair_for(fg, bg, pair);
        attr_t run_attrs = mirc_run_attrs(r, attrs);
        attron(COLOR_PAIR(run_pair) | run_attrs);
        for (size_t k = 0; k < r->len && line < max_lines; k++) {
            char ch = r->text[k];
            if (ch == '\r') {
                if (k + 1 < r->len && r->text[k + 1] == '\n') k++;
                line++;
                col = 0;
                if (line < max_lines) move(y + line, x);
                continue;
            }
            if (ch == '\n') {
                line++;
                col = 0;
                if (line < max_lines) move(y + line, x);
                continue;
            }
            if (col >= width) {
                line++;
                col = 0;
                if (line >= max_lines) break;
                move(y + line, x);
            }
            addch((unsigned char)ch);
            col++;
        }
        attroff(COLOR_PAIR(run_pair) | run_attrs);
    }
}

static int message_display_lines(const char *line, int width) {
    if (width <= 0) return 1;
    char prefix[256], nick[256];
    const char *body;
    if (split_message_line(line, prefix, sizeof(prefix), nick, sizeof(nick), &body)) {
        int body_x = (int)strlen(prefix) + (int)strlen(nick) + 3;
        int body_w = width - body_x;
        if (body_w < 12) body_w = width > 12 ? width - 2 : width;
        return wrapped_text_lines_visible(body, body_w);
    }
    return wrapped_text_lines_visible(line, width);
}

static void draw_message_line(int y, int x, int width, int max_lines, const char *line, bool mention_row, bool pending_row) {
    if (width <= 0 || max_lines <= 0) return;
    for (int row = 0; row < max_lines; row++) {
        if (mention_row) draw_fill(y + row, x, width, CP_MENTION);
    }

    char prefix[256], nick[256];
    const char *body;
    if (split_message_line(line, prefix, sizeof(prefix), nick, sizeof(nick), &body)) {
        int base_pair = mention_row ? CP_MENTION : (pending_row ? CP_MUTED : CP_MUTED);
        int body_pair = mention_row ? CP_MENTION : (pending_row ? CP_MUTED : CP_MAIN);
        attr_t body_attr = mention_row ? A_BOLD : (pending_row ? A_DIM : 0);
        attr_t base_attr = pending_row ? A_DIM : 0;
        draw_text(y, x, width, base_pair, base_attr, "%s", prefix);
        int px = x + (int)strlen(prefix);
        draw_text(y, px, 1, base_pair, base_attr, "<");
        draw_text(y, px + 1, (int)strlen(nick), mention_row ? CP_MENTION : nick_pair(nick), A_BOLD | base_attr, "%s", nick);
        draw_text(y, px + 1 + (int)strlen(nick), 1, base_pair, base_attr, ">");
        int body_x = px + 3 + (int)strlen(nick);
        int body_w = width - (body_x - x);
        if (body_w < 12) {
            body_x = x + 2;
            body_w = width - 2;
        }
        draw_wrapped_text(y, body_x, body_w, max_lines, body_pair, body_attr, body);
        if (pending_row && width > 11) draw_text(y + max_lines - 1, x + width - 11, 11, CP_MUTED, A_DIM, "[sending]");
    } else if (find_url(line)) {
        draw_wrapped_text(y, x, width, max_lines, media_kind_of(find_url(line)) != MEDIA_NONE ? CP_ACCENT : CP_MUTED, A_UNDERLINE, line);
    } else if (strstr(line, "failed") || strstr(line, "error")) {
        draw_wrapped_text(y, x, width, max_lines, CP_ERROR, 0, line);
    } else {
        draw_wrapped_text(y, x, width, max_lines, CP_MUTED, 0, line);
    }
}

static int input_display_lines(const char *prompt, const char *input, int width) {
    if (width <= 0) return 1;
    size_t total = strlen(prompt) + strlen(input);
    int lines = (int)(total / (size_t)width) + 1;
    return lines < 1 ? 1 : lines;
}

static void draw_input_box(int y, int x, int width, int height, const char *prompt, const char *input, int *cursor_y, int *cursor_x) {
    if (width <= 0 || height <= 0) return;
    for (int row = 0; row < height; row++) draw_fill(y + row, x, width, CP_INPUT);
    int inner_x = x + 1;
    int inner_w = width - 2;
    if (inner_w <= 0) inner_w = width;

    char *joined = xasprintf("%s%s", prompt, input);
    int total_lines = input_display_lines(prompt, input, inner_w);
    int first_line = total_lines > height ? total_lines - height : 0;
    int pos = 0;
    int row = 0;
    const int prompt_len = (int)strlen(prompt);
    const int joined_len = (int)strlen(joined);
    while (row < height && pos < joined_len) {
        int line_no = pos / inner_w;
        int take = inner_w - (pos % inner_w);
        if (take > joined_len - pos) take = joined_len - pos;
        if (line_no >= first_line) {
            attron(COLOR_PAIR(CP_INPUT) | A_BOLD);
            for (int i = 0; i < take; i++) {
                if (pos + i == prompt_len) attroff(COLOR_PAIR(CP_INPUT) | A_BOLD), attron(COLOR_PAIR(CP_INPUT));
                mvaddch(y + row, inner_x + (pos % inner_w) + i, (unsigned char)joined[pos + i]);
            }
            attroff(COLOR_PAIR(CP_INPUT) | A_BOLD);
            attroff(COLOR_PAIR(CP_INPUT));
            row++;
        }
        pos += take;
    }
    if (joined_len == 0) draw_text(y, inner_x, inner_w, CP_INPUT, 0, "%s", "");

    int cursor_pos = joined_len;
    int cursor_line = cursor_pos / inner_w;
    int cursor_col = cursor_pos % inner_w;
    if (cursor_line < first_line) {
        cursor_line = first_line;
        cursor_col = 0;
    }
    if (cursor_line - first_line >= height) {
        cursor_line = first_line + height - 1;
        cursor_col = inner_w - 1;
    }
    *cursor_y = y + cursor_line - first_line;
    *cursor_x = inner_x + cursor_col;
    free(joined);
}

static const char *panel_name(enum panel_kind panel) {
    switch (panel) {
    case PANEL_CHAT: return "chat";
    case PANEL_ARCHIVE: return "archive";
    case PANEL_SETTINGS: return "settings";
    case PANEL_ADMIN: return "admin";
    }
    return "chat";
}

/* ── Panels ────────────────────────────────────────────────────────────
 *
 * All three of these used to print a paragraph describing what the panel
 * would eventually show ("This panel shell is wired; ... is the next REST
 * pass"). They read the real endpoints now.
 *
 * Panel population does HTTP, so it must NOT hold app->lock — a blocking
 * request under the lock freezes the whole UI, including the draw thread.
 * Rows are gathered first and installed at the end. */

/* Format a byte count for a table cell. */
static void human_bytes(long bytes, char *out, size_t out_sz) {
    static const char *const unit[] = {"B", "KB", "MB", "GB", "TB"};
    double v = (double)bytes;
    size_t u = 0;
    while (v >= 1024.0 && u + 1 < sizeof(unit) / sizeof(unit[0])) {
        v /= 1024.0;
        u++;
    }
    if (u == 0) snprintf(out, out_sz, "%ld %s", bytes, unit[u]);
    else snprintf(out, out_sz, "%.1f %s", v, unit[u]);
}

/* Format a unix-second or ISO-8601 timestamp for a table cell. */
static void human_time(const json_value *v, char *out, size_t out_sz) {
    long secs = 0;
    if (json_long(v, &secs) && secs > 0) {
        time_t t = secs > 100000000000L ? (time_t)(secs / 1000) : (time_t)secs;
        struct tm tm;
        localtime_r(&t, &tm);
        strftime(out, out_sz, "%Y-%m-%d %H:%M", &tm);
        return;
    }
    const char *s = json_string(v);
    /* ISO-8601 truncated to minutes — the seconds and zone are noise in
     * a fixed-width table. */
    if (s) snprintf(out, out_sz, "%.16s", s);
    else snprintf(out, out_sz, "—");
}

/* GET a path and hand the parsed document to `render`. Centralises the
 * error reporting so a failing tab says WHICH call failed and why rather
 * than rendering as mysteriously empty. */
static void panel_fetch(struct app *app, const char *label, const char *path,
                        void (*render)(struct app *, const json_value *)) {
    struct http_response r = http_request(app, "GET", path, NULL);
    if (r.status < 200 || r.status >= 300) {
        panel_line(app, "  %s: HTTP %d%s%.80s", label, r.status, r.body ? " — " : "",
                   r.body ? r.body : "");
        free(r.body);
        return;
    }
    json_doc *doc = json_parse(r.body, r.body_len, NULL, 0);
    if (!doc) {
        panel_line(app, "  %s: malformed response", label);
        free(r.body);
        return;
    }
    render(app, json_root(doc));
    json_free(doc);
    free(r.body);
}

/* Some admin endpoints answer with a bare array, others with a named
 * envelope. Accept either rather than guessing wrong and showing empty. */
static const json_value *rows_of(const json_value *root, const char *key) {
    if (json_type_of(root) == JSON_ARRAY) return root;
    const json_value *v = json_get(root, key);
    if (json_type_of(v) == JSON_ARRAY) return v;
    v = json_get(root, "data");
    return json_type_of(v) == JSON_ARRAY ? v : NULL;
}

static void render_archive_rows(struct app *app, const json_value *root) {
    const json_value *rows = rows_of(root, "archive");
    size_t n = json_len(rows);
    panel_line(app, "  %-28s %-8s %8s  %s", "TARGET", "KIND", "ROWS", "LAST ACTIVITY");
    for (size_t i = 0; i < n; i++) {
        const json_value *e = json_at(rows, i);
        const char *target = json_string(json_get(e, "target"));
        const char *kind = json_string(json_get(e, "kind"));
        long count = 0;
        json_long(json_get(e, "row_count"), &count);
        char when[32];
        human_time(json_get(e, "last_activity"), when, sizeof(when));
        if (target)
            panel_line(app, "  %-28s %-8s %8ld  %s", target, kind ? kind : "?", count, when);
    }
    if (n == 0) panel_line(app, "  (nothing archived on this network)");
}

static void render_admin_users(struct app *app, const json_value *root) {
    const json_value *rows = rows_of(root, "users");
    size_t n = json_len(rows);
    panel_line(app, "  users (%zu)", n);
    panel_line(app, "    %-24s %-6s %s", "NAME", "ADMIN", "ID");
    for (size_t i = 0; i < n && i < 50; i++) {
        const json_value *e = json_at(rows, i);
        const char *name = json_string(json_get(e, "name"));
        const char *id = json_string(json_get(e, "id"));
        bool is_admin = json_bool(json_get(e, "is_admin"), false);
        if (name)
            panel_line(app, "    %-24s %-6s %.8s", name, is_admin ? "yes" : "no", id ? id : "");
    }
    if (n > 50) panel_line(app, "    ... %zu more", n - 50);
}

static void render_admin_sessions(struct app *app, const json_value *root) {
    const json_value *rows = rows_of(root, "sessions");
    size_t n = json_len(rows);
    panel_line(app, "  sessions (%zu)", n);
    /* DB state and live pid are separate sources of truth and are allowed
     * to disagree; showing both (with an explicit "—" for a missing live
     * state) is the honesty signal that something diverged. */
    panel_line(app, "    %-18s %-16s %-12s %s", "NETWORK", "NICK", "DB STATE", "LIVE");
    for (size_t i = 0; i < n && i < 50; i++) {
        const json_value *e = json_at(rows, i);
        const char *net = json_string(json_get(e, "network_slug"));
        const char *nick = json_string(json_get(e, "nick"));
        const char *db = json_string(json_get(e, "connection_state"));
        const json_value *live = json_get(e, "live_state");
        const char *live_s = json_string(live);
        panel_line(app, "    %-18s %-16s %-12s %s", net ? net : "?", nick ? nick : "?",
                   db ? db : "?", live_s ? live_s : "—");
    }
    if (n > 50) panel_line(app, "    ... %zu more", n - 50);
}

static void render_admin_visitors(struct app *app, const json_value *root) {
    const json_value *rows = rows_of(root, "visitors");
    size_t n = json_len(rows);
    panel_line(app, "  visitors (%zu)", n);
    for (size_t i = 0; i < n && i < 30; i++) {
        const json_value *e = json_at(rows, i);
        const char *nick = json_string(json_get(e, "nick"));
        char when[32];
        human_time(json_get(e, "expires_at"), when, sizeof(when));
        if (nick) panel_line(app, "    %-20s expires %s", nick, when);
    }
    if (n > 30) panel_line(app, "    ... %zu more", n - 30);
}

static void render_admin_uploads(struct app *app, const json_value *root) {
    const json_value *rows = rows_of(root, "uploads");
    size_t n = json_len(rows);
    long total = 0;
    for (size_t i = 0; i < n; i++) {
        long sz = 0;
        json_long(json_get(json_at(rows, i), "byte_size"), &sz);
        total += sz;
    }
    char human[32];
    human_bytes(total, human, sizeof(human));
    panel_line(app, "  uploads (%zu, %s total)", n, human);
}

static void render_admin_networks(struct app *app, const json_value *root) {
    const json_value *rows = rows_of(root, "networks");
    size_t n = json_len(rows);
    panel_line(app, "  networks (%zu)", n);
    panel_line(app, "    %-18s %-8s %s", "SLUG", "ID", "SERVICES");
    for (size_t i = 0; i < n && i < 30; i++) {
        const json_value *e = json_at(rows, i);
        const char *slug = json_string(json_get(e, "slug"));
        long id = 0;
        json_long(json_get(e, "id"), &id);
        const char *flavor = json_string(json_get(e, "services_flavor"));
        if (slug) panel_line(app, "    %-18s %-8ld %s", slug, id, flavor ? flavor : "—");
    }
}

static void render_settings_caps(struct app *app, const json_value *root) {
    const json_value *up = json_get(root, "upload");
    if (!up) up = root;
    const char *host = json_string(json_get(up, "active_host"));
    panel_line(app, "  upload host      %s", host ? host : "—");
    const struct { const char *key; const char *label; } caps[] = {
        {"image_per_file_cap_bytes", "image cap"},
        {"video_per_file_cap_bytes", "video cap"},
        {"document_per_file_cap_bytes", "document cap"},
        {"audio_per_file_cap_bytes", "audio cap"},
        {"global_cap_bytes", "global cap"},
    };
    for (size_t i = 0; i < sizeof(caps) / sizeof(caps[0]); i++) {
        long v = 0;
        if (json_long(json_get(up, caps[i].key), &v)) {
            char human[32];
            human_bytes(v, human, sizeof(human));
            panel_line(app, "  %-16s %s", caps[i].label, human);
        }
    }
}

static void render_notify_rows(struct app *app, const json_value *root) {
    const json_value *rows = rows_of(root, "notify");
    size_t n = json_len(rows);
    panel_line(app, "  watched nicks (%zu)", n);
    for (size_t i = 0; i < n && i < 30; i++) {
        const json_value *e = json_at(rows, i);
        const char *nick = json_string(json_get(e, "nick"));
        const char *presence = json_string(json_get(e, "presence"));
        if (nick) panel_line(app, "    %-20s %s", nick, presence ? presence : "unknown");
    }
    if (n == 0) panel_line(app, "    (none — /notify <nick> to add)");
}

static void open_panel(struct app *app, enum panel_kind panel) {
    /* Snapshot what the fetches need, then release the lock: everything
     * below blocks on HTTP. */
    pthread_mutex_lock(&app->lock);
    clear_panel_lines_locked(app);
    app->panel = panel;
    struct window current = app->windows[app->current];
    size_t window_count = app->window_count;
    size_t alias_count = app->aliases.count;
    /* Snapshot the network table too — the event thread mutates it. */
    struct network nets[MAX_NETWORKS];
    size_t net_count = app->network_count;
    for (size_t i = 0; i < net_count; i++) nets[i] = app->networks[i];
    pthread_mutex_unlock(&app->lock);

    panel_line(app, "%s", panel_name(panel));
    panel_line(app, "%s", "");

    switch (panel) {
    case PANEL_ARCHIVE: {
        panel_line(app, "archive — %s", current.network);
        panel_line(app, "%s", "");
        char *slug = url_encode(current.network);
        char *path = xasprintf("/networks/%s/archive", slug);
        free(slug);
        panel_fetch(app, "archive", path, render_archive_rows);
        free(path);
        panel_line(app, "%s", "");
        panel_line(app, "  /archive open <target>   re-open an archived window");
        panel_line(app, "  /archive purge <target>  delete its scrollback (irreversible)");
        break;
    }

    case PANEL_SETTINGS:
        panel_line(app, "connection");
        panel_line(app, "  server         %s", app->url.base);
        panel_line(app, "  subject        %s", app->subject);
        panel_line(app, "  websocket      %s", app->ws_connected ? "connected" : "reconnecting");
        panel_line(app, "  windows        %zu", window_count);
        panel_line(app, "  aliases        %zu", alias_count);
        panel_line(app, "%s", "");
        panel_line(app, "networks");
        for (size_t i = 0; i < net_count; i++) {
            struct network *n = &nets[i];
            panel_line(app, "  %-16s %-10s nick %s%s%s", n->slug,
                       n->conn_known ? wire_connection_state_name(n->conn_state) : "unknown",
                       n->nick[0] ? n->nick : "—", n->umodes[0] ? " +" : "",
                       n->umodes[0] ? n->umodes : "");
        }
        panel_line(app, "%s", "");
        {
            char *nslug = url_encode(current.network);
            char *npath = xasprintf("/networks/%s/notify", nslug);
            free(nslug);
            panel_fetch(app, "notify", npath, render_notify_rows);
            free(npath);
        }
        panel_line(app, "%s", "");
        panel_line(app, "server settings");
        panel_fetch(app, "settings", "/api/server-settings", render_settings_caps);
        panel_line(app, "%s", "");
        panel_line(app, "keys");
        panel_line(app, "  PgUp/PgDn scroll   End bottom   Ctrl-N/Ctrl-P cycle windows");
        panel_line(app, "  Tab complete       Up/Down history   Esc or /chat returns to chat");
        panel_line(app, "  click a media link to preview it in the terminal");
        break;

    case PANEL_ADMIN:
        panel_line(app, "admin");
        panel_line(app, "%s", "");
        /* Every tab is fetched independently and reports its own failure,
         * so a 403 on one (a non-admin subject, or a resource missing
         * from the proxy allowlist) does not blank the whole panel. */
        panel_fetch(app, "sessions", "/admin/sessions", render_admin_sessions);
        panel_line(app, "%s", "");
        panel_fetch(app, "users", "/admin/users", render_admin_users);
        panel_line(app, "%s", "");
        panel_fetch(app, "networks", "/admin/networks", render_admin_networks);
        panel_line(app, "%s", "");
        panel_fetch(app, "visitors", "/admin/visitors", render_admin_visitors);
        panel_line(app, "%s", "");
        panel_fetch(app, "uploads", "/admin/uploads", render_admin_uploads);
        break;

    case PANEL_CHAT:
        break;
    }
}

static int split_message_line(const char *line, char *prefix, size_t prefix_sz, char *nick, size_t nick_sz, const char **body) {
    const char *visible = line;
    if (*visible == '[') {
        const char *end = strchr(visible, ']');
        if (end && end[1] == ' ') visible = end + 2;
    }
    const char *lt = strchr(visible, '<');
    const char *gt = lt ? strchr(lt, '>') : NULL;
    if (!lt || !gt || gt <= lt + 1) {
        prefix[0] = 0;
        nick[0] = 0;
        *body = visible;
        return 0;
    }
    size_t plen = (size_t)(lt - visible);
    if (plen >= prefix_sz) plen = prefix_sz - 1;
    memcpy(prefix, visible, plen);
    prefix[plen] = 0;
    size_t nlen = (size_t)(gt - lt - 1);
    if (nlen >= nick_sz) nlen = nick_sz - 1;
    memcpy(nick, lt + 1, nlen);
    nick[nlen] = 0;
    *body = gt + 1;
    while (**body == ' ') (*body)++;
    return 1;
}

static bool login(struct app *app, const char *identifier, const char *password) {
    char *id = json_escape(identifier);
    char *pw = json_escape(password);
    char *body = xasprintf("{\"identifier\":\"%s\",\"password\":\"%s\"}", id, pw);
    free(id);
    free(pw);
    struct http_response r = http_request(app, "POST", "/auth/login", body);
    free(body);
    if (r.status < 200 || r.status >= 300) {
        fprintf(stderr, "login failed HTTP %d: %s\n", r.status, r.body);
        free(r.body);
        return false;
    }
    if (!json_top_string(r.body, r.body_len, "token", app->token, sizeof(app->token))) die("login response missing token");
    parse_subject(r.body, r.body_len, app->subject, sizeof(app->subject));
    if (!app->subject[0]) die("login response missing subject");
    free(r.body);
    return true;
}

static unsigned long token_key_hash(const char *server, const char *identifier) {
    char *key = xasprintf("%s|%s", server, identifier);
    unsigned long h = djb2(key);
    free(key);
    return h;
}

static char *token_path_for(const char *server, const char *identifier) {
    const char *home = getenv("HOME");
    if (!home || !home[0]) home = ".";
    char *dir = xasprintf("%s/.local", home);
    mkdir(dir, 0700);
    free(dir);
    dir = xasprintf("%s/.local/share", home);
    mkdir(dir, 0700);
    free(dir);
    dir = xasprintf("%s/.local/share/shottino", home);
    mkdir(dir, 0700);
    char *path = xasprintf("%s/%lx.token", dir, token_key_hash(server, identifier));
    free(dir);
    return path;
}

static bool load_saved_token(struct app *app, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return false;
    if (!fgets(app->token, sizeof(app->token), f)) {
        fclose(f);
        return false;
    }
    fclose(f);
    app->token[strcspn(app->token, "\r\n")] = 0;
    return app->token[0] != 0;
}

static void save_token(struct app *app, const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) return;
    chmod(path, 0600);
    fprintf(f, "%s\n", app->token);
    fclose(f);
    chmod(path, 0600);
}

static bool validate_saved_token(struct app *app) {
    struct http_response me = http_request(app, "GET", "/me", NULL);
    bool ok = me.status >= 200 && me.status < 300;
    if (ok) parse_subject(me.body, me.body_len, app->subject, sizeof(app->subject));
    free(me.body);
    return ok && app->subject[0];
}

static bool attach_or_login(struct app *app, const char *identifier, const char *password) {
    char *path = token_path_for(app->url.base, identifier);
    snprintf(app->token_path, sizeof(app->token_path), "%s", path);
    if (load_saved_token(app, path) && validate_saved_token(app)) {
        log_line(app, "reattached saved grappa session as %s", app->subject);
        free(path);
        return true;
    }
    app->token[0] = 0;
    app->subject[0] = 0;
    bool ok = login(app, identifier, password);
    if (ok) save_token(app, path);
    free(path);
    return ok;
}

static char *login_identifier_for_mode(const char *mode, const char *identifier) {
    if (strcmp(mode, "user") == 0 && strchr(identifier, '@') == NULL) {
        return xasprintf("%s@shottino.local", identifier);
    }
    return xasprintf("%s", identifier);
}

// Visitor session-sharing — consume side. Unauthenticated by design: the
// signed token IS the credential. POST /auth/share/consume {token} returns the
// same wire shape as /auth/login ({token, subject}) for the SAME visitor row.
static bool consume_share(struct app *app, const char *share_token) {
    char *t = json_escape(share_token);
    char *body = xasprintf("{\"token\":\"%s\"}", t);
    free(t);
    struct http_response r = http_request(app, "POST", "/auth/share/consume", body);
    free(body);
    if (r.status < 200 || r.status >= 300) {
        fprintf(stderr, "share consume failed HTTP %d: %s\n", r.status, r.body);
        free(r.body);
        return false;
    }
    if (!json_top_string(r.body, r.body_len, "token", app->token, sizeof(app->token))) die("share consume response missing token");
    parse_subject(r.body, r.body_len, app->subject, sizeof(app->subject));
    if (!app->subject[0]) die("share consume response missing subject");
    free(r.body);
    return true;
}

// Mirror of attach_or_login for the share path: reattach a previously consumed
// session if its bearer still validates, else consume the one-shot share token.
// Keyed on a fixed "visitor-share" identifier so a relaunch with the (now
// spent) link reattaches via the saved bearer instead of a doomed re-consume.
static bool attach_or_consume(struct app *app, const char *base, const char *share_token) {
    char *path = token_path_for(base, "visitor-share");
    snprintf(app->token_path, sizeof(app->token_path), "%s", path);
    if (load_saved_token(app, path) && validate_saved_token(app)) {
        log_line(app, "reattached saved grappa session as %s", app->subject);
        free(path);
        return true;
    }
    app->token[0] = 0;
    app->subject[0] = 0;
    bool ok = consume_share(app, share_token);
    if (ok) save_token(app, path);
    free(path);
    return ok;
}

static void logout_grappa(struct app *app) {
    struct http_response r = http_request(app, "DELETE", "/auth/logout", NULL);
    if (r.status == 204 || (r.status >= 200 && r.status < 300)) {
        log_line(app, "grappa session terminated");
        if (app->token_path[0]) unlink(app->token_path);
    } else {
        log_line(app, "logout failed HTTP %d: %.200s", r.status, r.body);
    }
    free(r.body);
}

static void seed_state(struct app *app) {
    struct http_response me = http_request(app, "GET", "/me", NULL);
    if (me.status >= 200 && me.status < 300) log_line(app, "authenticated as %s", app->subject);
    free(me.body);

    struct http_response nets = http_request(app, "GET", "/networks", NULL);
    if (nets.status < 200 || nets.status >= 300) die("GET /networks failed HTTP %d: %s", nets.status, nets.body);
    parse_networks(app, nets.body, nets.body_len);
    free(nets.body);
    if (app->network_count == 0) die("no networks available");

    for (size_t i = 0; i < app->network_count; i++) {
        /* Every network gets a $server window, not just a network with no
         * channels. It is where server replies land — MOTD, LUSERS, WHOIS,
         * LINKS, connection-state transitions — and previously those had
         * nowhere network-scoped to go, so a network with one channel had
         * its server output land in the channel or nowhere at all. */
        add_window_ex(app, app->networks[i].slug, "$server", false);
        char *slug = url_encode(app->networks[i].slug);
        char *path = xasprintf("/networks/%s/channels", slug);
        free(slug);
        struct http_response ch = http_request(app, "GET", path, NULL);
        free(path);
        if (ch.status >= 200 && ch.status < 300) parse_channels(app, app->networks[i].slug, ch.body, ch.body_len);
        free(ch.body);
    }
    /* Land on a real conversation, not on $server.
     *
     * $server is READ-ONLY by server contract — `validate_post_target_name/1`
     * rejects it with :bad_request — so focusing it at startup meant the
     * first thing a user typed came back as a bare "send failed HTTP 400".
     * Prefer the first channel or query; fall back to $server only when
     * there is genuinely nothing else, which is the case it exists for. */
    app->current = 0;
    for (size_t i = 0; i < app->window_count; i++) {
        if (strcmp(app->windows[i].channel, "$server") != 0) {
            app->current = i;
            break;
        }
    }
}

static void fetch_scrollback(struct app *app, struct window *w) {
    char *net = url_encode(w->network);
    char *chan = url_encode(w->channel);
    char *path = xasprintf("/networks/%s/channels/%s/messages?limit=80", net, chan);
    free(net);
    free(chan);
    struct http_response r = http_request(app, "GET", path, NULL);
    free(path);
    if (r.status >= 200 && r.status < 300) parse_messages(app, r.body, r.body_len);
    else log_line(app, "GET messages failed HTTP %d", r.status);
    free(r.body);
}

static void fetch_scrollback_target(struct app *app, const char *network, const char *channel) {
    char *net = url_encode(network);
    char *chan = url_encode(channel);
    char *path = xasprintf("/networks/%s/channels/%s/messages?limit=80", net, chan);
    free(net);
    free(chan);
    struct http_response r = http_request(app, "GET", path, NULL);
    free(path);
    if (r.status >= 200 && r.status < 300) parse_messages(app, r.body, r.body_len);
    else log_line(app, "GET messages failed HTTP %d", r.status);
    free(r.body);
}

static char *base64_encode(const unsigned char *buf, size_t len) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);
    BIO_write(b64, buf, (int)len);
    BIO_flush(b64);
    BUF_MEM *bptr = NULL;
    BIO_get_mem_ptr(mem, &bptr);
    char *out = malloc(bptr->length + 1);
    if (!out) die("out of memory");
    memcpy(out, bptr->data, bptr->length);
    out[bptr->length] = 0;
    BIO_free_all(b64);
    return out;
}

/* base64url (RFC 4648 §5): standard base64 with `-`/`_` substituted for
 * `+`/`/` and the `=` padding stripped. Phoenix's websocket transport
 * expects the bearer in exactly this form, and phoenix.js builds it the
 * same way (btoa, the two substitutions, then strip padding). */
static char *base64url_encode(const unsigned char *buf, size_t len) {
    char *b64 = base64_encode(buf, len);
    for (char *p = b64; *p; p++) {
        if (*p == '+') *p = '-';
        else if (*p == '/') *p = '_';
    }
    size_t n = strlen(b64);
    while (n > 0 && b64[n - 1] == '=') b64[--n] = '\0';
    return b64;
}

static bool ws_connect(struct app *app) {
    if (!conn_open(app, &app->ws)) return false;
    unsigned char nonce[16];
    RAND_bytes(nonce, sizeof(nonce));
    char *key = base64_encode(nonce, sizeof(nonce));

    /* The bearer rides the Sec-WebSocket-Protocol SUBPROTOCOL, never the
     * upgrade URL.
     *
     * #95 introduced this path — a `?token=…` query string is visible in
     * nginx access logs before redaction — and kept the query-string
     * bearer as a fallback. #202 (2026-07-19) DROPPED that fallback:
     * `UserSocket.connect/3` now reads the token ONLY from
     * `connect_info.auth_token`, which Phoenix decodes from
     * `base64url.bearer.phx.<base64url(token)>`.
     *
     * Shottino was still sending `?token=…` with no subprotocol, so every
     * handshake since #202 landed was rejected before it reached the
     * channel. That is what "websocket unavailable" was reporting. */
    char *tok_b64 = base64url_encode((const unsigned char *)app->token, strlen(app->token));
    char *req = xasprintf(
        "GET /socket/websocket?vsn=2.0.0 HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Protocol: base64url.bearer.phx.%s\r\n"
        "User-Agent: shottino/0.1\r\n\r\n",
        app->url.host, key, tok_b64);
    free(tok_b64);
    free(key);
    if (!conn_write_all(&app->ws, req, strlen(req))) {
        free(req);
        return false;
    }
    free(req);
    char hdr[4096];
    size_t len = 0;
    while (len + 1 < sizeof(hdr)) {
        char c;
        ssize_t n = conn_read(&app->ws, &c, 1);
        if (n <= 0) {
            log_line(app, "websocket handshake: connection closed before a reply");
            return false;
        }
        hdr[len++] = c;
        hdr[len] = 0;
        if (strstr(hdr, "\r\n\r\n")) break;
    }
    if (!strstr(hdr, " 101 ")) {
        /* Report WHAT the server said. "websocket unavailable" with no
         * status is what made this bug take a server-side code read to
         * diagnose: a 403 (bad/expired bearer) and a 404 (wrong path, or
         * a proxy not forwarding /socket) are entirely different repairs
         * and looked identical from here. */
        char status[128] = "";
        const char *eol = strstr(hdr, "\r\n");
        size_t status_len = eol ? (size_t)(eol - hdr) : len;
        if (status_len >= sizeof(status)) status_len = sizeof(status) - 1;
        memcpy(status, hdr, status_len);
        status[status_len] = '\0';
        log_line(app, "websocket handshake rejected: %s", status[0] ? status : "(no status line)");
        return false;
    }
    int flags = fcntl(app->ws.fd, F_GETFL, 0);
    fcntl(app->ws.fd, F_SETFL, flags | O_NONBLOCK);
    app->ws_connected = true;
    app->next_heartbeat = time(NULL) + 25;
    return true;
}

static bool ws_send_text(struct app *app, const char *text) {
    if (!app->ws_connected) return false;
    size_t len = strlen(text);
    unsigned char hdr[14];
    size_t hlen = 0;
    hdr[hlen++] = 0x81;
    if (len < 126) {
        hdr[hlen++] = 0x80 | (unsigned char)len;
    } else if (len <= 65535) {
        hdr[hlen++] = 0x80 | 126;
        hdr[hlen++] = (unsigned char)(len >> 8);
        hdr[hlen++] = (unsigned char)len;
    } else {
        hdr[hlen++] = 0x80 | 127;
        for (int i = 7; i >= 0; i--) hdr[hlen++] = (unsigned char)(len >> (i * 8));
    }
    unsigned char mask[4];
    RAND_bytes(mask, sizeof(mask));
    memcpy(hdr + hlen, mask, 4);
    hlen += 4;
    unsigned char *frame = malloc(hlen + len);
    if (!frame) die("out of memory");
    memcpy(frame, hdr, hlen);
    for (size_t i = 0; i < len; i++) frame[hlen + i] = ((const unsigned char *)text)[i] ^ mask[i % 4];
    bool ok = conn_write_all(&app->ws, (const char *)frame, hlen + len);
    free(frame);
    return ok;
}

static void ws_join(struct app *app, const char *topic) {
    char ref[32];
    snprintf(ref, sizeof(ref), "%lu", ++app->ws_ref);
    char *topic_json = json_escape(topic);
    char *frame = xasprintf("[\"%s\",\"%s\",\"%s\",\"phx_join\",{}]", ref, ref, topic_json);
    free(topic_json);
    ws_send_text(app, frame);
    free(frame);
}

static void ws_push_user(struct app *app, const char *event, const char *payload) {
    if (!app->ws_connected) {
        log_line(app, "websocket is not connected; /%s not sent", event);
        return;
    }
    char ref[32];
    snprintf(ref, sizeof(ref), "%lu", ++app->ws_ref);
    char *topic = xasprintf("grappa:user:%s", app->subject);
    char *topic_json = json_escape(topic);
    char *event_json = json_escape(event);
    char *frame = xasprintf("[\"%s\",\"%s\",\"%s\",\"%s\",%s]", ref, ref, topic_json, event_json, payload);
    free(topic);
    free(topic_json);
    free(event_json);
    ws_send_text(app, frame);
    free(frame);
}

static int current_network_id(struct app *app) {
    const char *slug = app->windows[app->current].network;
    for (size_t i = 0; i < app->network_count; i++) {
        if (strcmp(app->networks[i].slug, slug) == 0) return app->networks[i].id;
    }
    return app->network_count > 0 ? app->networks[0].id : 0;
}

static const char *current_channel(struct app *app) {
    return app->windows[app->current].channel;
}

static void ws_join_topics(struct app *app) {
    char *subject = json_escape(app->subject);
    char *topic = xasprintf("grappa:user:%s", subject);
    free(subject);
    ws_join(app, topic);
    free(topic);
    for (size_t i = 0; i < app->window_count; i++) {
        char *chan = json_escape(app->windows[i].channel);
        char *net = json_escape(app->windows[i].network);
        char *t = xasprintf("grappa:user:%s/network:%s/channel:%s", app->subject, net, chan);
        free(chan);
        free(net);
        ws_join(app, t);
        app->windows[i].joined_ws = true;
        free(t);
    }
}

static int ws_read_frame(struct app *app, char **out) {
    unsigned char h[2];
    ssize_t n = conn_read(&app->ws, h, 2);
    if (n < 0) {
        int e = app->ws.tls ? SSL_get_error(app->ws.ssl, (int)n) : 0;
        if ((!app->ws.tls && (errno == EAGAIN || errno == EWOULDBLOCK)) || e == SSL_ERROR_WANT_READ) return 0;
        return -1;
    }
    if (n == 0) return -1;
    if (n != 2) return 0;
    int opcode = h[0] & 0x0f;
    bool masked = (h[1] & 0x80) != 0;
    uint64_t len = h[1] & 0x7f;
    if (len == 126) {
        unsigned char x[2];
        if (conn_read(&app->ws, x, 2) != 2) return 0;
        len = ((uint64_t)x[0] << 8) | x[1];
    } else if (len == 127) {
        unsigned char x[8];
        if (conn_read(&app->ws, x, 8) != 8) return 0;
        len = 0;
        for (int i = 0; i < 8; i++) len = (len << 8) | x[i];
    }
    if (len > WS_MAX_PAYLOAD) return -1;
    unsigned char mask[4] = {0};
    if (masked && conn_read(&app->ws, mask, 4) != 4) return 0;
    char *payload = malloc((size_t)len + 1);
    if (!payload) die("out of memory");
    size_t off = 0;
    while (off < len) {
        ssize_t r = conn_read(&app->ws, payload + off, (size_t)len - off);
        if (r <= 0) {
            free(payload);
            return 0;
        }
        off += (size_t)r;
    }
    for (size_t i = 0; masked && i < len; i++) payload[i] ^= mask[i % 4];
    payload[len] = 0;
    if (opcode == 0x8) {
        free(payload);
        return -1;
    }
    if (opcode == 0x9) {
        free(payload);
        return 0;
    }
    if (opcode != 0x1) {
        free(payload);
        return 0;
    }
    *out = payload;
    return 1;
}

/* ── Typed wire-event handling ─────────────────────────────────────────
 *
 * One narrow, one dispatch. Every arm receives a fully-validated event, so
 * no handler re-reads the raw frame and none can half-apply a malformed
 * payload. A kind shottino does not consume falls through silently: a
 * version-skewed server WILL push events this build has never heard of,
 * and that is not an error worth a line in the user's chat buffer. */

static struct network *network_by_slug_locked(struct app *app, const char *slug) {
    for (size_t i = 0; i < app->network_count; i++)
        if (strcmp(app->networks[i].slug, slug) == 0) return &app->networks[i];
    return NULL;
}

static struct network *network_by_id_locked(struct app *app, long id) {
    for (size_t i = 0; i < app->network_count; i++)
        if (app->networks[i].id == (int)id) return &app->networks[i];
    return NULL;
}

/* Caller holds app->lock. The draw path is already inside the lock, so
 * the locking wrapper below would self-deadlock there — hence the split. */
static char member_sigil_locked(struct app *app, const char *network, const char *modes) {
    /* Conventional fallback, used until the network sends its 005. */
    static const char fallback_letters[] = "qaohv";
    static const char fallback_sigils[] = "~&@%+";
    struct network *n = network_by_slug_locked(app, network);
    if (n && n->prefix_count) {
        for (size_t i = 0; i < n->prefix_count; i++)
            if (strchr(modes, n->prefix_letters[i])) return n->prefix_sigils[i];
        return 0;
    }
    for (size_t i = 0; fallback_letters[i]; i++)
        if (strchr(modes, fallback_letters[i])) return fallback_sigils[i];
    return 0;
}

static char member_sigil(struct app *app, const char *network, const char *modes) {
    pthread_mutex_lock(&app->lock);
    char sigil = member_sigil_locked(app, network, modes);
    pthread_mutex_unlock(&app->lock);
    return sigil;
}

static void set_window_state(struct app *app, const char *network, const char *channel,
                            enum window_state state, const char *detail, long numeric) {
    pthread_mutex_lock(&app->lock);
    for (size_t i = 0; i < app->window_count; i++) {
        if (strcmp(app->windows[i].network, network) == 0 &&
            strcmp(app->windows[i].channel, channel) == 0) {
            app->windows[i].state = state;
            snprintf(app->windows[i].state_detail, sizeof(app->windows[i].state_detail), "%s",
                     detail ? detail : "");
            app->windows[i].failure_numeric = numeric;
            break;
        }
    }
    pthread_mutex_unlock(&app->lock);
}

static void copy_members_from_wire(struct app *app, const char *network, const char *channel,
                                   const json_value *list, size_t count) {
    /* Zero-init: wire_member_at cannot fail on a narrowed event today, but if
     * it ever did, the `continue` below would leave members[i] as uninitialised
     * stack that set_window_members still copies (interior hole -> a nick made
     * of stack garbage). One line closes that narrower/accessor coupling. */
    struct member members[512] = {0};
    size_t n = count > 512 ? 512 : count;
    for (size_t i = 0; i < n; i++) {
        struct wire_member wm;
        if (!wire_member_at(list, i, &wm)) continue;
        snprintf(members[i].nick, sizeof(members[i].nick), "%s", wm.nick);
        members[i].modes[0] = '\0';
        for (size_t j = 0, w = 0; j < wm.mode_count && w + 1 < sizeof(members[i].modes); j++) {
            const char *mode = wire_string_at(wm.modes, j);
            if (mode && mode[0]) {
                members[i].modes[w++] = mode[0];
                members[i].modes[w] = '\0';
            }
        }
    }
    set_window_members(app, network, channel, members, n);
}

/* ── Reply cards ───────────────────────────────────────────────────────
 *
 * Every one of these is a reply to something the user typed. Shottino
 * pushed the request upstream and then dropped the bundle that came back,
 * so /whois, /who, /names, /lusers, /banlist, /links, /motd, /info and
 * /version were all write-only verbs: they did something on the server and
 * showed the user nothing.
 *
 * They render into the $server window of the network that answered, which
 * is where a terminal client conventionally puts server output — and,
 * unlike the global log, keeps one network's MOTD out of another's.
 */

/* One card row, scoped to a network's $server window. */
static void card(struct app *app, const char *network, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void card(struct app *app, const char *network, const char *fmt, ...) {
    char body[MAX_LINE];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);
    log_line(app, "[%s/$server] %s", network, body);
}

/* Skip a NULL/empty field rather than printing "(null)" or a blank row —
 * a WHOIS against a hidden user is mostly empty and should read as short,
 * not as a wall of dashes. */
static void card_field(struct app *app, const char *network, const char *label, const char *value) {
    if (value && value[0]) card(app, network, "  %-12s %s", label, value);
}

static void render_whois(struct app *app, const struct wire_event *ev) {
    const char *net = ev->u.whois.network;
    card(app, net, "--- WHOIS %s", ev->u.whois.target);
    if (ev->u.whois.user || ev->u.whois.host) {
        card(app, net, "  %-12s %s@%s", "user", ev->u.whois.user ? ev->u.whois.user : "?",
             ev->u.whois.host ? ev->u.whois.host : "?");
    }
    card_field(app, net, "realname", ev->u.whois.realname);
    card_field(app, net, "account", ev->u.whois.account);
    if (ev->u.whois.server) {
        card(app, net, "  %-12s %s%s%s", "server", ev->u.whois.server,
             ev->u.whois.server_info ? " — " : "",
             ev->u.whois.server_info ? ev->u.whois.server_info : "");
    }
    card_field(app, net, "modes", ev->u.whois.umodes);
    card_field(app, net, "away", ev->u.whois.away_message);
    card_field(app, net, "actually", ev->u.whois.actually_host);
    card_field(app, net, "ip", ev->u.whois.actually_ip);

    if (ev->u.whois.has_idle) {
        long s = ev->u.whois.idle_seconds;
        card(app, net, "  %-12s %ldh %ldm %lds", "idle", s / 3600, (s % 3600) / 60, s % 60);
    }
    if (ev->u.whois.has_signon) {
        time_t t = (time_t)ev->u.whois.signon;
        struct tm tm;
        char when[64];
        localtime_r(&t, &tm);
        strftime(when, sizeof(when), "%Y-%m-%d %H:%M", &tm);
        card(app, net, "  %-12s %s", "signon", when);
    }

    /* Flags collapse onto one line — nine separate "yes" rows would bury
     * the fields that carry actual information. */
    char flags[256] = "";
    size_t w = 0;
    const struct { bool on; const char *name; } flag_list[] = {
        {ev->u.whois.is_operator, "operator"},
        {ev->u.whois.is_admin, "admin"},
        {ev->u.whois.is_services_admin, "services-admin"},
        {ev->u.whois.is_helper, "helper"},
        {ev->u.whois.is_chanop, "chanop"},
        {ev->u.whois.is_registered, "registered"},
        {ev->u.whois.using_ssl || ev->u.whois.secure, "secure"},
        {ev->u.whois.is_agent, "agent"},
        {ev->u.whois.is_java, "java"},
    };
    for (size_t i = 0; i < sizeof(flag_list) / sizeof(flag_list[0]); i++) {
        if (!flag_list[i].on) continue;
        int n = snprintf(flags + w, sizeof(flags) - w, "%s%s", w ? ", " : "", flag_list[i].name);
        if (n > 0 && (size_t)n < sizeof(flags) - w) w += (size_t)n;
    }
    card_field(app, net, "flags", flags);
    card_field(app, net, "oper", ev->u.whois.oper_text);
    card_field(app, net, "cipher", ev->u.whois.secure_cipher);
    card_field(app, net, "certfp", ev->u.whois.certfp);

    if (ev->u.whois.has_channels && ev->u.whois.channel_count) {
        /* Channels wrap across rows instead of one row each — an active
         * user is in dozens and would otherwise fill the buffer. */
        char line[MAX_LINE] = "";
        size_t lw = 0;
        bool first_row = true;
        for (size_t i = 0; i < ev->u.whois.channel_count; i++) {
            const char *ch = wire_string_at(ev->u.whois.channels, i);
            if (!ch) continue;
            if (lw && lw + strlen(ch) + 1 >= 68) {
                /* Only the first row carries the label; continuation rows
                 * align under it so the block reads as one field. */
                card(app, net, "  %-12s %s", first_row ? "channels" : "", line);
                first_row = false;
                line[0] = '\0';
                lw = 0;
            }
            int n = snprintf(line + lw, sizeof(line) - lw, "%s%s", lw ? " " : "", ch);
            if (n > 0 && (size_t)n < sizeof(line) - lw) lw += (size_t)n;
        }
        if (lw) card(app, net, "  %-12s %s", first_row ? "channels" : "", line);
    }
    for (size_t i = 0; i < ev->u.whois.extra_count; i++) {
        struct wire_whois_extra x;
        if (wire_whois_extra_at(ev->u.whois.extra_lines, i, &x))
            card(app, net, "  %-12s %s", "", x.text);
    }
}

static void render_whowas(struct app *app, const struct wire_event *ev) {
    const char *net = ev->u.whowas.network;
    if (ev->u.whowas.not_found) {
        card(app, net, "--- WHOWAS %s: no such nick in history", ev->u.whowas.target);
        return;
    }
    card(app, net, "--- WHOWAS %s", ev->u.whowas.target);
    if (ev->u.whowas.user || ev->u.whowas.host)
        card(app, net, "  %-12s %s@%s", "user", ev->u.whowas.user ? ev->u.whowas.user : "?",
             ev->u.whowas.host ? ev->u.whowas.host : "?");
    card_field(app, net, "realname", ev->u.whowas.realname);
    card_field(app, net, "server", ev->u.whowas.server);
    card_field(app, net, "last seen", ev->u.whowas.logoff_time);
}

static void render_who(struct app *app, const struct wire_event *ev) {
    const char *net = ev->u.who_reply.network;
    card(app, net, "--- WHO %s (%zu)", ev->u.who_reply.target, ev->u.who_reply.user_count);
    for (size_t i = 0; i < ev->u.who_reply.user_count; i++) {
        struct wire_who_user u;
        if (!wire_who_user_at(ev->u.who_reply.users, i, &u)) continue;
        card(app, net, "  %-16s %-4s %s@%s%s%s", u.nick, u.modes ? u.modes : "",
             u.user ? u.user : "?", u.host ? u.host : "?", u.realname ? " — " : "",
             u.realname ? u.realname : "");
    }
    if (ev->u.who_reply.user_count == 0) card(app, net, "  (no matches)");
}

static void render_names(struct app *app, const struct wire_event *ev) {
    const char *net = ev->u.names_reply.network;
    card(app, net, "--- NAMES %s (%zu)", ev->u.names_reply.channel,
         ev->u.names_reply.member_count);
    /* Wrapped columns, sigils resolved from this network's PREFIX. */
    char line[MAX_LINE] = "";
    size_t lw = 0;
    for (size_t i = 0; i < ev->u.names_reply.member_count; i++) {
        struct wire_member m;
        if (!wire_member_at(ev->u.names_reply.members, i, &m)) continue;
        char modes[8] = "";
        for (size_t j = 0, w = 0; j < m.mode_count && w + 1 < sizeof(modes); j++) {
            const char *mode = wire_string_at(m.modes, j);
            if (mode && mode[0]) { modes[w++] = mode[0]; modes[w] = '\0'; }
        }
        char sigil = member_sigil(app, net, modes);
        char entry[MAX_CHANNEL + 2];
        snprintf(entry, sizeof(entry), "%c%s", sigil ? sigil : ' ', m.nick);
        if (lw && lw + strlen(entry) + 1 >= 70) {
            card(app, net, "  %s", line);
            line[0] = '\0';
            lw = 0;
        }
        int n = snprintf(line + lw, sizeof(line) - lw, "%s%s", lw ? " " : "", entry);
        if (n > 0 && (size_t)n < sizeof(line) - lw) lw += (size_t)n;
    }
    if (lw) card(app, net, "  %s", line);
    /* NAMES doubles as a roster refresh for the channel's member pane. */
    copy_members_from_wire(app, net, ev->u.names_reply.channel, ev->u.names_reply.members,
                           ev->u.names_reply.member_count);
}

static void render_lusers(struct app *app, const struct wire_event *ev) {
    const char *net = ev->u.lusers.network;
    card(app, net, "--- LUSERS");
    const struct { int idx; const char *label; long value; } rows[] = {
        {LUSERS_TOTAL_USERS, "users", ev->u.lusers.total_users},
        {LUSERS_INVISIBLE, "invisible", ev->u.lusers.invisible},
        {LUSERS_OPERATORS, "operators", ev->u.lusers.operators},
        {LUSERS_SERVERS, "servers", ev->u.lusers.servers},
        {LUSERS_UNKNOWN_CONNECTIONS, "unknown", ev->u.lusers.unknown_connections},
        {LUSERS_CHANNELS_FORMED, "channels", ev->u.lusers.channels_formed},
        {LUSERS_LOCAL_CLIENTS, "local", ev->u.lusers.local_clients},
        {LUSERS_LOCAL_SERVERS, "local srv", ev->u.lusers.local_servers},
        {LUSERS_CURRENT_LOCAL, "cur local", ev->u.lusers.current_local},
        {LUSERS_MAX_LOCAL, "max local", ev->u.lusers.max_local},
        {LUSERS_CURRENT_GLOBAL, "cur global", ev->u.lusers.current_global},
        {LUSERS_MAX_GLOBAL, "max global", ev->u.lusers.max_global},
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        /* An absent count renders as an em dash rather than 0 — "we were
         * not told" and "there are none" are different facts. */
        if (ev->u.lusers.has[rows[i].idx]) card(app, net, "  %-12s %ld", rows[i].label, rows[i].value);
        else card(app, net, "  %-12s —", rows[i].label);
    }
}

static void render_banlist(struct app *app, const struct wire_event *ev) {
    const char *net = ev->u.banlist.network;
    card(app, net, "--- BANLIST %s (%zu)", ev->u.banlist.channel, ev->u.banlist.entry_count);
    for (size_t i = 0; i < ev->u.banlist.entry_count; i++) {
        struct wire_banlist_entry b;
        if (!wire_banlist_entry_at(ev->u.banlist.entries, i, &b)) continue;
        char when[64] = "";
        if (b.set_ts) {
            /* set_ts is a unix-second STRING on the wire. */
            time_t t = (time_t)strtol(b.set_ts, NULL, 10);
            if (t > 0) {
                struct tm tm;
                localtime_r(&t, &tm);
                strftime(when, sizeof(when), "%Y-%m-%d", &tm);
            }
        }
        card(app, net, "  %-32s %s%s%s", b.mask, b.setter ? b.setter : "?", when[0] ? " " : "",
             when);
    }
    if (ev->u.banlist.entry_count == 0) card(app, net, "  (no bans set)");
}

static void render_links(struct app *app, const struct wire_event *ev) {
    const char *net = ev->u.links.network;
    card(app, net, "--- LINKS (%zu)", ev->u.links.entry_count);
    if (ev->u.links.entry_count == 0) {
        /* An empty topology is the restricted/hidden signal, not an error
         * — say so rather than leaving a bare count of zero. */
        card(app, net, "  (topology hidden or restricted by the server)");
        return;
    }
    for (size_t i = 0; i < ev->u.links.entry_count; i++) {
        struct wire_links_entry l;
        if (!wire_links_entry_at(ev->u.links.entries, i, &l)) continue;
        /* Indent by hop count so the tree shape is visible in a terminal
         * the way cicchetto's radial map shows it graphically. */
        int depth = l.has_hopcount && l.hopcount > 0 && l.hopcount < 16 ? (int)l.hopcount : 0;
        card(app, net, "  %*s%s%s%s", depth * 2, "", l.server, l.description ? " — " : "",
             l.description ? l.description : "");
    }
}

static void render_server_reply(struct app *app, const struct wire_event *ev) {
    const char *net = ev->u.server_reply.network;
    const char *label = ev->u.server_reply.source == REPLY_INFO
                            ? "INFO"
                            : (ev->u.server_reply.source == REPLY_VERSION ? "VERSION" : "MOTD");
    card(app, net, "--- %s", label);
    for (size_t i = 0; i < ev->u.server_reply.line_count; i++) {
        const char *line = wire_string_at(ev->u.server_reply.lines, i);
        if (line) card(app, net, "  %s", line);
    }
}

static void render_channel_modes(struct app *app, const struct wire_event *ev) {
    char modes[128] = "+";
    size_t w = 1;
    for (size_t i = 0; i < ev->u.channel_modes.mode_count && w + 1 < sizeof(modes); i++) {
        const char *m = wire_string_at(ev->u.channel_modes.modes, i);
        if (m && m[0]) { modes[w++] = m[0]; modes[w] = '\0'; }
    }
    if (w == 1) return; /* no modes set — nothing worth a row */
    log_line(app, "[%s/%s] --- channel modes %s", ev->u.channel_modes.network,
             ev->u.channel_modes.channel, modes);
}

/* ── Server-owned read state ───────────────────────────────────────────
 *
 * The cursor is `last_read_message_id` per (subject, network, channel)
 * and it lives on the SERVER — that is a project invariant, not a cache.
 * It is what makes "where I left off" survive a restart and stay
 * consistent across devices. Shottino tracked unread as a purely local
 * counter, so reading a channel on the phone left it bold here forever,
 * and restarting reset every window to zero unread regardless of truth.
 *
 * `read_cursor_set` carries no channel: it is scoped by the per-channel
 * topic it arrives on. Rather than thread topic identity through the
 * dispatcher, the cursor is matched to the window that has actually seen
 * that id — ids are globally unique, so at most one window matches. */
static void apply_read_cursor(struct app *app, long last_read_id) {
    pthread_mutex_lock(&app->lock);
    for (size_t i = 0; i < app->window_count; i++) {
        if (app->windows[i].last_id >= last_read_id && last_read_id > app->windows[i].last_read_id) {
            app->windows[i].last_read_id = last_read_id;
            /* Everything up to the cursor is read by definition. */
            if (app->windows[i].last_id <= last_read_id) app->windows[i].unread = 0;
        }
    }
    pthread_mutex_unlock(&app->lock);
}

/* Publish the cursor for the focused window. Called when focus lands on a
 * window that has unread rows — the settle cadence is deliberately "on
 * focus change", not per keystroke, so a scroll through history does not
 * write a row per frame. */
static void push_read_cursor(struct app *app, const char *network, const char *channel,
                             long message_id) {
    if (message_id <= 0) return;
    char *net = url_encode(network);
    char *chan = url_encode(channel);
    char *path = xasprintf("/networks/%s/channels/%s/read-cursor", net, chan);
    char *body = xasprintf("{\"message_id\":%ld}", message_id);
    free(net);
    free(chan);
    struct http_response r = http_request(app, "POST", path, body);
    /* The server clamps monotonically, so an older id is refused rather
     * than moving the cursor backwards; that is not an error worth
     * reporting. A genuine failure is. */
    if (r.status >= 400 && r.status != 409)
        log_line(app, "read-cursor failed HTTP %d: %.120s", r.status, r.body ? r.body : "");
    free(path);
    free(body);
    free(r.body);
}

static void handle_wire_event(struct app *app, const struct wire_event *ev) {
    switch (ev->kind) {
    case WIRE_MESSAGE:
        render_message(app, &ev->u.message, true);
        break;

    case WIRE_TOPIC_CHANGED:
        set_window_topic(app, ev->u.topic_changed.network, ev->u.topic_changed.channel,
                         ev->u.topic_changed.text);
        break;

    case WIRE_MEMBERS_SEEDED:
        copy_members_from_wire(app, ev->u.members_seeded.network, ev->u.members_seeded.channel,
                               ev->u.members_seeded.members, ev->u.members_seeded.member_count);
        set_window_state(app, ev->u.members_seeded.network, ev->u.members_seeded.channel,
                         WS_JOINED, NULL, 0);
        break;

    case WIRE_QUERY_WINDOWS_LIST:
        apply_query_windows(app, ev);
        break;

    /* ── Window state: mirrored, never originated ───────────────────── */
    case WIRE_WINDOW_PENDING:
        add_window_ex(app, ev->u.window_open.network, ev->u.window_open.channel, false);
        set_window_state(app, ev->u.window_open.network, ev->u.window_open.channel, WS_PENDING,
                         NULL, 0);
        break;

    case WIRE_WINDOW_INVITED:
        /* An INVITE we did not ask for: open a greyed, not-joined tab so
         * the invitation is visible without silently joining. */
        add_window_ex(app, ev->u.window_open.network, ev->u.window_open.channel, false);
        set_window_state(app, ev->u.window_open.network, ev->u.window_open.channel, WS_INVITED,
                         NULL, 0);
        log_line(app, "[%s/%s] --- you were invited to %s", ev->u.window_open.network,
                 ev->u.window_open.channel, ev->u.window_open.channel);
        break;

    case WIRE_JOINED:
        set_window_state(app, ev->u.window_state.network, ev->u.window_state.channel, WS_JOINED,
                         NULL, 0);
        break;

    case WIRE_JOIN_FAILED:
        set_window_state(app, ev->u.window_state.network, ev->u.window_state.channel, WS_FAILED,
                         ev->u.window_state.reason,
                         ev->u.window_state.has_numeric ? ev->u.window_state.numeric : 0);
        log_line(app, "[%s/%s] --- cannot join %s%s%s", ev->u.window_state.network,
                 ev->u.window_state.channel, ev->u.window_state.channel,
                 ev->u.window_state.reason ? ": " : "",
                 ev->u.window_state.reason ? ev->u.window_state.reason : "");
        break;

    case WIRE_KICKED:
        set_window_state(app, ev->u.window_state.network, ev->u.window_state.channel, WS_KICKED,
                         ev->u.window_state.reason, 0);
        log_line(app, "[%s/%s] <-- you were kicked from %s%s%s%s%s", ev->u.window_state.network,
                 ev->u.window_state.channel, ev->u.window_state.channel,
                 ev->u.window_state.by ? " by " : "",
                 ev->u.window_state.by ? ev->u.window_state.by : "",
                 ev->u.window_state.reason ? ": " : "",
                 ev->u.window_state.reason ? ev->u.window_state.reason : "");
        break;

    /* ── Identity + session state ───────────────────────────────────── */
    case WIRE_OWN_NICK_CHANGED: {
        pthread_mutex_lock(&app->lock);
        struct network *n = network_by_id_locked(app, ev->u.own_nick.network_id);
        const char *slug = n ? n->slug : NULL;
        if (n) snprintf(n->nick, sizeof(n->nick), "%s", ev->u.own_nick.nick);
        pthread_mutex_unlock(&app->lock);
        if (slug) log_line(app, "[%s/$server] --- you are now known as %s", slug, ev->u.own_nick.nick);
        break;
    }

    case WIRE_AWAY_CONFIRMED: {
        pthread_mutex_lock(&app->lock);
        struct network *n = network_by_slug_locked(app, ev->u.away_confirmed.network);
        if (n) n->away = ev->u.away_confirmed.away;
        pthread_mutex_unlock(&app->lock);
        log_line(app, "[%s/$server] --- you are now %s", ev->u.away_confirmed.network,
                 ev->u.away_confirmed.away ? "away" : "back");
        break;
    }

    case WIRE_PEER_AWAY:
        log_line(app, "[%s/%s] --- %s is away: %s", ev->u.peer_away.network, ev->u.peer_away.peer,
                 ev->u.peer_away.peer, ev->u.peer_away.message);
        break;

    case WIRE_UMODE_CHANGED: {
        char modes[32] = "";
        size_t w = 0;
        for (size_t i = 0; i < ev->u.umodes.mode_count && w + 1 < sizeof(modes); i++) {
            const char *m = wire_string_at(ev->u.umodes.modes, i);
            if (m && m[0]) modes[w++] = m[0];
        }
        modes[w] = '\0';
        pthread_mutex_lock(&app->lock);
        struct network *n = network_by_id_locked(app, ev->u.umodes.network_id);
        const char *slug = n ? n->slug : NULL;
        if (n) snprintf(n->umodes, sizeof(n->umodes), "%s", modes);
        pthread_mutex_unlock(&app->lock);
        if (slug) log_line(app, "[%s/$server] --- your user modes are +%s", slug, modes);
        break;
    }

    case WIRE_ISUPPORT_CHANGED: {
        pthread_mutex_lock(&app->lock);
        struct network *n = network_by_id_locked(app, ev->u.isupport.network_id);
        if (n) {
            size_t count = json_len(ev->u.isupport.prefix);
            if (count > sizeof(n->prefix_letters)) count = sizeof(n->prefix_letters);
            n->prefix_count = 0;
            for (size_t i = 0; i < count; i++) {
                const char *letter = json_key_at(ev->u.isupport.prefix, i);
                const char *sigil = json_string(json_value_at(ev->u.isupport.prefix, i));
                if (letter && letter[0] && sigil && sigil[0]) {
                    n->prefix_letters[n->prefix_count] = letter[0];
                    n->prefix_sigils[n->prefix_count] = sigil[0];
                    n->prefix_count++;
                }
            }
        }
        pthread_mutex_unlock(&app->lock);
        break;
    }

    case WIRE_CONNECTION_STATE_CHANGED: {
        pthread_mutex_lock(&app->lock);
        struct network *n = network_by_slug_locked(app, ev->u.connection_state.network_slug);
        if (n) {
            n->conn_state = ev->u.connection_state.state;
            n->conn_known = true;
            snprintf(n->nick, sizeof(n->nick), "%s", ev->u.connection_state.nick);
        }
        /* A parked/failed network's windows are all dead — mark them so
         * the sidebar greys the whole network, not just the tab that
         * happened to receive a terminal event. */
        if (ev->u.connection_state.state != CONN_CONNECTED) {
            for (size_t i = 0; i < app->window_count; i++)
                if (strcmp(app->windows[i].network, ev->u.connection_state.network_slug) == 0)
                    app->windows[i].state = WS_PARKED;
        }
        pthread_mutex_unlock(&app->lock);
        log_line(app, "[%s/$server] --- network %s -> %s%s%s", ev->u.connection_state.network_slug,
                 wire_connection_state_name(ev->u.connection_state.from),
                 wire_connection_state_name(ev->u.connection_state.to),
                 ev->u.connection_state.reason ? ": " : "",
                 ev->u.connection_state.reason ? ev->u.connection_state.reason : "");
        break;
    }

    case WIRE_CONNECTION_PROGRESS: {
        pthread_mutex_lock(&app->lock);
        struct network *n = network_by_slug_locked(app, ev->u.connection_progress.network);
        if (n) n->connecting = !ev->u.connection_progress.connected;
        pthread_mutex_unlock(&app->lock);
        break;
    }

    case WIRE_INVITE_ACK:
        log_line(app, "[%s/$server] --- invited %s to %s", ev->u.invite_ack.network,
                 ev->u.invite_ack.peer, ev->u.invite_ack.channel);
        break;

    /* ── Reply cards ────────────────────────────────────────────────── */
    case WIRE_WHOIS_BUNDLE:   render_whois(app, ev); break;
    case WIRE_WHOWAS_BUNDLE:  render_whowas(app, ev); break;
    case WIRE_WHO_REPLY:      render_who(app, ev); break;
    case WIRE_NAMES_REPLY:    render_names(app, ev); break;
    case WIRE_LUSERS_BUNDLE:  render_lusers(app, ev); break;
    case WIRE_BANLIST_BUNDLE: render_banlist(app, ev); break;
    case WIRE_LINKS_BUNDLE:   render_links(app, ev); break;
    case WIRE_SERVER_REPLY:   render_server_reply(app, ev); break;
    case WIRE_CHANNEL_MODES_CHANGED: render_channel_modes(app, ev); break;

    case WIRE_PRESENCE_CHANGED: {
        /* A watched nick coming or going. `initial` marks the snapshot
         * edge the server sends on (re)subscribe — reporting those would
         * announce "bob is online" for everyone on the list at every
         * reconnect, so they seed state silently. */
        if (ev->u.presence_changed.initial) break;
        pthread_mutex_lock(&app->lock);
        struct network *n = network_by_id_locked(app, ev->u.presence_changed.network_id);
        const char *slug = n ? n->slug : NULL;
        pthread_mutex_unlock(&app->lock);
        if (slug)
            card(app, slug, "--- %s is now %s", ev->u.presence_changed.nick,
                 ev->u.presence_changed.online ? "online" : "offline");
        break;
    }

    case WIRE_PRESENCE_ERROR: {
        pthread_mutex_lock(&app->lock);
        struct network *n = network_by_id_locked(app, ev->u.presence_error.network_id);
        const char *slug = n ? n->slug : NULL;
        pthread_mutex_unlock(&app->lock);
        if (slug) card(app, slug, "--- watch list full: %s", ev->u.presence_error.detail);
        break;
    }

    case WIRE_READ_CURSOR_SET:
        /* Read state is server-owned per (subject, network, channel), so
         * marking a window read on one device must move the divider on
         * every other. The payload carries no channel — it is scoped by
         * the per-channel topic it arrives on — so it is applied to the
         * window whose last_id brackets the cursor. */
        apply_read_cursor(app, ev->u.read_cursor.last_read_message_id);
        break;

    case WIRE_WINDOW_COUNTS: {
        /* Server-authoritative counts REPLACE the local tally. The server
         * knows about messages this client never received (it was
         * offline) and about reads from other devices; a locally
         * incremented badge drifts from the truth in both directions. */
        pthread_mutex_lock(&app->lock);
        for (size_t i = 0; i < app->window_count; i++) {
            if (strcmp(app->windows[i].channel, ev->u.window_counts.channel) != 0) continue;
            app->windows[i].unread = (unsigned)ev->u.window_counts.messages;
            app->windows[i].mentions = (unsigned)ev->u.window_counts.mentions;
            app->windows[i].severity = ev->u.window_counts.severity;
        }
        pthread_mutex_unlock(&app->lock);
        break;
    }

    case WIRE_MENTIONS_BUNDLE: {
        /* Everything that mentioned you while you were away, replayed in
         * one card so the catch-up is not a hunt through N channels. */
        const char *net = ev->u.mentions_bundle.network;
        if (ev->u.mentions_bundle.message_count == 0) break;
        card(app, net, "--- %zu mention%s while away%s%s", ev->u.mentions_bundle.message_count,
             ev->u.mentions_bundle.message_count == 1 ? "" : "s",
             ev->u.mentions_bundle.away_reason ? ": " : "",
             ev->u.mentions_bundle.away_reason ? ev->u.mentions_bundle.away_reason : "");
        for (size_t i = 0; i < ev->u.mentions_bundle.message_count; i++) {
            struct wire_mention m;
            if (!wire_mention_at(ev->u.mentions_bundle.messages, i, &m)) continue;
            char clock[16];
            time_t ts = m.server_time > 100000000000L ? (time_t)(m.server_time / 1000)
                                                      : (time_t)m.server_time;
            struct tm tm;
            localtime_r(&ts, &tm);
            strftime(clock, sizeof(clock), "%H:%M", &tm);
            card(app, net, "  %s %-14s <%s> %.*s", clock, m.channel, m.sender, 60,
                 m.body ? m.body : "");
        }
        break;
    }

    /* A /list scan runs in the background and can take a while on a
     * large network; without these the user types /list, sees an empty
     * cache, and has no idea a scan is running. */
    case WIRE_DIRECTORY_PROGRESS:
        card(app, ev->u.directory.network, "--- channel scan: %ld so far", ev->u.directory.count);
        break;

    case WIRE_DIRECTORY_COMPLETE:
        card(app, ev->u.directory.network, "--- channel scan complete: %ld channels — /list to browse",
             ev->u.directory.count);
        break;

    case WIRE_DIRECTORY_FAILED:
        card(app, ev->u.directory.network, "--- channel scan failed: %s", ev->u.directory.reason);
        break;

    case WIRE_CHANNEL_CREATED:
    case WIRE_CHANNELS_CHANGED:
    case WIRE_NOTIFY_LIST:
    case WIRE_PRESENCE_SNAPSHOT:
    case WIRE_SUPPORTED_UMODES_CHANGED:
    case WIRE_BUNDLE_HASH:
    case WIRE_SERVER_SETTINGS_CHANGED:
    case WIRE_ARCHIVE_CHANGED:
    case WIRE_ARCHIVE_PURGED:
    case WIRE_UNKNOWN:
        /* Narrowed but not yet rendered — landing here is deliberate, not
         * a gap in the switch. Each becomes a card or a store update in a
         * later commit; listing them explicitly means -Wswitch flags the
         * NEXT kind the server adds instead of it silently vanishing. */
        break;
    }
}

static void handle_ws_frame(struct app *app, const char *frame) {
    char err[160];
    json_doc *doc = json_parse(frame, strlen(frame), err, sizeof(err));
    if (!doc) {
        log_line(app, "malformed websocket frame: %s", err);
        return;
    }
    struct wire_frame f;
    if (!wire_frame_split(json_root(doc), &f)) {
        json_free(doc);
        return;
    }
    if (strcmp(f.event, "phx_reply") == 0) {
        if (json_str_is(json_get(f.payload, "status"), "error"))
            log_line(app, "channel join error: %.200s", frame);
    } else if (strcmp(f.event, "event") == 0) {
        struct wire_event ev;
        if (wire_narrow(f.payload, &ev)) handle_wire_event(app, &ev);
    }
    json_free(doc);
}

/* ── Reconnect + backfill ──────────────────────────────────────────────
 *
 * A dropped socket used to be terminal: ws_pump logged "websocket
 * disconnected", cleared the flag, and nothing ever set it again. The
 * client stayed up looking connected-ish while receiving nothing — the
 * worst failure shape, because the user has no reason to distrust what
 * they see. A laptop suspend or a brief network blip ended the session.
 *
 * Reconnect is exponential with a cap and jitter. Jitter matters: without
 * it, every client that a bouncer restart knocked offline comes back in
 * lockstep and does it again on the next failure.
 *
 * Reconnecting is only half the job. PubSub broadcast is fire-and-forget,
 * so anything sent during the gap is GONE — rejoining the topics does not
 * replay it. Each window therefore refetches from the last id it saw
 * (`?after=`), which is exactly what cicchetto's reconnect backfill does.
 * Without this the client silently misses every message in the gap, which
 * is worse than a visible disconnect. */
#define WS_BACKOFF_MIN 1
#define WS_BACKOFF_MAX 60

static void ws_schedule_retry(struct app *app) {
    if (app->ws_backoff == 0) app->ws_backoff = WS_BACKOFF_MIN;
    else {
        app->ws_backoff *= 2;
        if (app->ws_backoff > WS_BACKOFF_MAX) app->ws_backoff = WS_BACKOFF_MAX;
    }
    /* Up to 25% jitter, so a fleet of clients does not resynchronise on a
     * server restart and thunder back together. */
    unsigned char r = 0;
    RAND_bytes(&r, 1);
    int jitter = (int)((unsigned)app->ws_backoff * r / (255 * 4));
    app->ws_retry_at = time(NULL) + app->ws_backoff + jitter;
}

/* Pull anything that arrived while the socket was down. Uses `?after=<id>`
 * (ascending, per Scrollback.fetch_after) rather than re-reading the tail,
 * so a long gap is filled completely instead of to an arbitrary depth. */
static void backfill_window(struct app *app, const char *network, const char *channel,
                            long after_id) {
    char *net = url_encode(network);
    char *chan = url_encode(channel);
    char *path = xasprintf("/networks/%s/channels/%s/messages?after=%ld", net, chan, after_id);
    free(net);
    free(chan);
    struct http_response r = http_request(app, "GET", path, NULL);
    free(path);
    if (r.status >= 200 && r.status < 300) {
        /* This endpoint answers ASCENDING, unlike the DESC tail fetch, so
         * rows are rendered in array order rather than reversed. */
        json_doc *doc = json_parse(r.body, r.body_len, NULL, 0);
        const json_value *list = json_root(doc);
        size_t n = json_len(list);
        for (size_t i = 0; i < n; i++) {
            struct wire_scrollback_message m;
            if (wire_narrow_message(json_at(list, i), &m)) render_message(app, &m, false);
        }
        if (n) log_line(app, "[%s/%s] --- %zu message%s recovered", network, channel, n,
                        n == 1 ? "" : "s");
        json_free(doc);
    }
    free(r.body);
}

static void ws_backfill_all(struct app *app) {
    /* Snapshot the window list under the lock; the HTTP calls must not
     * hold it (they block for as long as the server takes). */
    struct { char network[MAX_SLUG]; char channel[MAX_CHANNEL]; long last_id; } snap[MAX_WINDOWS];
    size_t count;
    pthread_mutex_lock(&app->lock);
    count = app->window_count;
    for (size_t i = 0; i < count; i++) {
        snprintf(snap[i].network, sizeof(snap[i].network), "%s", app->windows[i].network);
        snprintf(snap[i].channel, sizeof(snap[i].channel), "%s", app->windows[i].channel);
        snap[i].last_id = app->windows[i].last_id;
    }
    pthread_mutex_unlock(&app->lock);
    for (size_t i = 0; i < count; i++) {
        if (strcmp(snap[i].channel, "$server") == 0) continue; /* no scrollback */
        /* last_id 0 means this window never saw a message; a full tail
         * fetch is the right recovery there, not an ?after=0 flood. */
        if (snap[i].last_id > 0) backfill_window(app, snap[i].network, snap[i].channel, snap[i].last_id);
        else fetch_scrollback_target(app, snap[i].network, snap[i].channel);
    }
}

/* Attempt one reconnect if the backoff timer has expired. */
static void ws_try_reconnect(struct app *app) {
    time_t now = time(NULL);
    if (now < app->ws_retry_at) return;

    conn_close(&app->ws);
    if (!ws_connect(app)) {
        ws_schedule_retry(app);
        log_line(app, "reconnect failed; retrying in %ds", (int)(app->ws_retry_at - now));
        return;
    }
    app->ws_backoff = 0;
    pthread_mutex_lock(&app->lock);
    for (size_t i = 0; i < app->window_count; i++) app->windows[i].joined_ws = false;
    pthread_mutex_unlock(&app->lock);
    ws_join_topics(app);
    log_line(app, "websocket reconnected");
    ws_backfill_all(app);
}

static void ws_pump(struct app *app) {
    if (!app->ws_connected) {
        ws_try_reconnect(app);
        return;
    }
    time_t now = time(NULL);
    if (now >= app->next_heartbeat) {
        char ref[32];
        snprintf(ref, sizeof(ref), "%lu", ++app->ws_ref);
        char *hb = xasprintf("[null,\"%s\",\"phoenix\",\"heartbeat\",{}]", ref);
        ws_send_text(app, hb);
        free(hb);
        app->next_heartbeat = now + 25;
    }
    for (;;) {
        char *frame = NULL;
        int r = ws_read_frame(app, &frame);
        if (r == 0) break;
        if (r < 0) {
            conn_close(&app->ws);
            app->ws_connected = false;
            ws_schedule_retry(app);
            log_line(app, "websocket disconnected; reconnecting in %ds",
                     (int)(app->ws_retry_at - time(NULL)));
            break;
        }
        handle_ws_frame(app, frame);
        free(frame);
    }
}

/* Draw a decoded image at (y, x).
 *
 * Character art goes through ncurses like any other text, so it
 * participates in normal repaint and scrolling — no special handling.
 * A protocol image cannot: ncurses knows nothing about it, so the escape
 * is written directly and only when the picture MOVES. That works
 * precisely because ncurses repaints changed cells only; the cells under
 * an image stay blank in its model, so it leaves them alone.
 *
 * Caller holds app->lock. */
static void draw_inline_media(struct inline_media *m, int y, int x, int max_rows,
                              int max_cols) {
    if (m->state != IM_READY || m->rows <= 0) return;
    /* Clamp BOTH axes. The cell box was fitted when the row was first
     * measured; a terminal resize since then leaves it stale, and an
     * image that overruns its box writes over the member pane or past
     * the scroll region. */
    int rows = m->rows > max_rows ? max_rows : m->rows;
    int cols = m->cols > max_cols ? max_cols : m->cols;
    if (rows <= 0 || cols <= 0) return;

    if (m->rgb) {
        /* Half blocks: two image rows per cell, upper glyph in the top
         * pixel's colour over the bottom pixel's. */
        for (int r = 0; r < rows; r++) {
            for (int c = 0; c < cols; c++) {
                const unsigned char *top = m->rgb + (((size_t)(r * 2) * m->cols) + c) * 3;
                const unsigned char *bot = m->rgb + (((size_t)(r * 2 + 1) * m->cols) + c) * 3;
                long tv = ((long)top[0] << 16) | ((long)top[1] << 8) | top[2];
                long bv = ((long)bot[0] << 16) | ((long)bot[1] << 8) | bot[2];
                int pair = mirc_pair_for(tv, bv, CP_MAIN);
                attron(COLOR_PAIR(pair));
                mvaddstr(y + r, x + c, "\u2580");
                attroff(COLOR_PAIR(pair));
            }
        }
        return;
    }

    if (m->payload) {
        /* Reserve the cells so ncurses does not paint over the picture,
         * then place it. Re-emitted only when the position changed. */
        for (int r = 0; r < rows; r++)
            for (int c = 0; c < cols; c++) mvaddch(y + r, x + c, ' ');
        if (!m->drawn || m->drawn_y != y || m->drawn_x != x) {
            refresh();
            printf("\033[%d;%dH", y + 1, x + 1); /* 1-based cursor address */
            fwrite(m->payload, 1, m->payload_len, stdout);
            fflush(stdout);
            m->drawn = true;
            m->drawn_y = y;
            m->drawn_x = x;
        }
    }
}

/* Rows a message's image adds, by state.
 *
 * ONE definition, used by BOTH the measuring pass (which sizes the scroll
 * region) and the draw pass (which consumes the rows). They disagreed:
 * measuring reserved the full picture height for an image that was still
 * LOADING, while drawing spent a single line on the placeholder. That
 * inflated total_visible_lines, which inflated the scroll offset, which
 * made the draw loop skip rows that should have been on screen — a chat
 * window that goes blank and stays blank while a decode is slow or
 * wedged. Two numbers that must agree belong in one function.
 *
 * Caller holds app->lock, which draw() holds for the whole frame, so a
 * worker cannot flip the state between the two passes. */
static int media_extra_rows(const struct inline_media *m) {
    if (!m) return 0;
    switch (m->state) {
    case IM_READY:
        return m->rows;
    case IM_IDLE:     /* promoted to FETCHING by the draw pass */
    case IM_FETCHING: /* "[loading image…]" */
    case IM_FAILED:   /* "[image could not be decoded…]" */
        return 1;
    }
    return 0;
}

/* Open the layout log once, if SHOTTINO_LAYOUT_LOG is set. Returns NULL
 * when the diagnostic is off, which is the normal case — the call sites
 * check for NULL and cost nothing. */
static FILE *layout_log(void) {
    static FILE *f;
    static bool tried;
    if (!tried) {
        tried = true;
        const char *path = getenv("SHOTTINO_LAYOUT_LOG");
        if (path && *path) f = fopen(path, "w");
    }
    return f;
}

/* One-character marker for a non-joined window state. A joined window (or
 * one whose state the server has not told us yet) gets a blank, so only
 * genuinely-abnormal windows draw the eye. */
static char window_state_mark(enum window_state state) {
    switch (state) {
    case WS_PENDING: return '.';
    case WS_INVITED: return '?';
    case WS_FAILED:  return '!';
    case WS_KICKED:  return 'x';
    case WS_PARKED:  return '~';
    case WS_JOINED:
    case WS_UNKNOWN: return ' ';
    }
    return ' ';
}

/* Human-readable reason a window is in its current state, for the status
 * line. Returns NULL when there is nothing worth saying. */
static const char *window_state_label(enum window_state state) {
    switch (state) {
    case WS_PENDING: return "joining";
    case WS_INVITED: return "invited — /join to accept";
    case WS_FAILED:  return "join failed";
    case WS_KICKED:  return "kicked";
    case WS_PARKED:  return "network parked";
    case WS_JOINED:
    case WS_UNKNOWN: return NULL;
    }
    return NULL;
}

/* ── Inline media ──────────────────────────────────────────────────────
 *
 * Decoding is asynchronous by construction: the UI thread only ever
 * allocates a slot and reads a finished one. ffmpeg runs on the worker,
 * which is why a picture arriving no longer freezes the client the way
 * the old synchronous preview did.
 *
 * Slots are claimed lazily from the DRAW path — a row's image is fetched
 * the first time it is actually on screen. Scrollback holds thousands of
 * rows; decoding every link ever seen would burn CPU and bandwidth on
 * pictures nobody scrolled to. */

static void media_decode_job(struct app *app, int slot);
static bool enqueue_job(struct app *app, struct job job);

static void media_slot_reset(struct inline_media *m) {
    free(m->payload);
    free(m->rgb);
    memset(m, 0, sizeof(*m));
}

/* Claim a slot for `url`, recycling the oldest when full. Caller holds
 * app->lock. Returns the index, or -1 when inline media is off. */
static int media_claim_locked(struct app *app, const char *url, bool is_video) {
    if (!app->inline_media_enabled) return -1;
    size_t idx;
    if (app->media_count < MAX_INLINE_MEDIA) {
        idx = app->media_count++;
    } else {
        idx = app->media_next;
        app->media_next = (app->media_next + 1) % MAX_INLINE_MEDIA;
        /* Any log row still pointing at the recycled slot must let go, or
         * it would render someone else's picture. */
        for (size_t i = 0; i < app->log_count; i++)
            if (app->log_media[i] == (int)idx) app->log_media[i] = -1;
    }
    struct inline_media *m = &app->media[idx];
    media_slot_reset(m);
    snprintf(m->url, sizeof(m->url), "%s", url);
    m->is_video = is_video;
    m->state = IM_IDLE;
    return (int)idx;
}

/* Record the screen rectangle of a media link so a later mouse event can map
 * back to its URL. Caller holds app->lock (draw path). */
static void add_link_region(struct app *app, int y0, int y1, int x0, int x1,
                            const char *url, bool is_video) {
    if (app->link_region_count >= MAX_LINK_REGIONS) return;
    struct link_region *r = &app->link_regions[app->link_region_count++];
    r->y0 = y0;
    r->y1 = y1;
    r->x0 = x0;
    r->x1 = x1;
    r->is_video = is_video;
    snprintf(r->url, sizeof(r->url), "%s", url);
}

static void draw(struct app *app) {
    pthread_mutex_lock(&app->lock);
    erase();
    app->link_region_count = 0;
    int rows, cols;
    getmaxyx(stdscr, rows, cols);
    int side = cols > 118 ? 22 : (cols > 90 ? 18 : 14);
    int members = cols > 118 ? 24 : 0;
    int main_x = side + 1;
    int main_w = cols - side - members - 2;
    int members_x = cols - members;
    int chrome_y = 0;
    int topic_y = 1;
    struct window *w = &app->windows[app->current];
    char prompt[MAX_CHANNEL + 4];
    if (app->panel == PANEL_CHAT) snprintf(prompt, sizeof(prompt), "%s> ", w->channel);
    else snprintf(prompt, sizeof(prompt), "%s> ", panel_name(app->panel));
    int input_h = input_display_lines(prompt, app->input, main_w - 4);
    int max_input_h = rows / 3;
    if (max_input_h < 1) max_input_h = 1;
    if (input_h > max_input_h) input_h = max_input_h;
    int input_y = rows - input_h - 1;
    int compose_y = input_y - 1;
    const char *topic_text = w->topic[0] ? w->topic : "(not loaded yet)";
    int topic_label_w = main_w / 3;
    if (topic_label_w < 12) topic_label_w = 12;
    if (topic_label_w > main_w - 12) topic_label_w = main_w / 2;
    int topic_text_x = main_x + topic_label_w + 2;
    int topic_text_w = main_w - topic_label_w - 3;
    int topic_prefix_w = 7;
    if (topic_text_w < topic_prefix_w + 8) topic_prefix_w = 0;
    int topic_wrap_w = topic_text_w - topic_prefix_w;
    if (topic_wrap_w < 1) topic_wrap_w = 1;
    int topic_h = wrapped_text_lines_visible(topic_text, topic_wrap_w);
    int max_topic_h = compose_y - topic_y - 1;
    if (max_topic_h < 1) max_topic_h = 1;
    if (topic_h > max_topic_h) topic_h = max_topic_h;
    int scroll_y = topic_y + topic_h;
    int scroll_h = compose_y - 1 - scroll_y;
    if (scroll_h < 0) scroll_h = 0;

    for (int y = 0; y < rows; y++) {
        draw_fill(y, 0, side, CP_ALT);
        if (members) draw_fill(y, members_x, members, CP_ALT);
    }
    attron(COLOR_PAIR(CP_BORDER));
    mvvline(0, side, ACS_VLINE, rows);
    if (members) mvvline(0, members_x - 1, ACS_VLINE, rows);
    mvhline(scroll_y, main_x, ACS_HLINE, main_w);
    mvhline(compose_y - 1, main_x, ACS_HLINE, main_w);
    attroff(COLOR_PAIR(CP_BORDER));

    draw_text(0, 1, side - 2, CP_ACCENT, A_BOLD, "shottino");
    if (app->ws_connected) {
        draw_text(1, 1, side - 2, CP_MUTED, 0, "ws");
    } else {
        /* Count down to the next attempt. "offline" alone reads as a dead
         * end; the countdown says recovery is in progress. */
        long wait = (long)(app->ws_retry_at - time(NULL));
        if (wait < 0) wait = 0;
        draw_text(1, 1, side - 2, CP_ERROR, A_BOLD, "retry %lds", wait);
    }

    char last_net[MAX_SLUG] = "";
    int y = 3;
    for (size_t i = 0; i < app->window_count && y < rows - 1; i++) {
        struct window *win = &app->windows[i];
        if (strcmp(last_net, win->network) != 0) {
            snprintf(last_net, sizeof(last_net), "%s", win->network);
            draw_text(y++, 1, side - 2, CP_ACCENT, A_BOLD, "%s", win->network);
            if (y >= rows - 1) break;
        }
        bool selected = i == app->current;
        bool unread = app->windows[i].unread > 0;
        /* A not-joined window is greyed and marked. cicchetto renders the
         * same states as greyed synthetic rows; the sigil is the terminal
         * equivalent of its badge, so a dead tab reads as dead at a glance
         * instead of looking like an ordinary empty channel. */
        char state_mark = window_state_mark(win->state);
        bool dead = state_mark != ' ';
        int pair = selected ? CP_SELECTED : (unread ? CP_ACCENT : (dead ? CP_MUTED : CP_ALT));
        draw_fill(y, 0, side, pair);
        draw_text(y, 1, 2, pair, (selected || unread) ? A_BOLD : 0, "%2zu", i + 1);
        if (dead) draw_text(y, 4, side - 5, pair, A_DIM, "%c%s", state_mark, win->channel);
        else if (win->mentions > 0) {
            /* A mention outranks a plain-message count: it is the reason
             * to look now rather than later, so it gets its own colour
             * and marker instead of being folded into one number. */
            draw_text(y, 4, side - 5, selected ? pair : CP_MENTION, A_BOLD, "%s (%u)",
                      win->channel, win->mentions);
        }
        else if (unread) draw_text(y, 4, side - 5, pair, A_BOLD, "%s [%u]", win->channel, app->windows[i].unread);
        else draw_text(y, 4, side - 5, pair, selected ? A_BOLD : 0, "%s", win->channel);
        y++;
    }

    if (app->hover_url[0])
        draw_text(chrome_y, main_x + 1, main_w - 2, CP_ACCENT, A_BOLD,
                  "click to preview: %s", app->hover_url);
    else
        draw_text(chrome_y, main_x + 1, main_w - 2, CP_MUTED, 0,
                  "/archive  /settings  /admin  /chat  ws:%s", app->ws_connected ? "connected" : "offline");
    for (int ty = 0; ty < topic_h; ty++) draw_fill(topic_y + ty, main_x, main_w, CP_ALT);
    draw_text(topic_y, main_x + 1, topic_label_w, CP_ACCENT, A_BOLD, "%s/%s", w->network, w->channel);
    if (topic_prefix_w) draw_text(topic_y, topic_text_x, topic_text_w, CP_ALT, A_BOLD, "topic: ");
    draw_wrapped_text(topic_y, topic_text_x + topic_prefix_w, topic_wrap_w, topic_h, CP_ALT, 0, topic_text);

    if (app->panel != PANEL_CHAT) {
        draw_text(scroll_y, main_x + 1, main_w - 2, CP_ACCENT, A_BOLD, "%s", panel_name(app->panel));
        for (size_t i = 0; i < app->panel_line_count && (int)i + scroll_y + 2 < compose_y - 1; i++) {
            int pair = i == 0 ? CP_ACCENT : CP_MAIN;
            attr_t attr = i == 0 ? A_BOLD : 0;
            draw_text(scroll_y + 2 + (int)i, main_x + 1, main_w - 2, pair, attr, "%s", app->panel_lines[i]);
        }
        draw_text(compose_y, main_x + 1, main_w - 2, CP_MUTED, 0, "panel: %s | Esc or /chat returns to chat", panel_name(app->panel));
        int cursor_y = input_y;
        int cursor_x = main_x + 2;
        draw_input_box(input_y, main_x + 1, main_w - 2, input_h, prompt, app->input, &cursor_y, &cursor_x);
        move(cursor_y, cursor_x);
        pthread_mutex_unlock(&app->lock);
        refresh();
        return;
    }

    char wanted_prefix[MAX_SLUG + MAX_CHANNEL + 8];
    snprintf(wanted_prefix, sizeof(wanted_prefix), "[%s/%s]", w->network, w->channel);
    size_t visible[LOG_LINES];
    int heights[LOG_LINES];
    size_t visible_count = 0;
    static int text_heights[LOG_LINES];
    bool divider_counted = false;
    int total_visible_lines = 0;
    for (size_t i = 0; i < app->log_count; i++) {
        if (strncmp(app->log[i], "[", 1) != 0 || strncmp(app->log[i], wanted_prefix, strlen(wanted_prefix)) == 0) {
            visible[visible_count] = i;
            heights[visible_count] = message_display_lines(app->log[i], main_w - 2);
            if (heights[visible_count] < 1) heights[visible_count] = 1;
            /* The TEXT height, kept apart from the total below. Conflating
             * the two put the image after text+image rows instead of
             * after the text, and double-counted it in used_lines — which
             * pushed later rows past the scroll region and over the input
             * box, leaving the client looking dead. */
            text_heights[visible_count] = heights[visible_count];
            /* The unread divider occupies a row of its own above the first
             * unread message, and the DRAW pass spends one (`used_lines +=
             * 1`). Measuring has to reserve it too: otherwise the budget is
             * a line short of what gets drawn, the content overflows the
             * region by one, and the bottom line — the newest message —
             * never appears. Reserved on the same row the draw pass tests,
             * so the two agree. */
            if (!divider_counted && w->last_read_id > 0 &&
                app->log_ids[i] > w->last_read_id) {
                heights[visible_count] += 1;
                divider_counted = true;
            }
            /* An image reserves rows UNDER its message line. The height is
             * known before the picture is decoded (the cell box is chosen
             * from the available width), so the layout does not jump when
             * the decode lands. */
            int mi = app->log_media[i];
            if (mi >= 0 && mi < (int)app->media_count) {
                struct inline_media *m = &app->media[mi];
                if (m->rows <= 0) {
                    int box_rows = INLINE_MAX_ROWS;
                    if (box_rows > scroll_h / 2) box_rows = scroll_h / 2;
                    if (box_rows < 3) box_rows = 3;
                    /* Aspect is unknown until decode; assume 4:3, which is
                     * close enough that the reserved box rarely changes. */
                    media_fit_cells(4, 3, main_w - 4, box_rows, &m->cols, &m->rows);
                }
                heights[visible_count] += media_extra_rows(m);
            }
            total_visible_lines += heights[visible_count];
            visible_count++;
        }
    }
    /* Layout diagnostic, off unless SHOTTINO_LAYOUT_LOG names a file.
     *
     * A scrollback row's height is computed in TWO places — here, to size
     * the scroll region, and again in the draw loop, to consume it. Every
     * "a line went missing" bug in this client so far has been those two
     * disagreeing, and the disagreement is invisible from the screen:
     * you see a missing line, not which pass was wrong. This dumps both
     * sides so a report can carry the numbers instead of a description.
     *
     * Written from the draw path, which already holds app->lock. */
    FILE *lay = layout_log();
    if (lay) {
        fprintf(lay, "\n== frame scroll_y=%d scroll_h=%d visible=%zu total=%d\n", scroll_y,
                scroll_h, visible_count, total_visible_lines);
        for (size_t k = 0; k < visible_count; k++) {
            int mi = app->log_media[visible[k]];
            fprintf(lay, "   row=%zu h=%d text=%d media=%d%s :: %.56s\n", visible[k], heights[k],
                    text_heights[k], mi,
                    mi >= 0 && mi < (int)app->media_count
                        ? (app->media[mi].state == IM_READY      ? " READY"
                           : app->media[mi].state == IM_FETCHING ? " FETCHING"
                           : app->media[mi].state == IM_FAILED   ? " FAILED"
                                                                 : " IDLE")
                        : "",
                    app->log[visible[k]]);
        }
    }
    int max_offset = total_visible_lines > scroll_h ? total_visible_lines - scroll_h : 0;
    if ((int)app->scrollback_offset > max_offset) app->scrollback_offset = (size_t)max_offset;
    int skip_lines = max_offset - (int)app->scrollback_offset;
    int used_lines = 0;
    bool divider_drawn = false;
    int drawn_rows = 0;
    for (size_t vi = 0; vi < visible_count; vi++) {
        if (skip_lines >= heights[vi]) {
            skip_lines -= heights[vi];
            continue;
        }
        size_t i = visible[vi];
        if (skip_lines > 0) {
            skip_lines = 0;
            continue;
        }
        int available = scroll_h - used_lines;
        int draw_lines = text_heights[vi];
        if (draw_lines > available) draw_lines = available;
        if (draw_lines <= 0) break;
        int msg_y = scroll_y + used_lines;
        /* Unread divider: drawn once, immediately above the first row the
         * server's cursor says has not been read. It is deliberately
         * anchored to the CURSOR rather than to "where I was scrolled
         * last", so it means the same thing here as on every other device
         * attached to this session. */
        if (!divider_drawn && w->last_read_id > 0 && app->log_ids[i] > w->last_read_id &&
            used_lines + 1 < scroll_h) {
            attron(COLOR_PAIR(CP_ERROR) | A_BOLD);
            mvhline(msg_y, main_x + 1, ACS_HLINE, main_w - 2);
            mvprintw(msg_y, main_x + 3, " unread ");
            attroff(COLOR_PAIR(CP_ERROR) | A_BOLD);
            divider_drawn = true;
            used_lines += 1;
            msg_y += 1;
            available -= 1;
            if (draw_lines > available) draw_lines = available;
            if (draw_lines <= 0) break;
        }
        draw_message_line(msg_y, main_x + 1, main_w - 2, draw_lines, app->log[i], app->log_mentions[i], app->log_pending[i]);
        const char *msg_url = find_url(app->log[i]);
        enum media_kind mk = msg_url ? media_kind_of(msg_url) : MEDIA_NONE;
        if (mk != MEDIA_NONE) {
            char url_tok[MAX_LINE];
            copy_url_token(msg_url, url_tok, sizeof(url_tok));
            add_link_region(app, msg_y, msg_y + draw_lines - 1, main_x + 1,
                            main_x + main_w - 2, url_tok, mk == MEDIA_VIDEO);
        }
        /* Draw the row's image beneath it, and kick off its decode the
         * first time it is on screen — lazy by design, so scrollback full
         * of links costs nothing until you scroll to them. */
        int mi = app->log_media[i];
        if (mi >= 0 && mi < (int)app->media_count) {
            struct inline_media *m = &app->media[mi];
            if (m->state == IM_IDLE && m->cols > 0) {
                m->state = IM_FETCHING;
                struct job mj = {.kind = JOB_MEDIA};
                snprintf(mj.arg1, sizeof(mj.arg1), "%d", mi);
                enqueue_job(app, mj);
            }
            int img_y = msg_y + draw_lines;
            int room = scroll_y + scroll_h - img_y;
            /* Spend exactly what the measuring pass reserved, clamped to
             * the room actually left. */
            int want = media_extra_rows(m);
            int spend = want < room ? want : room;
            if (spend > 0) {
                if (m->state == IM_READY) {
                    draw_inline_media(m, img_y, main_x + 2, spend, main_w - 4);
                } else if (m->state == IM_FAILED) {
                    draw_text(img_y, main_x + 2, main_w - 4, CP_MUTED, A_DIM,
                              "  [image could not be decoded — /open to view externally]");
                } else {
                    draw_text(img_y, main_x + 2, main_w - 4, CP_MUTED, A_DIM, "  [loading image…]");
                }
                used_lines += spend;
            }
        }
        used_lines += draw_lines;
        drawn_rows++;
        skip_lines = 0;
    }
    if (lay) {
        /* used < scroll_h with rows left undrawn means the budget ran out
         * early: the bottom of the buffer was clipped. used == scroll_h
         * with rows left is the normal "scrolled" case. */
        fprintf(lay, "   END max_off=%d skip=%d used=%d/%d drawn=%d/%zu%s\n", max_offset,
                max_offset - (int)app->scrollback_offset, used_lines, scroll_h, drawn_rows,
                visible_count,
                (used_lines > scroll_h) ? "  *** OVERFLOW: budget exceeded ***" : "");
        fflush(lay);
    }

    /* A window in a terminal state says WHY on the status line — the
     * sidebar sigil says "dead", this says "kicked by op: flooding". */
    const char *state_label = window_state_label(w->state);
    if (state_label) {
        draw_text(compose_y, main_x + 1, main_w - 2, CP_ERROR, A_BOLD, "[%s] %s%s%s%s",
                  w->channel, state_label, w->state_detail[0] ? ": " : "", w->state_detail,
                  app->scrollback_pinned ? " | scrolled" : "");
    } else {
        draw_text(compose_y, main_x + 1, main_w - 2, CP_MUTED, 0,
                  "[%s] PgUp/PgDn scroll | End bottom | Tab complete | Up/Down history | /open | /exit%s",
                  w->channel, app->scrollback_pinned ? " | scrolled" : "");
    }
    int cursor_y = input_y;
    int cursor_x = main_x + 2;
    draw_input_box(input_y, main_x + 1, main_w - 2, input_h, prompt, app->input, &cursor_y, &cursor_x);

    /* The member pane used to render three lines of prose describing what
     * a member pane would show. It shows the members now: ops first, then
     * halfops, voiced, plain — each with the sigil its network actually
     * advertises via ISUPPORT PREFIX, nick-coloured to match scrollback. */
    if (members) {
        draw_text(0, members_x + 1, members - 2, CP_ACCENT, A_BOLD, "members %zu", w->member_count);
        int my = 2;
        for (size_t i = 0; i < w->member_count && my < rows - 1; i++, my++) {
            char sigil = member_sigil_locked(app, w->network, w->members[i].modes);
            int pair = nick_pair(w->members[i].nick);
            if (sigil) draw_text(my, members_x + 1, members - 2, pair, A_BOLD, "%c%s", sigil, w->members[i].nick);
            else draw_text(my, members_x + 1, members - 2, pair, 0, " %s", w->members[i].nick);
        }
        if (w->member_count == 0)
            draw_text(2, members_x + 1, members - 2, CP_MUTED, 0, "(not seeded)");
    }

    move(cursor_y, cursor_x);
    pthread_mutex_unlock(&app->lock);
    refresh();
}

static void send_message(struct app *app, const char *body) {
    struct window *w = &app->windows[app->current];
    char *net = url_encode(w->network);
    char *chan = url_encode(w->channel);
    char *escaped = json_escape(body);
    char *path = xasprintf("/networks/%s/channels/%s/messages", net, chan);
    char *json = xasprintf("{\"body\":\"%s\"}", escaped);
    free(net);
    free(chan);
    free(escaped);
    struct http_response r = http_request(app, "POST", path, json);
    if (r.status < 200 || r.status >= 300) log_line(app, "send failed HTTP %d: %.200s", r.status, r.body);
    else if (r.status == 201) render_created_message(app, r.body, r.body_len);
    free(path);
    free(json);
    free(r.body);
}

static void send_message_target(struct app *app, const char *network, const char *channel, const char *body) {
    char *net = url_encode(network);
    char *chan = url_encode(channel);
    char *escaped = json_escape(body);
    char *path = xasprintf("/networks/%s/channels/%s/messages", net, chan);
    char *json = xasprintf("{\"body\":\"%s\"}", escaped);
    free(net);
    free(chan);
    free(escaped);
    struct http_response r = http_request(app, "POST", path, json);
    if (r.status < 200 || r.status >= 300) log_line(app, "send failed HTTP %d: %.200s", r.status, r.body);
    else if (r.status == 201) render_created_message(app, r.body, r.body_len);
    free(path);
    free(json);
    free(r.body);
}

static void set_network_state(struct app *app, const char *network, const char *state, const char *reason) {
    char *net = url_encode(network);
    char *path = xasprintf("/networks/%s/", net);
    char *why = json_escape(reason ? reason : "");
    char *body = reason && reason[0]
        ? xasprintf("{\"connection_state\":\"%s\",\"reason\":\"%s\"}", state, why)
        : xasprintf("{\"connection_state\":\"%s\"}", state);
    free(net);
    free(why);
    struct http_response r = http_request(app, "PATCH", path, body);
    if (r.status >= 200 && r.status < 300) log_line(app, "%s is %s", network, state);
    else log_line(app, "network state failed HTTP %d: %.200s", r.status, r.body);
    free(path);
    free(body);
    free(r.body);
}

static void set_nick(struct app *app, const char *nick) {
    char *net = url_encode(app->windows[app->current].network);
    char *path = xasprintf("/networks/%s/nick", net);
    char *escaped = json_escape(nick);
    char *body = xasprintf("{\"nick\":\"%s\"}", escaped);
    free(net);
    free(escaped);
    struct http_response r = http_request(app, "POST", path, body);
    if (r.status >= 200 && r.status < 300) log_line(app, "nick change requested: %s", nick);
    else log_line(app, "nick failed HTTP %d: %.200s", r.status, r.body);
    free(path);
    free(body);
    free(r.body);
}

static void set_topic_target(struct app *app, const char *network, const char *channel, const char *topic) {
    char *net = url_encode(network);
    char *chan = url_encode(channel);
    char *escaped = json_escape(topic);
    char *path = xasprintf("/networks/%s/channels/%s/topic", net, chan);
    char *body = xasprintf("{\"body\":\"%s\"}", escaped);
    free(net);
    free(chan);
    free(escaped);
    struct http_response r = http_request(app, "POST", path, body);
    if (r.status >= 200 && r.status < 300) log_line(app, "topic change requested for %s", channel);
    else log_line(app, "topic failed HTTP %d: %.200s", r.status, r.body);
    free(path);
    free(body);
    free(r.body);
}

static void list_members_target(struct app *app, const char *network, const char *channel) {
    char *net = url_encode(network);
    char *chan = url_encode(channel);
    char *path = xasprintf("/networks/%s/channels/%s/members", net, chan);
    free(net);
    free(chan);
    struct http_response r = http_request(app, "GET", path, NULL);
    if (r.status == 204) {
        log_line(app, "members for %s are not seeded yet", channel);
    } else if (r.status >= 200 && r.status < 300) {
        /* The previous reader scanned for `"nick"` / `"modes"` and copied
         * every character following a quote that was not 'm' — an attempt
         * to skip the literal key "modes" that also mangled any mode
         * letter 'm' and any nick containing a quote. Parse properly. */
        char err[160];
        json_doc *doc = json_parse(r.body, r.body_len, err, sizeof(err));
        /* This endpoint answers with an ENVELOPE — `{"members": [...]}`
         * (`Session.Wire.members_index/1`) — unlike the messages and
         * channels endpoints, which return a bare array. Accept either:
         * assuming a bare array here made every /members call report
         * "malformed response". */
        const json_value *root = json_root(doc);
        const json_value *list = root;
        if (json_type_of(root) == JSON_OBJECT) list = json_get(root, "members");
        if (!doc || json_type_of(list) != JSON_ARRAY) {
            log_line(app, "members %s: malformed response (%s)", channel, doc ? "not a list" : err);
            json_free(doc);
            free(path);
            free(r.body);
            return;
        }
        struct member rows[512];
        size_t count = 0;
        for (size_t i = 0; i < json_len(list) && count < 512; i++) {
            const json_value *m = json_at(list, i);
            const char *nick = NULL;
            if (!json_str_req(m, "nick", &nick)) continue;
            snprintf(rows[count].nick, sizeof(rows[count].nick), "%s", nick);
            rows[count].modes[0] = '\0';
            const json_value *modes = json_get(m, "modes");
            for (size_t j = 0, w = 0; j < json_len(modes) && w + 1 < sizeof(rows[count].modes); j++) {
                const char *mode = json_string(json_at(modes, j));
                if (mode && mode[0]) {
                    rows[count].modes[w++] = mode[0];
                    rows[count].modes[w] = '\0';
                }
            }
            count++;
        }
        json_free(doc);
        for (size_t i = 0; i < count; i++) {
            for (size_t j = i + 1; j < count; j++) {
                int ri = member_rank(rows[i].modes), rj = member_rank(rows[j].modes);
                if (rj < ri || (rj == ri && strcasecmp(rows[j].nick, rows[i].nick) < 0)) {
                    struct member tmp = rows[i]; rows[i] = rows[j]; rows[j] = tmp;
                }
            }
        }
        set_window_members(app, network, channel, rows, count);
        log_line(app, "members %s (%zu):", channel, count);
        for (size_t i = 0; i < count; i++) {
            int rank = member_rank(rows[i].modes);
            const char *label = rank == 0 ? "op" : (rank == 1 ? "halfop" : (rank == 2 ? "voice" : "user"));
            char sigil = member_sigil(app, network, rows[i].modes);
            log_line(app, "  %-6s %c%s", label, sigil ? sigil : ' ', rows[i].nick);
        }
        if (count == 0) log_line(app, "members %s: (none)", channel);
    } else {
        log_line(app, "members failed HTTP %d: %.200s", r.status, r.body);
    }
    free(path);
    free(r.body);
}

static void push_simple_channel_action(struct app *app, const char *event, const char *extra_json) {
    int id = current_network_id(app);
    char *channel = json_escape(current_channel(app));
    char *payload = extra_json
        ? xasprintf("{\"network_id\":%d,\"channel\":\"%s\",%s}", id, channel, extra_json)
        : xasprintf("{\"network_id\":%d,\"channel\":\"%s\"}", id, channel);
    free(channel);
    ws_push_user(app, event, payload);
    free(payload);
}

static char *json_array_words(const char *words) {
    char *copy = xasprintf("%s", words);
    char *out = xasprintf("[");
    bool first = true;
    for (char *tok = strtok(copy, " \t"); tok; tok = strtok(NULL, " \t")) {
        char *e = json_escape(tok);
        char *next = xasprintf("%s%s\"%s\"", out, first ? "" : ",", e);
        free(out);
        free(e);
        out = next;
        first = false;
    }
    char *next = xasprintf("%s]", out);
    free(out);
    free(copy);
    return next;
}

static void query_window(struct app *app, const char *target) {
    int id = current_network_id(app);
    char *t = json_escape(target);
    char *payload = xasprintf("{\"network_id\":%d,\"target_nick\":\"%s\"}", id, t);
    ws_push_user(app, "open_query_window", payload);
    add_window(app, app->windows[app->current].network, target);
    free(t);
    free(payload);
}

static void join_channel(struct app *app, const char *name) {
    const char *net_slug = app->networks[0].slug;
    if (app->window_count > 0) net_slug = app->windows[app->current].network;
    char *net = url_encode(net_slug);
    char *path = xasprintf("/networks/%s/channels", net);
    char *escaped = json_escape(name);
    char *body = xasprintf("{\"name\":\"%s\"}", escaped);
    free(net);
    free(escaped);
    struct http_response r = http_request(app, "POST", path, body);
    if (r.status >= 200 && r.status < 300) {
        add_window(app, net_slug, name);
        fetch_scrollback(app, &app->windows[app->current]);
        if (app->ws_connected) {
            char *t = xasprintf("grappa:user:%s/network:%s/channel:%s", app->subject, net_slug, name);
            ws_join(app, t);
            free(t);
        }
    } else {
        log_line(app, "join failed HTTP %d: %.200s", r.status, r.body);
    }
    free(path);
    free(body);
    free(r.body);
}

static void part_current(struct app *app) {
    char network[MAX_SLUG];
    char channel[MAX_CHANNEL];
    pthread_mutex_lock(&app->lock);
    snprintf(network, sizeof(network), "%s", app->windows[app->current].network);
    snprintf(channel, sizeof(channel), "%s", app->windows[app->current].channel);
    pthread_mutex_unlock(&app->lock);
    char *net = url_encode(network);
    char *chan = url_encode(channel);
    char *path = xasprintf("/networks/%s/channels/%s", net, chan);
    free(net);
    free(chan);
    struct http_response r = http_request(app, "DELETE", path, NULL);
    if (r.status >= 200 && r.status < 300) {
        log_line(app, "parted %s", channel);
        remove_window(app, network, channel);
    }
    else log_line(app, "part failed HTTP %d: %.200s", r.status, r.body);
    free(path);
    free(r.body);
}

static void close_query_target(struct app *app, const char *network, const char *target) {
    int id = 0;
    for (size_t i = 0; i < app->network_count; i++) {
        if (strcmp(app->networks[i].slug, network) == 0) {
            id = app->networks[i].id;
            break;
        }
    }
    if (id == 0) {
        log_line(app, "close query failed: unknown network %s", network);
        return;
    }
    char *nick = json_escape(target);
    char *payload = xasprintf("{\"network_id\":%d,\"target_nick\":\"%s\"}", id, nick);
    free(nick);
    ws_push_user(app, "close_query_window", payload);
    free(payload);
    remove_window(app, network, target);
    log_line(app, "closed query %s", target);
}

static bool enqueue_job(struct app *app, struct job job) {
    pthread_mutex_lock(&app->jobs_lock);
    size_t next = (app->jobs_tail + 1) % JOB_QUEUE;
    if (next == app->jobs_head) {
        pthread_mutex_unlock(&app->jobs_lock);
        log_line(app, "background queue full; command not sent");
        return false;
    }
    app->jobs[app->jobs_tail] = job;
    app->jobs_tail = next;
    pthread_cond_signal(&app->jobs_cond);
    pthread_mutex_unlock(&app->jobs_lock);
    return true;
}

static bool dequeue_job(struct app *app, struct job *job) {
    pthread_mutex_lock(&app->jobs_lock);
    while (!app->worker_stop && app->jobs_head == app->jobs_tail) pthread_cond_wait(&app->jobs_cond, &app->jobs_lock);
    if (app->worker_stop && app->jobs_head == app->jobs_tail) {
        pthread_mutex_unlock(&app->jobs_lock);
        return false;
    }
    *job = app->jobs[app->jobs_head];
    app->jobs_head = (app->jobs_head + 1) % JOB_QUEUE;
    pthread_mutex_unlock(&app->jobs_lock);
    return true;
}

static void *worker_main(void *arg) {
    struct app *app = arg;
    struct job job;
    while (dequeue_job(app, &job)) {
        switch (job.kind) {
        case JOB_FETCH:
            fetch_scrollback_target(app, job.network, job.channel);
            break;
        case JOB_READ_CURSOR:
            push_read_cursor(app, job.network, job.channel, strtol(job.arg1, NULL, 10));
            break;
        case JOB_MEDIA:
            media_decode_job(app, (int)strtol(job.arg1, NULL, 10));
            break;
        case JOB_SEND: {
            send_message_target(app, job.network, job.channel, job.arg1);
            break;
        }
        case JOB_JOIN:
            join_channel(app, job.channel);
            break;
        case JOB_PART: {
            add_window(app, job.network, job.channel);
            part_current(app);
            break;
        }
        case JOB_NICK:
            add_window(app, job.network, job.channel);
            set_nick(app, job.arg1);
            break;
        case JOB_NETWORK_STATE:
            set_network_state(app, job.network, job.arg1, job.arg2[0] ? job.arg2 : NULL);
            break;
        case JOB_TOPIC:
            set_topic_target(app, job.network, job.channel, job.arg1);
            break;
        case JOB_MEMBERS:
            list_members_target(app, job.network, job.channel);
            break;
        case JOB_CLOSE_QUERY:
            close_query_target(app, job.network, job.channel);
            break;
        }
    }
    return NULL;
}

/* Queue a read-cursor publish. Deliberately fire-and-forget: the cursor
 * is advisory catch-up state, and a failed write costs a stale divider,
 * not a lost message. */
static void enqueue_read_cursor(struct app *app, const char *network, const char *channel,
                                long message_id) {
    struct job job = { .kind = JOB_READ_CURSOR };
    snprintf(job.network, sizeof(job.network), "%s", network);
    snprintf(job.channel, sizeof(job.channel), "%s", channel);
    snprintf(job.arg1, sizeof(job.arg1), "%ld", message_id);
    enqueue_job(app, job);
}

static void enqueue_fetch(struct app *app, const char *network, const char *channel) {
    struct job job = { .kind = JOB_FETCH };
    snprintf(job.network, sizeof(job.network), "%s", network);
    snprintf(job.channel, sizeof(job.channel), "%s", channel);
    enqueue_job(app, job);
}

static void enqueue_send(struct app *app, const char *network, const char *channel, const char *body) {
    struct job job = { .kind = JOB_SEND };
    snprintf(job.network, sizeof(job.network), "%s", network);
    snprintf(job.channel, sizeof(job.channel), "%s", channel);
    snprintf(job.arg1, sizeof(job.arg1), "%s", body);
    enqueue_job(app, job);
}

static const char *own_nick_for_network(struct app *app, const char *network) {
    for (size_t i = 0; i < app->network_count; i++) {
        if (strcmp(app->networks[i].slug, network) == 0 && app->networks[i].nick[0]) return app->networks[i].nick;
    }
    if (app->login_nick[0]) return app->login_nick;
    const char *colon = strchr(app->subject, ':');
    return colon ? colon + 1 : app->subject;
}

static void add_history(struct app *app, const char *line) {
    if (!line[0]) return;
    if (app->history_count > 0 && strcmp(app->history[app->history_count - 1], line) == 0) {
        app->history_pos = app->history_count;
        return;
    }
    if (app->history_count == INPUT_HISTORY) {
        memmove(app->history, app->history + 1, sizeof(app->history[0]) * (INPUT_HISTORY - 1));
        app->history_count--;
    }
    snprintf(app->history[app->history_count++], MAX_LINE, "%s", line);
    app->history_pos = app->history_count;
}

static void history_prev(struct app *app) {
    if (app->history_count == 0 || app->history_pos == 0) return;
    app->history_pos--;
    snprintf(app->input, sizeof(app->input), "%s", app->history[app->history_pos]);
    app->input_len = strlen(app->input);
}

static void history_next(struct app *app) {
    if (app->history_pos >= app->history_count) return;
    app->history_pos++;
    if (app->history_pos == app->history_count) app->input[0] = 0;
    else snprintf(app->input, sizeof(app->input), "%s", app->history[app->history_pos]);
    app->input_len = strlen(app->input);
}

static void scroll_chat(struct app *app, int delta) {
    pthread_mutex_lock(&app->lock);
    if (delta > 0) app->scrollback_offset += (size_t)delta;
    else {
        size_t n = (size_t)(-delta);
        app->scrollback_offset = n > app->scrollback_offset ? 0 : app->scrollback_offset - n;
    }
    app->scrollback_pinned = app->scrollback_offset > 0;
    pthread_mutex_unlock(&app->lock);
}

static void scroll_bottom(struct app *app) {
    pthread_mutex_lock(&app->lock);
    app->scrollback_offset = 0;
    app->scrollback_pinned = false;
    pthread_mutex_unlock(&app->lock);
}

static void cycle_window(struct app *app, int delta) {
    pthread_mutex_lock(&app->lock);
    if (app->window_count == 0) {
        pthread_mutex_unlock(&app->lock);
        return;
    }
    if (delta > 0) app->current = (app->current + 1) % app->window_count;
    else app->current = app->current == 0 ? app->window_count - 1 : app->current - 1;
    clear_current_unread_locked(app);
    app->scrollback_offset = 0;
    app->scrollback_pinned = false;
    char network[MAX_SLUG];
    char channel[MAX_CHANNEL];
    snprintf(network, sizeof(network), "%s", app->windows[app->current].network);
    snprintf(channel, sizeof(channel), "%s", app->windows[app->current].channel);
    pthread_mutex_unlock(&app->lock);
    enqueue_fetch(app, network, channel);
}

static const char *commands[] = {
    "/admin", "/archive", "/away", "/ban", "/banlist", "/chat", "/clear", "/close", "/connect", "/deop", "/devoice", "/disconnect",
    "/invite", "/join", "/kick", "/lusers", "/me", "/members", "/mode", "/msg", "/names",
    "/nick", "/op", "/oper", "/part", "/q", "/query", "/quit", "/quote", "/settings", "/share", "/topic", "/umode",
    "/unban", "/users", "/voice", "/w", "/watch", "/whowas", "/who", "/whois", "/win", "/window"
};

static bool prefix_ci(const char *s, const char *prefix) {
    while (*prefix) {
        if (!*s) return false;
        if (tolower((unsigned char)*s) != tolower((unsigned char)*prefix)) return false;
        s++;
        prefix++;
    }
    return true;
}

static bool candidate_seen(char candidates[][MAX_CHANNEL], size_t count, const char *candidate) {
    for (size_t i = 0; i < count; i++) {
        if (strcasecmp(candidates[i], candidate) == 0) return true;
    }
    return false;
}

static void add_completion_candidate(char candidates[][MAX_CHANNEL], size_t *count, const char *candidate, const char *stem) {
    if (!candidate || !candidate[0]) return;
    if (!prefix_ci(candidate, stem)) return;
    if (candidate_seen(candidates, *count, candidate)) return;
    if (*count >= 64) return;
    snprintf(candidates[*count], MAX_CHANNEL, "%s", candidate);
    (*count)++;
}

static void collect_log_nick_candidate(struct app *app, char candidates[][MAX_CHANNEL], size_t *count, const char *line, const char *stem) {
    char prefix[256];
    char nick[MAX_CHANNEL];
    const char *body;
    (void)app;
    if (split_message_line(line, prefix, sizeof(prefix), nick, sizeof(nick), &body)) {
        add_completion_candidate(candidates, count, nick, stem);
    }
}

static void complete_input(struct app *app) {
    char prefix[MAX_LINE];
    snprintf(prefix, sizeof(prefix), "%s", app->input);
    char *last_space = strrchr(prefix, ' ');
    const char *stem = last_space ? last_space + 1 : prefix;
    size_t stem_len = strlen(stem);

    if (app->input_len == 0 || stem_len == 0) return;

    char candidates[64][MAX_CHANNEL];
    size_t matches = 0;

    if (prefix[0] == '/' && !last_space) {
        for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
            add_completion_candidate(candidates, &matches, commands[i], stem);
        }
    } else {
        const char *current_network = app->window_count > 0 ? app->windows[app->current].network : "";
        if (app->window_count > 0) {
            struct window *w = &app->windows[app->current];
            for (size_t i = 0; i < w->member_count; i++) add_completion_candidate(candidates, &matches, w->members[i].nick, stem);
        }
        for (size_t i = 0; i < app->window_count; i++) {
            const char *name = app->windows[i].channel;
            add_completion_candidate(candidates, &matches, name, stem);
        }
        for (size_t i = 0; i < app->network_count; i++) {
            const char *name = app->networks[i].slug;
            add_completion_candidate(candidates, &matches, name, stem);
            if (strcmp(app->networks[i].slug, current_network) == 0) add_completion_candidate(candidates, &matches, app->networks[i].nick, stem);
        }
        for (size_t i = 0; i < app->log_count; i++) {
            collect_log_nick_candidate(app, candidates, &matches, app->log[i], stem);
        }
    }

    if (matches == 1) {
        size_t head = last_space ? (size_t)(last_space + 1 - prefix) : 0;
        snprintf(app->input + head, sizeof(app->input) - head, "%s", candidates[0]);
        app->input_len = strlen(app->input);
        if (app->input_len + 1 < sizeof(app->input)) {
            app->input[app->input_len++] = ' ';
            app->input[app->input_len] = 0;
        }
    } else if (matches > 1) {
        char list[1024] = "";
        size_t used = 0;
        for (size_t i = 0; i < matches; i++) {
            int n = snprintf(list + used, sizeof(list) - used, "%s%s", i == 0 ? "" : " ", candidates[i]);
            if (n < 0 || (size_t)n >= sizeof(list) - used) break;
            used += (size_t)n;
        }
        log_line(app, "completions for '%s': %s", stem, list);
    }
}

static void open_external_url(struct app *app, const char *url) {
    if (!url || !url[0]) {
        log_line(app, "no URL captured yet");
        return;
    }
    /* Double-fork: the grandchild runs xdg-open and is reparented to init,
     * so it is auto-reaped — we must not block the UI thread waiting on a
     * browser launcher, and a single fork would leak a zombie per call.
     * xdg-open's own diagnostics are sent to /dev/null so they can't scribble
     * over the ncurses screen. */
    pid_t pid = fork();
    if (pid == 0) {
        if (fork() == 0) {
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
                if (devnull > STDERR_FILENO) close(devnull);
            }
            execlp("xdg-open", "xdg-open", url, (char *)NULL);
            _exit(127);
        }
        _exit(0);
    }
    if (pid < 0) {
        log_line(app, "failed to launch xdg-open");
        return;
    }
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
    log_line(app, "opened %s", url);
}


/* Run argv[0] with execvp (no shell). stderr always discarded; stdout goes to
 * the controlling terminal when `inherit_stdout` (so chafa can paint), else to
 * /dev/null (ffmpeg writes its frame to a file, not stdout). Returns the
 * process exit code, or -1 on spawn/abnormal exit. */
static int run_cmd(char *const argv[], bool inherit_stdout) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            if (!inherit_stdout) dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO) close(devnull);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}

/* Block for a single raw keypress on stdin, used to dismiss the preview while
 * ncurses is suspended. Restores the prior terminal mode before returning. */
static void wait_for_dismiss_key(void) {
    struct termios old_tio, raw;
    if (tcgetattr(STDIN_FILENO, &old_tio) != 0) {
        getchar();
        return;
    }
    raw = old_tio;
    cfmakeraw(&raw);
    unsigned char c;
    /* First drain whatever the terminal sent in reply to chafa's graphics
     * capability probes (DA / cursor-position / Kitty responses). If left in
     * the buffer, the blocking read below would consume one of those bytes as
     * the dismiss key and flash the preview shut. VMIN=0/VTIME=1 polls with a
     * 100ms idle window: read until a quiet gap, then there is nothing stray
     * left. */
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 1;
    tcsetattr(STDIN_FILENO, TCSANOW, &raw);
    while (read(STDIN_FILENO, &c, 1) > 0) {}
    /* Then block for a genuine keypress. */
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &raw);
    while (read(STDIN_FILENO, &c, 1) < 0 && errno == EINTR) {}
    tcsetattr(STDIN_FILENO, TCSANOW, &old_tio);
}

/* Mouse motion/button reporting escapes. Enabled while shottino owns the
 * screen; disabled around the preview (so frame bytes aren't read as a
 * dismiss key) and at shutdown. */
/* Mouse tracking is what makes click-to-preview work — and it is also
 * what stops the terminal doing its own text selection, because the
 * terminal hands motion/button events to us instead of acting on them.
 * Nothing the application can do restores native selection while tracking
 * is on: the only fix is to turn it off, which is why this is toggleable
 * from `/mouse` rather than being unconditional.
 *
 * `app->mouse_enabled` is the user's PREFERENCE; this function is the
 * mechanism. The two are separate because the media-preview path disables
 * tracking around a full-screen preview and must restore whatever the
 * user chose, not force it back on. */
static void mouse_reporting(bool on) {
    fputs(on ? "\033[?1000h\033[?1003h\033[?1006h"
             : "\033[?1006l\033[?1003l\033[?1000l",
          stdout);
    fflush(stdout);
}

/* Apply the user's preference. Used everywhere tracking is (re-)asserted
 * so a `/mouse off` is never silently undone by a preview or a resize.
 *
 * BOTH halves are required, and sending only the escape sequences (as the
 * first attempt at this did) does not work: ncurses OWNS the mouse mode
 * once `mousemask()` is set non-zero, and re-emits the enable sequence on
 * its own schedule, so a raw `\033[?1000l` is silently undone and
 * selection never comes back. Clearing the mask is what actually makes
 * ncurses stop; the raw sequences then mop up 1003/1006, which it does
 * not consistently manage. */
static void mouse_apply(struct app *app) {
    if (app->mouse_enabled) {
        mousemask(ALL_MOUSE_EVENTS | REPORT_MOUSE_POSITION, NULL);
        mouseinterval(0);
        mouse_reporting(true);
    } else {
        mousemask(0, NULL);
        mouse_reporting(false);
    }
    /* ncurses buffers its own output; without this the mode change does
     * not reach the terminal until the next unrelated repaint. */
    refresh();
}

/* Full-screen modal media preview. Both images and videos are normalized to a
 * single PNG frame by ffmpeg (which also does the network fetch + decode),
 * then rendered by chafa, which auto-detects the terminal graphics protocol
 * (Kitty > iTerm2 > Sixel > symbols). Falls back to xdg-open when either tool
 * is absent or the frame extraction fails. Blocks until a key is pressed; the
 * caller's next draw() repaints the chat, clearing the preview. */
/* Decode one inline image on the WORKER thread.
 *
 * Two output shapes, chosen by protocol:
 *   kitty / iTerm2 — a PNG, which the terminal decodes itself;
 *   sixel / art    — raw RGB24 at the exact pixel grid we will draw.
 *
 * Either way ffmpeg does the fetch, decode and scale in one pass, and the
 * `thumbnail` filter picks a representative frame so a video does not
 * render as a black leader frame.
 *
 * Runs entirely off the UI thread; the only shared-state touch is the
 * short critical section at the end that publishes the result. */
static void media_decode_job(struct app *app, int slot) {
    if (slot != MEDIA_SLOT_PREVIEW && (slot < 0 || slot >= MAX_INLINE_MEDIA)) return;

    char url[MAX_LINE];
    media_protocol proto;
    int cols, rows;
    pthread_mutex_lock(&app->lock);
    struct inline_media *m =
        (slot == MEDIA_SLOT_PREVIEW) ? &app->preview : &app->media[slot];
    snprintf(url, sizeof(url), "%s", m->url);
    /* /preview-ascii forces the pixel path regardless of what the
     * terminal can do. */
    proto = m->force_ascii ? MEDIA_PROTO_NONE : app->proto;
    cols = m->cols;
    rows = m->rows;
    pthread_mutex_unlock(&app->lock);
    if (!url[0] || cols <= 0 || rows <= 0) return;

    char dir[] = "/tmp/shottino-media-XXXXXX";
    if (!mkdtemp(dir)) return;

    bool ok = false;
    char *payload = NULL;
    size_t payload_len = 0;
    unsigned char *rgb = NULL;

    if (proto == MEDIA_PROTO_KITTY || proto == MEDIA_PROTO_ITERM2) {
        /* Let the terminal scale: ask ffmpeg for a reasonable pixel size
         * and pass the CELL box in the escape. */
        char png[PATH_MAX];
        snprintf(png, sizeof(png), "%s/m.png", dir);
        char scale[96];
        snprintf(scale, sizeof(scale), "thumbnail,scale=%d:-1:flags=lanczos", cols * 8);
        char *argv[] = {"ffmpeg", "-y", "-loglevel", "error", "-rw_timeout", "15000000",
                        /* #451: fetch untrusted peer media, so bound ffmpeg to the
                         * protocols this path actually needs — file (temp output),
                         * http/https + tcp/tls/crypto (the fetch). Blocks the
                         * concat/hls/rtp/data/pipe demuxers a hostile URL could
                         * otherwise reach. Input option, so it precedes -i. */
                        "-protocol_whitelist", "file,crypto,tcp,tls,http,https",
                        "-i", url, "-vf", scale, "-frames:v", "1", png, NULL};
        if (run_cmd(argv, false) == 0) {
            FILE *f = fopen(png, "rb");
            if (f) {
                fseek(f, 0, SEEK_END);
                long n = ftell(f);
                rewind(f);
                if (n > 0 && n < 8L * 1024 * 1024) {
                    unsigned char *buf = malloc((size_t)n);
                    if (buf && fread(buf, 1, (size_t)n, f) == (size_t)n) {
                        char *mem = NULL;
                        size_t mem_len = 0;
                        FILE *ms = open_memstream(&mem, &mem_len);
                        if (ms) {
                            ok = (proto == MEDIA_PROTO_KITTY)
                                     ? media_emit_kitty(buf, (size_t)n, cols, rows, ms)
                                     : media_emit_iterm2(buf, (size_t)n, cols, rows, ms);
                            fclose(ms);
                            if (ok) { payload = mem; payload_len = mem_len; }
                            else free(mem);
                        }
                    }
                    free(buf);
                }
                fclose(f);
            }
            unlink(png);
        }
    } else {
        /* Sixel and character art both want pixels. Two source rows per
         * cell row: sixel draws at pixel resolution, and the art renderer
         * packs two pixels into one cell as a half block. */
        int px_w = cols, px_h = rows * 2;
        if (proto == MEDIA_PROTO_SIXEL) { px_w = cols * 6; px_h = rows * 12; }
        char raw[PATH_MAX];
        snprintf(raw, sizeof(raw), "%s/m.rgb", dir);
        char scale[192];
        snprintf(scale, sizeof(scale),
                 "thumbnail,scale=%d:%d:force_original_aspect_ratio=decrease:flags=lanczos,"
                 "pad=%d:%d:(ow-iw)/2:(oh-ih)/2,format=rgb24",
                 px_w, px_h, px_w, px_h);
        char *argv[] = {"ffmpeg", "-y", "-loglevel", "error", "-rw_timeout", "15000000",
                        /* #451: fetch untrusted peer media, so bound ffmpeg to the
                         * protocols this path actually needs — file (temp output),
                         * http/https + tcp/tls/crypto (the fetch). Blocks the
                         * concat/hls/rtp/data/pipe demuxers a hostile URL could
                         * otherwise reach. Input option, so it precedes -i. */
                        "-protocol_whitelist", "file,crypto,tcp,tls,http,https",
                        "-i", url, "-vf", scale, "-frames:v", "1",
                        "-f", "rawvideo", "-pix_fmt", "rgb24", raw, NULL};
        if (run_cmd(argv, false) == 0) {
            size_t want = (size_t)px_w * (size_t)px_h * 3;
            unsigned char *buf = malloc(want);
            FILE *f = buf ? fopen(raw, "rb") : NULL;
            if (f) {
                if (fread(buf, 1, want, f) == want) {
                    if (proto == MEDIA_PROTO_SIXEL) {
                        char *mem = NULL;
                        size_t mem_len = 0;
                        FILE *ms = open_memstream(&mem, &mem_len);
                        if (ms) {
                            ok = media_emit_sixel(buf, px_w, px_h, ms);
                            fclose(ms);
                            if (ok) { payload = mem; payload_len = mem_len; }
                            else free(mem);
                        }
                        free(buf);
                        buf = NULL;
                    } else {
                        rgb = buf;
                        buf = NULL;
                        ok = true;
                    }
                }
                fclose(f);
            }
            free(buf);
            unlink(raw);
        }
    }
    rmdir(dir);

    pthread_mutex_lock(&app->lock);
    m = (slot == MEDIA_SLOT_PREVIEW) ? &app->preview : &app->media[slot];
    /* The slot may have been recycled while ffmpeg ran; publishing then
     * would attach this picture to a different message. */
    if (strcmp(m->url, url) == 0 && m->state == IM_FETCHING) {
        m->payload = payload;
        m->payload_len = payload_len;
        m->rgb = rgb;
        m->state = ok ? IM_READY : IM_FAILED;
        m->drawn = false;
    } else {
        free(payload);
        free(rgb);
    }
    pthread_mutex_unlock(&app->lock);
}


/* Full-screen preview. `force_ascii` bypasses any graphics protocol and
 * renders character art — the `/preview-ascii` path. */
/* ── Full-screen preview, decoded off the UI thread ────────────────────
 *
 * The old preview ran ffmpeg inline: `/preview` froze the whole client
 * for as long as the fetch and decode took, which on a large image over a
 * slow link is seconds of a dead terminal. It reused the same modal
 * takeover for the display, so the two were welded together.
 *
 * They are split now. `request_preview` claims a slot sized to the screen
 * and hands the decode to the worker — the client keeps drawing, chat
 * keeps arriving, input keeps working. The event loop notices when the
 * slot is ready and only THEN takes the screen over.
 *
 * chafa is no longer used: with a dithered sixel encoder and the
 * half-block renderer in-tree there is no reason to keep a second,
 * differently-tuned path that may or may not be installed. */
static void request_preview(struct app *app, const char *url, bool is_video, bool force_ascii) {
    int rows_avail = LINES > 4 ? LINES - 3 : 1;
    int cols_avail = COLS > 4 ? COLS - 2 : 1;

    pthread_mutex_lock(&app->lock);
    /* Reuse the dedicated preview slot rather than competing with the
     * inline pool, so opening a preview never evicts an image that is on
     * screen. */
    struct inline_media *m = &app->preview;
    media_slot_reset(m);
    snprintf(m->url, sizeof(m->url), "%s", url);
    m->is_video = is_video;
    m->force_ascii = force_ascii;
    /* Aspect is unknown until decode; ffmpeg letterboxes into this box. */
    m->cols = cols_avail;
    m->rows = rows_avail;
    m->state = IM_FETCHING;
    app->preview_pending = true;
    pthread_mutex_unlock(&app->lock);

    struct job job = {.kind = JOB_MEDIA};
    snprintf(job.arg1, sizeof(job.arg1), "%d", MEDIA_SLOT_PREVIEW);
    enqueue_job(app, job);
    log_line(app, "preparing preview of %.60s%s", url, force_ascii ? " (ascii)" : "");
}

/* Display an already-decoded preview. Runs on the UI thread — it owns the
 * screen — but does no fetching, so the takeover is brief. */
static void show_preview(struct app *app) {
    char url[MAX_LINE];
    bool is_video, ok;
    char *payload = NULL;
    size_t payload_len = 0;
    unsigned char *rgb = NULL;
    int cols, rows;

    pthread_mutex_lock(&app->lock);
    struct inline_media *m = &app->preview;
    snprintf(url, sizeof(url), "%s", m->url);
    is_video = m->is_video;
    ok = (m->state == IM_READY);
    /* Take ownership of the buffers so the modal can run without the
     * lock and without the worker recycling them underneath it. */
    payload = m->payload;
    payload_len = m->payload_len;
    rgb = m->rgb;
    cols = m->cols;
    rows = m->rows;
    m->payload = NULL;
    m->rgb = NULL;
    m->state = IM_IDLE;
    app->preview_pending = false;
    pthread_mutex_unlock(&app->lock);

    if (!ok) {
        log_line(app, "preview: could not decode %.60s — /open to view externally", url);
        free(payload);
        free(rgb);
        return;
    }

    struct winsize ws = {0};
    int term_rows = LINES, term_cols = COLS;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 2 && ws.ws_col > 0) {
        term_rows = ws.ws_row;
        term_cols = ws.ws_col;
    }

    def_prog_mode();
    endwin();
    mouse_reporting(false);
    fputs("\033[2J\033[H", stdout);
    int url_w = term_cols - 10;
    if (url_w < 0) url_w = 0;
    printf("preview: %.*s\r\n", url_w, url);
    fflush(stdout);

    const char *how;
    if (payload) {
        fwrite(payload, 1, payload_len, stdout);
        how = "image";
    } else {
        termcolor_render_rgb(rgb, cols, rows * 2, termcolor_detect_depth(), stdout);
        how = termcolor_detect_depth() == TERM_COLOR_NONE ? "ascii" : "colour ascii";
    }
    fflush(stdout);

    printf("\033[%d;1H[ %s%s — press any key to return ]", term_rows,
           is_video ? "video frame, " : "", how);
    fflush(stdout);
    wait_for_dismiss_key();

    /* Kitty placements persist above the cell grid; drop them so the chat
     * repaint underneath is clean (a no-op on other terminals). */
    fputs("\033_Ga=d\033\\", stdout);
    fflush(stdout);

    free(payload);
    free(rgb);

    reset_prog_mode();
    clearok(stdscr, TRUE);
    refresh();
    mouse_apply(app);
}


static void show_help(struct app *app) {
    log_line(app, "commands: /help /archive /settings /admin /chat /exit /quit /window N [/w N, /win N] /join #chan [/j] /part /close /clear /msg nick text /query nick [/q nick] /me text");
    log_line(app, "network: /connect slug /disconnect [slug] [reason] /nick nick /away [reason] /umode +modes /mode [#chan] +modes [params]");
    log_line(app, "info: /topic [text|-delete] /members [/users] /whois nick /whowas nick /who [#chan] /names [#chan] /lusers /list [-refresh|query] /links /motd /info /version /stats [q] /rehash [opt]");
    log_line(app, "ops: /op nicks /deop nicks /voice nicks /devoice nicks /kick nick [reason] /kb nick [reason] /ban mask /unban mask /banlist /invite nick");
    log_line(app, "watch: /notify [nick...|del nick|list] watches PEOPLE; /hilight pattern, /dehilight pattern watch WORDS (/watch add|del|list is the older spelling)");
    log_line(app, "services: /cs /ns /ms /os /hs /rs [command] — bare form sends HELP; aliases: /alias name expansion ($1..$9, $*), /unalias name, bare /alias lists");
    log_line(app, "files: /upload <path> — post a local file and share its link (IRC stays text; the link is clickable)");
    log_line(app, "terminal: mouse tracking is OFF by default so the terminal keeps its own copy/paste selection; /mouse on enables click-to-preview (and suppresses selection), /mouse off restores it");
    log_line(app, "media: images render INLINE when the terminal supports it (kitty/iTerm2/sixel) or as colour art otherwise; /media [on|off] toggles");
    log_line(app, "       /preview full-screen; /preview-ascii forces the art renderer; /open opens externally; with /mouse on, click a link to preview");
    log_line(app, "raw/media: /quote line /oper name password /open last-url; keys: PgUp/PgDn scroll, End bottom, Tab complete, Up/Down history, Ctrl-N/Ctrl-P window cycle");
}

static void show_command_help(struct app *app, const char *raw) {
    while (*raw == ' ') raw++;
    const char *cmd = raw[0] == '/' ? raw + 1 : raw;
    if (!*cmd) {
        show_help(app);
        return;
    }
    if (strcmp(cmd, "quit") == 0) log_line(app, "/quit — terminate the grappa session, delete saved token, and exit Shottino");
    else if (strcmp(cmd, "exit") == 0) log_line(app, "/exit — close Shottino only; grappa stays connected and token remains for reattach");
    else if (strcmp(cmd, "window") == 0 || strcmp(cmd, "win") == 0 || strcmp(cmd, "w") == 0) log_line(app, "/window N, /win N, /w N — switch to window number N and clear its unread count");
    else if (strcmp(cmd, "join") == 0 || strcmp(cmd, "j") == 0) log_line(app, "/join #chan [key], /j #chan [key] — join a channel");
    else if (strcmp(cmd, "part") == 0) log_line(app, "/part — part the current channel");
    else if (strcmp(cmd, "close") == 0) log_line(app, "/close — close current channel/query; channels PART, queries close the query window");
    else if (strcmp(cmd, "clear") == 0) log_line(app, "/clear — clear the local visible buffer for the active window; does not delete server scrollback");
    else if (strcmp(cmd, "msg") == 0) log_line(app, "/msg nick text — send a private message and open/reuse the query window");
    else if (strcmp(cmd, "query") == 0 || strcmp(cmd, "q") == 0) log_line(app, "/query nick, /q nick — open a query window without sending a message");
    else if (strcmp(cmd, "me") == 0) log_line(app, "/me text — send an ACTION (/me) message to the current window");
    else if (strcmp(cmd, "topic") == 0) log_line(app, "/topic [text|-delete] — set or clear the current channel topic; bare /topic requests a snapshot");
    else if (strcmp(cmd, "members") == 0 || strcmp(cmd, "users") == 0) log_line(app, "/members, /users — list known members for the current channel");
    else if (strcmp(cmd, "nick") == 0) log_line(app, "/nick nick — request an IRC nick change on the current network");
    else if (strcmp(cmd, "away") == 0) log_line(app, "/away [reason] — set away with reason; bare /away returns present");
    else if (strcmp(cmd, "connect") == 0) log_line(app, "/connect network — mark a parked network connected so grappa can spawn it");
    else if (strcmp(cmd, "disconnect") == 0) log_line(app, "/disconnect [network] [reason] — park a network while keeping Shottino running");
    else if (strcmp(cmd, "whois") == 0) log_line(app, "/whois nick — request WHOIS for nick");
    else if (strcmp(cmd, "whowas") == 0) log_line(app, "/whowas nick — request WHOWAS for nick");
    else if (strcmp(cmd, "who") == 0) log_line(app, "/who [#chan] — request WHO for target/current channel");
    else if (strcmp(cmd, "names") == 0) log_line(app, "/names [#chan] — request NAMES for target/current channel");
    else if (strcmp(cmd, "lusers") == 0) log_line(app, "/lusers — request IRC network user/server counts");
    else if (strcmp(cmd, "watch") == 0 || strcmp(cmd, "highlight") == 0) log_line(app, "/watch add|del|list pattern — manage highlight watchlist");
    else if (strcmp(cmd, "op") == 0 || strcmp(cmd, "deop") == 0 || strcmp(cmd, "voice") == 0 || strcmp(cmd, "devoice") == 0) log_line(app, "/%s nick [nick...] — change channel privileges", cmd);
    else if (strcmp(cmd, "kick") == 0) log_line(app, "/kick nick [reason] — kick nick from the current channel");
    else if (strcmp(cmd, "ban") == 0 || strcmp(cmd, "unban") == 0) log_line(app, "/%s mask — set or remove a channel ban mask", cmd);
    else if (strcmp(cmd, "banlist") == 0) log_line(app, "/banlist — request current channel ban list");
    else if (strcmp(cmd, "invite") == 0) log_line(app, "/invite nick — invite nick to the current channel");
    else if (strcmp(cmd, "quote") == 0) log_line(app, "/quote raw-line — send a raw IRC line through grappa");
    else if (strcmp(cmd, "oper") == 0) log_line(app, "/oper name password — send IRC OPER credentials; password is not logged");
    else if (strcmp(cmd, "open") == 0) log_line(app, "/open — open the most recent URL using xdg-open");
    else if (strcmp(cmd, "share") == 0) log_line(app, "/share — (visitor only) mint a session-share link; open it on another device to attach it to this same session");
    else if (strcmp(cmd, "archive") == 0 || strcmp(cmd, "settings") == 0 || strcmp(cmd, "admin") == 0 || strcmp(cmd, "chat") == 0) log_line(app, "/%s — switch to the %s panel", cmd, cmd);
    else log_line(app, "no help for /%s; use /help for the command list", cmd);
}

// Visitor session-sharing — mint side. POST /me/share-token (visitor-only;
// the server 403s a registered user) returns {token, expires_at}. We wrap the
// token in `<base>/share/<token>` — the URL the other device feeds to
// /share/<token> (consume) to land on this same session.
static void mint_share_link(struct app *app) {
    struct http_response r = http_request(app, "POST", "/me/share-token", NULL);
    if (r.status == 403) {
        log_line(app, "/share: solo le sessioni visitor possono generare un link di condivisione");
        free(r.body);
        return;
    }
    if (r.status < 200 || r.status >= 300) {
        log_line(app, "/share failed HTTP %d: %.200s", r.status, r.body ? r.body : "");
        free(r.body);
        return;
    }
    char token[MAX_TOKEN];
    char expires[64] = "";
    if (!json_top_string(r.body, r.body_len, "token", token, sizeof(token))) {
        log_line(app, "/share: response missing token");
        free(r.body);
        return;
    }
    json_top_string(r.body, r.body_len, "expires_at", expires, sizeof(expires));
    free(r.body);
    char *enc = url_encode(token);
    snprintf(app->last_url, sizeof(app->last_url), "%s/share/%s", app->url.base, enc);
    if (expires[0]) log_line(app, "share link (scade %s): %s", expires, app->last_url);
    else log_line(app, "share link: %s", app->last_url);
    log_line(app, "  aprilo sull'altro dispositivo, o /open per lanciarlo");
    free(enc);
}

static void handle_command_dispatch(struct app *app, char *line);

/* ── /upload ───────────────────────────────────────────────────────────
 *
 * Posts a local file to grappa's upload surface and sends the resulting
 * URL to the current window as TEXT. That is the whole model: IRC stays
 * text, the URL is a clickable link, and the 📸 prefix matches what
 * cicchetto ships so the two clients produce identical wire bytes.
 * Nothing is rendered inline in scrollback. */
/* Declared MIME per extension.
 *
 * The server validates against a CLOSED allowlist
 * (`UploadsController.@mime_categories`) and trusts what we declare, so
 * this table must mirror it: a type it does not list is a 415, and a type
 * we mislabel is a 415 the user cannot act on. Kept in the same order as
 * the server's map so the two can be diffed.
 *
 * Deliberately ABSENT: ogg and opus. The server does not accept them
 * (Safari support is patchy, so they were left out on purpose) and
 * claiming a MIME it will reject only converts a clear local message into
 * a confusing server error. */
static const char *mime_for_path(const char *path) {
    const char *dot = strrchr(path, '.');
    if (!dot) return NULL;
    static const struct { const char *ext; const char *mime; } table[] = {
        /* image */
        {"png", "image/png"},   {"jpg", "image/jpeg"},  {"jpeg", "image/jpeg"},
        {"gif", "image/gif"},   {"webp", "image/webp"}, {"apng", "image/apng"},
        /* video */
        {"mp4", "video/mp4"},   {"mov", "video/quicktime"}, {"webm", "video/webm"},
        /* document */
        {"pdf", "application/pdf"}, {"txt", "text/plain"},
        {"odt", "application/vnd.oasis.opendocument.text"},
        {"ods", "application/vnd.oasis.opendocument.spreadsheet"},
        {"docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
        {"xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
        /* audio */
        {"mp3", "audio/mpeg"},  {"m4a", "audio/mp4"},   {"m4r", "audio/mp4"},
        {"aac", "audio/aac"},   {"wav", "audio/wav"},   {"flac", "audio/flac"},
    };
    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++)
        if (strcasecmp(dot + 1, table[i].ext) == 0) return table[i].mime;
    return NULL; /* unsupported — refused locally, see upload_command */
}

static void upload_command(struct app *app, const char *path) {
    while (*path == ' ') path++;
    if (!*path) {
        log_line(app, "/upload requires a file path");
        return;
    }
    /* Refuse an unsupported type HERE. The server would answer 415, and
     * "HTTP 415" tells the user nothing about which types it takes. */
    const char *mime = mime_for_path(path);
    if (!mime) {
        log_line(app, "/upload: unsupported file type — images (png jpg gif webp apng), "
                      "video (mp4 mov webm), audio (mp3 m4a aac wav flac), "
                      "documents (pdf txt odt ods docx xlsx)");
        return;
    }
    /* Same read-only rule as a typed message: the link would be posted to
     * the current window, and $server rejects a PRIVMSG. */
    if (strcmp(app->windows[app->current].channel, "$server") == 0) {
        log_line(app, "/upload: the server window is read-only — switch to a channel or query first");
        return;
    }
    FILE *f = fopen(path, "rb");
    if (!f) {
        log_line(app, "/upload: cannot open %s", path);
        return;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        log_line(app, "/upload: cannot size %s", path);
        return;
    }
    long size = ftell(f);
    rewind(f);
    /* Bounded so a mistyped path at a huge file cannot exhaust memory
     * before the server's cap ever sees it. */
    if (size < 0 || size > 64L * 1024 * 1024) {
        fclose(f);
        log_line(app, "/upload: %s is too large (%ld bytes)", path, size);
        return;
    }
    char *data = malloc((size_t)size);
    if (!data) {
        fclose(f);
        log_line(app, "/upload: out of memory");
        return;
    }
    size_t got = fread(data, 1, (size_t)size, f);
    fclose(f);
    if (got != (size_t)size) {
        free(data);
        log_line(app, "/upload: short read on %s", path);
        return;
    }

    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    const char *boundary = "----shottino7RcH2mQx";
    char *head = xasprintf("--%s\r\n"
                           "Content-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
                           "Content-Type: %s\r\n\r\n",
                           boundary, base, mime);
    char *tail = xasprintf("\r\n--%s--\r\n", boundary);
    size_t hlen = strlen(head), tlen = strlen(tail);
    size_t total = hlen + got + tlen;
    char *body = malloc(total);
    if (!body) {
        free(head); free(tail); free(data);
        log_line(app, "/upload: out of memory");
        return;
    }
    memcpy(body, head, hlen);
    memcpy(body + hlen, data, got);
    memcpy(body + hlen + got, tail, tlen);
    free(head);
    free(tail);
    free(data);

    char ctype[128];
    snprintf(ctype, sizeof(ctype), "multipart/form-data; boundary=%s", boundary);
    log_line(app, "uploading %s (%ld bytes)...", base, size);
    struct http_response r = http_request_raw(app, "POST", "/api/uploads", body, total, ctype);
    free(body);

    if (r.status < 200 || r.status >= 300) {
        log_line(app, "/upload failed HTTP %d: %.200s", r.status, r.body ? r.body : "");
        free(r.body);
        return;
    }
    char url[MAX_LINE] = "";
    if (!json_top_string(r.body, r.body_len, "url", url, sizeof(url)) || !url[0]) {
        log_line(app, "/upload: response missing url");
        free(r.body);
        return;
    }
    free(r.body);

    /* The server may answer with a path rather than an absolute URL;
     * make it absolute so the link is clickable from any client. */
    char message[MAX_LINE];
    if (strncmp(url, "http://", 7) == 0 || strncmp(url, "https://", 8) == 0)
        snprintf(message, sizeof(message), "📸 %s", url);
    else
        snprintf(message, sizeof(message), "📸 %s%s", app->url.base, url);

    const char *network = app->windows[app->current].network;
    const char *channel = app->windows[app->current].channel;
    add_pending_echo(app, network, channel, own_nick_for_network(app, network), message);
    enqueue_send(app, network, channel, message);
}

/* ── /archive open|purge ───────────────────────────────────────────────
 * `open` re-opens an archived window locally and pulls its scrollback
 * back; `purge` is the DESTRUCTIVE delete of that target's history and
 * requires the target to be named explicitly — there is deliberately no
 * "purge everything" form. */
static void archive_command(struct app *app, const char *rest) {
    while (*rest == ' ') rest++;
    const char *network = app->windows[app->current].network;

    if (strncmp(rest, "open ", 5) == 0) {
        const char *target = rest + 5;
        while (*target == ' ') target++;
        if (!*target) {
            log_line(app, "/archive open requires a target");
            return;
        }
        add_window_ex(app, network, target, true);
        enqueue_fetch(app, network, target);
        log_line(app, "reopened archived window %s", target);
        return;
    }

    if (strncmp(rest, "purge ", 6) == 0) {
        const char *target = rest + 6;
        while (*target == ' ') target++;
        if (!*target) {
            log_line(app, "/archive purge requires a target");
            return;
        }
        char *slug = url_encode(network);
        char *tgt = url_encode(target);
        char *path = xasprintf("/networks/%s/archive/%s", slug, tgt);
        free(slug);
        free(tgt);
        struct http_response r = http_request(app, "DELETE", path, NULL);
        free(path);
        if (r.status >= 200 && r.status < 300) log_line(app, "purged archived scrollback for %s", target);
        else log_line(app, "/archive purge failed HTTP %d: %.200s", r.status, r.body ? r.body : "");
        free(r.body);
        return;
    }

    log_line(app, "/archive [open <target>|purge <target>]");
}

/* ── Services shortcuts ────────────────────────────────────────────────
 * /cs /ns /ms /os /hs /rs → the conventional service nicks. Keyed on the
 * first letter, which is unambiguous across the six. */
static const char *service_for_shortcut(char c) {
    switch (c) {
    case 'c': return "ChanServ";
    case 'n': return "NickServ";
    case 'm': return "MemoServ";
    case 'o': return "OperServ";
    case 'h': return "HelpServ";
    case 'r': return "RootServ";
    default:  return "NickServ";
    }
}

/* ── /notify — presence watch list ─────────────────────────────────────
 * A REST resource (GET/POST/DELETE /notify), NOT the `watchlist` push,
 * which is the separate keyword-highlight list. Sharing the irssi verb
 * names between two different server stores is a real trap: /notify
 * watches PEOPLE, /hilight watches WORDS. */
static void notify_command(struct app *app, const char *rest) {
    while (*rest == ' ') rest++;
    /* The watch list is per-network (it maps to that session's
     * MONITOR/WATCH registration upstream), so every call is scoped to
     * the active window's network. */
    char *slug = url_encode(app->windows[app->current].network);
    if (!*rest || strcmp(rest, "list") == 0) {
        char *path = xasprintf("/networks/%s/notify", slug);
        struct http_response r = http_request(app, "GET", path, NULL);
        free(path);
        if (r.status < 200 || r.status >= 300) {
            log_line(app, "/notify failed HTTP %d", r.status);
        } else {
            json_doc *doc = json_parse(r.body, r.body_len, NULL, 0);
            const json_value *list = json_root(doc);
            log_line(app, "--- watched nicks (%zu)", json_len(list));
            for (size_t i = 0; i < json_len(list); i++) {
                const json_value *row = json_at(list, i);
                const char *nick = json_string(json_get(row, "nick"));
                const char *presence = json_string(json_get(row, "presence"));
                if (nick) log_line(app, "  %-20s %s", nick, presence ? presence : "unknown");
            }
            if (json_len(list) == 0) log_line(app, "  (none — /notify <nick> to add)");
            json_free(doc);
        }
        free(r.body);
        free(slug);
        return;
    }
    if (strncmp(rest, "del ", 4) == 0 || strncmp(rest, "-", 1) == 0) {
        const char *nick = rest[0] == '-' ? rest + 1 : rest + 4;
        while (*nick == ' ') nick++;
        char *enc = url_encode(nick);
        char *path = xasprintf("/networks/%s/notify/%s", slug, enc);
        free(enc);
        struct http_response r = http_request(app, "DELETE", path, NULL);
        free(path);
        if (r.status >= 200 && r.status < 300) log_line(app, "no longer watching %s", nick);
        else log_line(app, "/notify del failed HTTP %d", r.status);
        free(r.body);
        free(slug);
        return;
    }
    /* Bare nicks (possibly several) are an add. */
    char nicks_json[MAX_LINE];
    char *arr = json_array_words(rest);
    snprintf(nicks_json, sizeof(nicks_json), "{\"nicks\":%s}", arr);
    free(arr);
    char *add_path = xasprintf("/networks/%s/notify", slug);
    struct http_response r = http_request(app, "POST", add_path, nicks_json);
    free(add_path);
    if (r.status >= 200 && r.status < 300) log_line(app, "watching %s", rest);
    else log_line(app, "/notify failed HTTP %d: %.200s", r.status, r.body);
    free(r.body);
    free(slug);
}

/* ── /list — channel directory ─────────────────────────────────────────
 * A full LIST is expensive on a large network, so grappa runs it as a
 * background scan (POST .../directory/refresh) that reports progress via
 * directory_* events, and serves the result from a cached table. Bare
 * /list reads the cache; `/list -refresh` starts a new scan. */
static void directory_command(struct app *app, const char *rest) {
    while (*rest == ' ') rest++;
    const char *network = app->windows[app->current].network;
    char *slug = url_encode(network);
    if (strcmp(rest, "-refresh") == 0) {
        char *path = xasprintf("/networks/%s/directory/refresh", slug);
        free(slug);
        struct http_response r = http_request(app, "POST", path, "{}");
        free(path);
        if (r.status >= 200 && r.status < 300) log_line(app, "scanning %s channel list...", network);
        else log_line(app, "/list refresh failed HTTP %d: %.200s", r.status, r.body);
        free(r.body);
        return;
    }
    char *path;
    if (*rest) {
        char *q = url_encode(rest);
        path = xasprintf("/networks/%s/directory?q=%s", slug, q);
        free(q);
    } else {
        path = xasprintf("/networks/%s/directory", slug);
    }
    free(slug);
    struct http_response r = http_request(app, "GET", path, NULL);
    free(path);
    if (r.status < 200 || r.status >= 300) {
        log_line(app, "/list failed HTTP %d: %.200s", r.status, r.body);
        free(r.body);
        return;
    }
    json_doc *doc = json_parse(r.body, r.body_len, NULL, 0);
    /* The endpoint may answer with a bare array or an envelope carrying
     * the rows plus scan metadata; accept either rather than guessing. */
    const json_value *root = json_root(doc);
    const json_value *rows = json_type_of(root) == JSON_ARRAY ? root : json_get(root, "channels");
    if (!rows) rows = json_get(root, "entries");
    size_t n = json_len(rows);
    log_line(app, "--- channel directory %s (%zu)", network, n);
    for (size_t i = 0; i < n; i++) {
        const json_value *row = json_at(rows, i);
        const char *name = json_string(json_get(row, "name"));
        const char *topic = json_string(json_get(row, "topic"));
        long users = 0;
        json_long(json_get(row, "users"), &users);
        if (name) log_line(app, "  %-28s %4ld  %.80s", name, users, topic ? topic : "");
    }
    if (n == 0) log_line(app, "  (empty — /list -refresh to scan)");
    json_free(doc);
    free(r.body);
}

/* ── User-defined aliases ──────────────────────────────────────────────
 * Grammar mirrors cicchetto's: $1..$9 positional (missing → empty), $*
 * all args, and an implicit verbatim append when the expansion holds no
 * placeholder. An alias may shadow any builtin except /alias and /unalias
 * (#427); expansion is depth-bounded so `/alias a /a` cannot spin. */
/* Alias storage + expansion live in alias.[ch] — pure, and tested there.
 * These wrappers only add the app lock and the user-facing log lines. */

static void alias_command(struct app *app, const char *rest) {
    while (*rest == ' ') rest++;
    if (!*rest) {
        pthread_mutex_lock(&app->lock);
        size_t count = app->aliases.count;
        log_line(app, "--- aliases (%zu)", count);
        for (size_t i = 0; i < count; i++)
            log_line(app, "  /%-12s %s", app->aliases.entries[i].name,
                     app->aliases.entries[i].expansion);
        pthread_mutex_unlock(&app->lock);
        if (count == 0) log_line(app, "  (none — /alias <name> <expansion>)");
        return;
    }
    const char *sp = strchr(rest, ' ');
    if (!sp) {
        log_line(app, "/alias requires <name> <expansion>");
        return;
    }
    char name[ALIAS_MAX_NAME];
    size_t nlen = (size_t)(sp - rest);
    if (nlen >= sizeof(name)) nlen = sizeof(name) - 1;
    memcpy(name, rest, nlen);
    name[nlen] = '\0';
    const char *expansion = sp + 1;
    while (*expansion == ' ') expansion++;

    pthread_mutex_lock(&app->lock);
    alias_set_result res = alias_set(&app->aliases, name, expansion);
    pthread_mutex_unlock(&app->lock);
    switch (res) {
    case ALIAS_SET_OK:
        log_line(app, "alias /%s = %s", name, expansion);
        break;
    case ALIAS_SET_NON_SHADOWABLE:
        log_line(app, "/alias: /%s can't be aliased — it's needed to manage aliases", name);
        break;
    case ALIAS_SET_FULL:
        log_line(app, "/alias: table full (%d)", ALIAS_MAX_ENTRIES);
        break;
    case ALIAS_SET_INVALID:
        log_line(app, "/alias requires <name> <expansion>");
        break;
    }
}

static void alias_remove(struct app *app, const char *name) {
    while (*name == ' ') name++;
    pthread_mutex_lock(&app->lock);
    bool found = alias_unset(&app->aliases, name);
    pthread_mutex_unlock(&app->lock);
    if (found) log_line(app, "alias /%s removed", name);
    else log_line(app, "/unalias: no such alias: %s", name);
}

static void handle_command(struct app *app, const char *input) {
    /* Alias expansion happens BEFORE dispatch, so an expanded alias flows
     * through the ordinary command path and cannot reach a second, parallel
     * implementation. Bounded so a self-referential alias terminates.
     *
     * Works on a LOCAL copy: internal callers pass string literals
     * (`handle_command(app, "/close")`), and the dispatcher itself splits
     * arguments in place with `*sp = 0`. Writing through to the caller's
     * buffer would be undefined behaviour for those. */
    char line[MAX_LINE];
    pthread_mutex_lock(&app->lock);
    alias_expand(&app->aliases, input, line, sizeof(line));
    pthread_mutex_unlock(&app->lock);
    handle_command_dispatch(app, line);
}

static void handle_command_dispatch(struct app *app, char *line) {
    if (strcmp(line, "/quit") == 0) {
        logout_grappa(app);
        app->running = false;
    } else if (strcmp(line, "/exit") == 0) {
        app->running = false;
    } else if (strcmp(line, "/help") == 0) {
        show_help(app);
    } else if (strncmp(line, "/help ", 6) == 0) {
        show_command_help(app, line + 6);
    } else if (strncmp(line, "/mouse", 6) == 0 && (line[6] == ' ' || line[6] == '\0')) {
        /* Mouse tracking and the terminal's own text selection are mutually
         * exclusive — while shottino is tracking, the terminal forwards
         * button/motion events here instead of selecting. Shift-drag
         * overrides tracking in most terminals, but that is a workaround,
         * not a setting, so this makes the trade explicit and switchable. */
        const char *rest = line + 6;
        while (*rest == ' ') rest++;
        bool want = app->mouse_enabled;
        if (!*rest) want = !app->mouse_enabled;
        else if (strcmp(rest, "on") == 0) want = true;
        else if (strcmp(rest, "off") == 0) want = false;
        else {
            log_line(app, "/mouse [on|off] — bare /mouse toggles");
            return;
        }
        app->mouse_enabled = want;
        mouse_apply(app);
        if (want)
            log_line(app, "mouse tracking ON — click media links to preview; "
                          "terminal text selection is suppressed (Shift-drag usually still works)");
        else
            log_line(app, "mouse tracking OFF — select and copy with the mouse as usual; "
                          "click-to-preview is disabled until /mouse on");
    } else if (strcmp(line, "/chat") == 0) {
        pthread_mutex_lock(&app->lock);
        app->panel = PANEL_CHAT;
        pthread_mutex_unlock(&app->lock);
    } else if (strcmp(line, "/archive") == 0) {
        open_panel(app, PANEL_ARCHIVE);
    } else if (strncmp(line, "/archive ", 9) == 0) {
        archive_command(app, line + 9);
    } else if (strcmp(line, "/settings") == 0) {
        open_panel(app, PANEL_SETTINGS);
    } else if (strcmp(line, "/admin") == 0) {
        open_panel(app, PANEL_ADMIN);
    } else if (strcmp(line, "/share") == 0) {
        mint_share_link(app);
    } else if (strcmp(line, "/media") == 0 || strncmp(line, "/media ", 7) == 0) {
        const char *rest = line[6] ? line + 7 : "";
        while (*rest == ' ') rest++;
        if (!*rest) app->inline_media_enabled = !app->inline_media_enabled;
        else if (strcmp(rest, "on") == 0) app->inline_media_enabled = true;
        else if (strcmp(rest, "off") == 0) app->inline_media_enabled = false;
        else { log_line(app, "/media [on|off] — bare /media toggles inline images"); return; }
        log_line(app, "inline images %s (terminal graphics: %s)",
                 app->inline_media_enabled ? "ON" : "OFF", media_protocol_name(app->proto));
    } else if (strcmp(line, "/preview-ascii") == 0) {
        /* Force the character-art renderer even where a graphics protocol
         * exists — useful over a link that mangles binary escapes, or just
         * to see the art. */
        char url[MAX_LINE];
        bool is_video;
        pthread_mutex_lock(&app->lock);
        snprintf(url, sizeof(url), "%s", app->last_media_url);
        is_video = app->last_media_is_video;
        pthread_mutex_unlock(&app->lock);
        if (!url[0]) log_line(app, "/preview-ascii: no image or video link seen yet");
        else request_preview(app, url, is_video, true);
    } else if (strcmp(line, "/preview") == 0) {
        /* The keyboard route to click-to-preview. With mouse tracking off
         * by default (so the terminal keeps its own selection), this is
         * how the preview stays reachable — the feature is not gated on
         * surrendering copy/paste. */
        char url[MAX_LINE];
        bool is_video;
        pthread_mutex_lock(&app->lock);
        snprintf(url, sizeof(url), "%s", app->last_media_url);
        is_video = app->last_media_is_video;
        pthread_mutex_unlock(&app->lock);
        if (!url[0]) log_line(app, "/preview: no image or video link seen yet in this session");
        else request_preview(app, url, is_video, false);
    } else if (strcmp(line, "/open") == 0) {
        open_external_url(app, app->last_url);
    } else if (strcmp(line, "/clear") == 0) {
        clear_active_window_log(app);
    } else if (strcmp(line, "/close") == 0) {
        struct window w;
        pthread_mutex_lock(&app->lock);
        w = app->windows[app->current];
        pthread_mutex_unlock(&app->lock);
        if (w.channel[0] == '#' || w.channel[0] == '&' || w.channel[0] == '+' || w.channel[0] == '!') {
            struct job job = { .kind = JOB_PART };
            snprintf(job.network, sizeof(job.network), "%s", w.network);
            snprintf(job.channel, sizeof(job.channel), "%s", w.channel);
            enqueue_job(app, job);
        } else if (strcmp(w.channel, "$server") == 0) {
            log_line(app, "cannot close server window");
        } else {
            struct job job = { .kind = JOB_CLOSE_QUERY };
            snprintf(job.network, sizeof(job.network), "%s", w.network);
            snprintf(job.channel, sizeof(job.channel), "%s", w.channel);
            enqueue_job(app, job);
        }
    } else if (strncmp(line, "/join ", 6) == 0 && line[6]) {
        struct job job = { .kind = JOB_JOIN };
        snprintf(job.network, sizeof(job.network), "%s", app->windows[app->current].network);
        snprintf(job.channel, sizeof(job.channel), "%s", line + 6);
        enqueue_job(app, job);
    } else if (strncmp(line, "/j ", 3) == 0 && line[3]) {
        struct job job = { .kind = JOB_JOIN };
        snprintf(job.network, sizeof(job.network), "%s", app->windows[app->current].network);
        snprintf(job.channel, sizeof(job.channel), "%s", line + 3);
        enqueue_job(app, job);
    } else if (strcmp(line, "/part") == 0) {
        handle_command(app, "/close");
    } else if (strncmp(line, "/nick ", 6) == 0 && line[6]) {
        struct job job = { .kind = JOB_NICK };
        snprintf(job.network, sizeof(job.network), "%s", app->windows[app->current].network);
        snprintf(job.channel, sizeof(job.channel), "%s", app->windows[app->current].channel);
        snprintf(job.arg1, sizeof(job.arg1), "%s", line + 6);
        enqueue_job(app, job);
    } else if (strncmp(line, "/msg ", 5) == 0) {
        char *sp = strchr(line + 5, ' ');
        if (!sp) log_line(app, "/msg requires <target> <body>");
        else {
            *sp = 0;
            const char *target = line + 5;
            const char *body = sp + 1;
            const char *network = app->windows[app->current].network;
            query_window(app, target);
            add_pending_echo(app, network, target, own_nick_for_network(app, network), body);
            enqueue_send(app, app->windows[app->current].network, target, body);
        }
    } else if (strcmp(line, "/query") == 0 || strcmp(line, "/q") == 0) {
        log_line(app, "/query requires a nick; use /query nick or /q nick");
    } else if (strncmp(line, "/query ", 7) == 0 && line[7]) {
        query_window(app, line + 7);
    } else if (strncmp(line, "/q ", 3) == 0 && line[3]) {
        query_window(app, line + 3);
    } else if (strncmp(line, "/me ", 4) == 0 && line[4]) {
        char *body = xasprintf("\001ACTION %s\001", line + 4);
        send_message(app, body);
        free(body);
    } else if (strncmp(line, "/disconnect", 11) == 0) {
        char *rest = line + 11;
        while (*rest == ' ') rest++;
        struct job job = { .kind = JOB_NETWORK_STATE };
        snprintf(job.arg1, sizeof(job.arg1), "parked");
        if (!*rest) {
            snprintf(job.network, sizeof(job.network), "%s", app->windows[app->current].network);
            enqueue_job(app, job);
        }
        else {
            char *sp = strchr(rest, ' ');
            if (sp) { *sp = 0; snprintf(job.arg2, sizeof(job.arg2), "%s", sp + 1); }
            snprintf(job.network, sizeof(job.network), "%s", rest);
            enqueue_job(app, job);
        }
    } else if (strncmp(line, "/connect ", 9) == 0 && line[9]) {
        struct job job = { .kind = JOB_NETWORK_STATE };
        snprintf(job.network, sizeof(job.network), "%s", line + 9);
        snprintf(job.arg1, sizeof(job.arg1), "connected");
        enqueue_job(app, job);
    } else if (strncmp(line, "/away", 5) == 0) {
        char *rest = line + 5;
        while (*rest == ' ') rest++;
        char *net = json_escape(app->windows[app->current].network);
        char *payload;
        if (*rest) {
            if (*rest == ':') rest++;
            char *reason = json_escape(rest);
            payload = xasprintf("{\"action\":\"set\",\"network\":\"%s\",\"reason\":\"%s\"}", net, reason);
            free(reason);
        } else {
            payload = xasprintf("{\"action\":\"unset\",\"network\":\"%s\"}", net);
        }
        ws_push_user(app, "away", payload);
        free(net);
        free(payload);
    } else if (strncmp(line, "/whois ", 7) == 0 && line[7]) {
        char *nick = json_escape(line + 7);
        char *payload = xasprintf("{\"network_id\":%d,\"nick\":\"%s\"}", current_network_id(app), nick);
        ws_push_user(app, "whois", payload);
        free(nick); free(payload);
    } else if (strncmp(line, "/whowas ", 8) == 0 && line[8]) {
        char *nick = json_escape(line + 8);
        char *payload = xasprintf("{\"network_id\":%d,\"nick\":\"%s\"}", current_network_id(app), nick);
        ws_push_user(app, "whowas", payload);
        free(nick); free(payload);
    } else if (strcmp(line, "/lusers") == 0) {
        char *payload = xasprintf("{\"network_id\":%d}", current_network_id(app));
        ws_push_user(app, "lusers", payload);
        free(payload);
    } else if (strncmp(line, "/who", 4) == 0) {
        const char *target = line[4] ? line + 5 : current_channel(app);
        char *chan = json_escape(target && *target ? target : current_channel(app));
        char *payload = xasprintf("{\"network_id\":%d,\"channel\":\"%s\"}", current_network_id(app), chan);
        ws_push_user(app, "who", payload);
        free(chan); free(payload);
    } else if (strncmp(line, "/names", 6) == 0) {
        const char *target = line[6] ? line + 7 : current_channel(app);
        char *chan = json_escape(target && *target ? target : current_channel(app));
        char *origin = json_escape(current_channel(app));
        char *payload = xasprintf("{\"network_id\":%d,\"channel\":\"%s\",\"origin_window\":\"%s\"}", current_network_id(app), chan, origin);
        ws_push_user(app, "names", payload);
        free(chan); free(origin); free(payload);
    } else if (strcmp(line, "/members") == 0 || strcmp(line, "/users") == 0) {
        struct job job = { .kind = JOB_MEMBERS };
        snprintf(job.network, sizeof(job.network), "%s", app->windows[app->current].network);
        snprintf(job.channel, sizeof(job.channel), "%s", app->windows[app->current].channel);
        enqueue_job(app, job);
    } else if (strncmp(line, "/topic", 6) == 0) {
        const char *rest = line + 6;
        while (*rest == ' ') rest++;
        if (!*rest) {
            char *chan = json_escape(current_channel(app));
            char *payload = xasprintf("{\"network_id\":%d,\"channel\":\"%s\",\"origin_window\":\"%s\"}", current_network_id(app), chan, chan);
            ws_push_user(app, "names", payload);
            free(chan); free(payload);
            log_line(app, "requested topic snapshot for %s", current_channel(app));
        } else {
            struct job job = { .kind = JOB_TOPIC };
            snprintf(job.network, sizeof(job.network), "%s", app->windows[app->current].network);
            snprintf(job.channel, sizeof(job.channel), "%s", app->windows[app->current].channel);
            snprintf(job.arg1, sizeof(job.arg1), "%s", strcmp(rest, "-delete") == 0 ? " " : rest);
            enqueue_job(app, job);
        }
    } else if (strncmp(line, "/quote ", 7) == 0 && line[7]) {
        char *raw = json_escape(line + 7);
        char *payload = xasprintf("{\"network_id\":%d,\"line\":\"%s\"}", current_network_id(app), raw);
        ws_push_user(app, "raw", payload);
        free(raw); free(payload);
    } else if (strncmp(line, "/oper ", 6) == 0) {
        char *rest = line + 6;
        char *sp = strchr(rest, ' ');
        if (!sp) log_line(app, "/oper requires <name> <password>");
        else {
            *sp = 0;
            char *name = json_escape(rest);
            char *pw = json_escape(sp + 1);
            char *payload = xasprintf("{\"network_id\":%d,\"name\":\"%s\",\"password\":\"%s\"}", current_network_id(app), name, pw);
            ws_push_user(app, "oper", payload);
            free(name); free(pw); free(payload);
        }
    } else if (strncmp(line, "/op ", 4) == 0 || strncmp(line, "/deop ", 6) == 0 || strncmp(line, "/voice ", 7) == 0 || strncmp(line, "/devoice ", 9) == 0) {
        const char *event = line[1] == 'o' ? "op" : (line[1] == 'v' ? "voice" : (line[3] == 'p' ? "deop" : "devoice"));
        char *rest = strchr(line + 1, ' ');
        char *nicks = json_array_words(rest ? rest + 1 : "");
        char *extra = xasprintf("\"nicks\":%s", nicks);
        push_simple_channel_action(app, event, extra);
        free(nicks); free(extra);
    } else if (strncmp(line, "/kick ", 6) == 0) {
        char *rest = line + 6;
        char *sp = strchr(rest, ' ');
        if (sp) *sp = 0;
        char *nick = json_escape(rest);
        char *reason = json_escape(sp ? sp + 1 : "");
        char *extra = xasprintf("\"nick\":\"%s\",\"reason\":\"%s\"", nick, reason);
        push_simple_channel_action(app, "kick", extra);
        free(nick); free(reason); free(extra);
    } else if (strncmp(line, "/ban ", 5) == 0 || strncmp(line, "/unban ", 7) == 0) {
        bool unban = strncmp(line, "/unban ", 7) == 0;
        char *mask = json_escape(line + (unban ? 7 : 5));
        char *extra = xasprintf("\"mask\":\"%s\"", mask);
        push_simple_channel_action(app, unban ? "unban" : "ban", extra);
        free(mask); free(extra);
    } else if (strcmp(line, "/banlist") == 0) {
        push_simple_channel_action(app, "banlist", NULL);
    } else if (strncmp(line, "/invite ", 8) == 0) {
        char *nick = json_escape(line + 8);
        char *extra = xasprintf("\"nick\":\"%s\"", nick);
        push_simple_channel_action(app, "invite", extra);
        free(nick); free(extra);
    } else if (strncmp(line, "/umode ", 7) == 0) {
        char *modes = json_escape(line + 7);
        char *payload = xasprintf("{\"network_id\":%d,\"modes\":\"%s\"}", current_network_id(app), modes);
        ws_push_user(app, "umode", payload);
        free(modes); free(payload);
    } else if (strncmp(line, "/mode", 5) == 0 && (line[5] == ' ' || line[5] == '\0')) {
        /* The server has taken a structured `mode` verb since before this
         * client existed — {network_id, target, modes, params}. The old
         * body told the user to fall back to `/quote MODE`, which skipped
         * the server's validation and its channel_modes_changed
         * broadcast. Grammar mirrors cicchetto's:
         *   /mode                → show current channel's modes
         *   /mode +ns            → apply to the current channel
         *   /mode #chan +ns      → apply to a named channel
         *   /mode +k secret      → mode letters plus positional params
         */
        char *rest = line + 5;
        while (*rest == ' ') rest++;
        char target[MAX_CHANNEL];
        snprintf(target, sizeof(target), "%s", current_channel(app));
        if (*rest == '#' || *rest == '&' || *rest == '+' || *rest == '!') {
            char *sp = strchr(rest, ' ');
            if (sp) {
                *sp = 0;
                snprintf(target, sizeof(target), "%s", rest);
                rest = sp + 1;
                while (*rest == ' ') rest++;
            } else {
                snprintf(target, sizeof(target), "%s", rest);
                rest += strlen(rest);
            }
        }
        if (!target[0] || strcmp(target, "$server") == 0) {
            log_line(app, "/mode needs a channel; use /mode #chan +modes from a server window");
        } else {
            /* Split "+k secret" into the mode string and its params. */
            char modes[128] = "";
            char *sp = strchr(rest, ' ');
            const char *params_src = "";
            if (sp) { *sp = 0; params_src = sp + 1; }
            snprintf(modes, sizeof(modes), "%s", rest);
            char *tgt = json_escape(target);
            char *mds = json_escape(modes);
            char *params = json_array_words(params_src);
            char *payload = xasprintf(
                "{\"network_id\":%d,\"target\":\"%s\",\"modes\":\"%s\",\"params\":%s}",
                current_network_id(app), tgt, mds, params);
            ws_push_user(app, "mode", payload);
            free(tgt); free(mds); free(params); free(payload);
        }
    } else if (strcmp(line, "/links") == 0) {
        char *payload = xasprintf("{\"network_id\":%d}", current_network_id(app));
        ws_push_user(app, "links", payload);
        free(payload);
    } else if (strcmp(line, "/motd") == 0 || strcmp(line, "/info") == 0 ||
               strcmp(line, "/version") == 0) {
        /* All three answer with a `server_reply` bundle discriminated by
         * source, so one arm covers them. */
        char *payload = xasprintf("{\"network_id\":%d}", current_network_id(app));
        ws_push_user(app, line + 1, payload);
        free(payload);
    } else if (strncmp(line, "/stats", 6) == 0 && (line[6] == ' ' || line[6] == '\0')) {
        /* STATS has no structured verb; it rides `raw`, as in cicchetto.
         * Trailing args are omitted rather than sent empty so the frame
         * stays positionally valid. */
        const char *rest = line + 6;
        while (*rest == ' ') rest++;
        char frame[MAX_LINE];
        if (*rest) snprintf(frame, sizeof(frame), "STATS %s", rest);
        else snprintf(frame, sizeof(frame), "STATS");
        char *raw = json_escape(frame);
        char *payload = xasprintf("{\"network_id\":%d,\"line\":\"%s\"}", current_network_id(app), raw);
        ws_push_user(app, "raw", payload);
        free(raw); free(payload);
    } else if (strncmp(line, "/rehash", 7) == 0 && (line[7] == ' ' || line[7] == '\0')) {
        const char *rest = line + 7;
        while (*rest == ' ') rest++;
        char frame[MAX_LINE];
        if (*rest) snprintf(frame, sizeof(frame), "REHASH %s", rest);
        else snprintf(frame, sizeof(frame), "REHASH");
        char *raw = json_escape(frame);
        char *payload = xasprintf("{\"network_id\":%d,\"line\":\"%s\"}", current_network_id(app), raw);
        ws_push_user(app, "raw", payload);
        free(raw); free(payload);
    } else if (strncmp(line, "/kb ", 4) == 0 || strncmp(line, "/kickban ", 9) == 0) {
        /* Kick + ban as one verb. Banning FIRST is deliberate: kick then
         * ban leaves a window in which the user can rejoin ahead of the
         * ban landing. */
        char *rest = strchr(line + 1, ' ');
        rest++;
        while (*rest == ' ') rest++;
        char *sp = strchr(rest, ' ');
        if (sp) *sp = 0;
        if (!*rest) {
            log_line(app, "/kb requires <nick> [reason]");
        } else {
            char mask[MAX_CHANNEL + 8];
            snprintf(mask, sizeof(mask), "%s!*@*", rest);
            char *emask = json_escape(mask);
            char *ban_extra = xasprintf("\"mask\":\"%s\"", emask);
            push_simple_channel_action(app, "ban", ban_extra);
            free(emask); free(ban_extra);
            char *nick = json_escape(rest);
            char *reason = json_escape(sp ? sp + 1 : "");
            char *kick_extra = xasprintf("\"nick\":\"%s\",\"reason\":\"%s\"", nick, reason);
            push_simple_channel_action(app, "kick", kick_extra);
            free(nick); free(reason); free(kick_extra);
        }
    } else if (strncmp(line, "/cs ", 4) == 0 || strncmp(line, "/ns ", 4) == 0 ||
               strncmp(line, "/ms ", 4) == 0 || strncmp(line, "/os ", 4) == 0 ||
               strncmp(line, "/hs ", 4) == 0 || strncmp(line, "/rs ", 4) == 0 ||
               strcmp(line, "/cs") == 0 || strcmp(line, "/ns") == 0 ||
               strcmp(line, "/ms") == 0 || strcmp(line, "/os") == 0 ||
               strcmp(line, "/hs") == 0 || strcmp(line, "/rs") == 0) {
        /* Services shortcuts: /<x>s <cmd> is a PRIVMSG to the service. A
         * BARE /<x>s sends HELP, which is what cicchetto's services modal
         * opens with. */
        const char *service = service_for_shortcut(line[1]);
        const char *rest = line[3] ? line + 4 : "";
        while (*rest == ' ') rest++;
        const char *body = *rest ? rest : "HELP";
        const char *network = app->windows[app->current].network;
        query_window(app, service);
        add_pending_echo(app, network, service, own_nick_for_network(app, network), body);
        enqueue_send(app, network, service, body);
    } else if (strncmp(line, "/notify", 7) == 0 && (line[7] == ' ' || line[7] == '\0')) {
        notify_command(app, line + 7);
    } else if (strncmp(line, "/hilight ", 9) == 0 || strncmp(line, "/dehilight ", 11) == 0) {
        /* Keyword highlights are a DIFFERENT list from /notify's presence
         * watch — same irssi naming, separate server stores. */
        bool remove = line[1] == 'd';
        const char *rest = strchr(line + 1, ' ') + 1;
        while (*rest == ' ') rest++;
        char *pat = json_escape(rest);
        char *payload = xasprintf("{\"action\":\"%s\",\"pattern\":\"%s\"}", remove ? "del" : "add", pat);
        ws_push_user(app, "watchlist", payload);
        free(pat); free(payload);
    } else if (strncmp(line, "/alias", 6) == 0 && (line[6] == ' ' || line[6] == '\0')) {
        alias_command(app, line + 6);
    } else if (strncmp(line, "/unalias ", 9) == 0) {
        alias_remove(app, line + 9);
    } else if (strncmp(line, "/upload ", 8) == 0) {
        upload_command(app, line + 8);
    } else if (strcmp(line, "/upload") == 0) {
        log_line(app, "/upload <path> — send a local file and post its link");
    } else if (strcmp(line, "/list") == 0 || strncmp(line, "/list ", 6) == 0) {
        directory_command(app, line[5] ? line + 6 : "");
    } else if (strncmp(line, "/watch ", 7) == 0 || strncmp(line, "/highlight ", 11) == 0) {
        char *rest = strchr(line + 1, ' ');
        char action[16] = "list";
        char pattern[MAX_LINE] = "";
        if (rest) sscanf(rest + 1, "%15s %1023[^\n]", action, pattern);
        char *pat = json_escape(pattern);
        char *payload = xasprintf("{\"action\":\"%s\",\"pattern\":\"%s\"}", action, pat);
        ws_push_user(app, "watchlist", payload);
        free(pat); free(payload);
    } else if (strncmp(line, "/window ", 8) == 0 || strncmp(line, "/win ", 5) == 0 || strncmp(line, "/w ", 3) == 0) {
        const char *arg = line[2] == 'w' && line[3] == ' ' ? line + 3 : (line[4] == ' ' ? line + 5 : line + 8);
        int n = atoi(arg);
        if (n > 0 && (size_t)n <= app->window_count) {
            app->current = (size_t)n - 1;
            clear_current_unread_locked(app);
            app->scrollback_offset = 0;
            app->scrollback_pinned = false;
            enqueue_fetch(app, app->windows[app->current].network, app->windows[app->current].channel);
        }
    } else {
        log_line(app, "unknown command: %.40s — /help lists every verb", line);
    }
}

static void handle_enter(struct app *app) {
    app->input[app->input_len] = 0;
    if (app->input_len == 0) return;
    char line[MAX_LINE];
    snprintf(line, sizeof(line), "%s", app->input);
    add_history(app, line);
    app->input_len = 0;
    app->input[0] = 0;
    if (line[0] == '/') handle_command(app, line);
    else {
        const char *network = app->windows[app->current].network;
        const char *channel = app->windows[app->current].channel;
        /* $server is read-only by server contract, so say so HERE rather
         * than firing a request that can only come back 400. The client
         * knows the rule; making the user decode an HTTP status to learn
         * it is the failure this replaces. Commands still work from a
         * $server window — only a bare PRIVMSG has nowhere to go. */
        if (strcmp(channel, "$server") == 0) {
            log_line(app, "[%s/$server] --- the server window is read-only — "
                          "switch to a channel, or use /msg <nick> <text> or /join #chan",
                     network);
        } else {
            add_pending_echo(app, network, channel, own_nick_for_network(app, network), line);
            enqueue_send(app, network, channel, line);
        }
    }
}

/* Topmost recorded media region containing screen cell (x, y), or NULL.
 * Caller holds app->lock. */
static const struct link_region *region_at(struct app *app, int x, int y) {
    for (size_t i = 0; i < app->link_region_count; i++) {
        const struct link_region *r = &app->link_regions[i];
        if (y >= r->y0 && y <= r->y1 && x >= r->x0 && x <= r->x1) return r;
    }
    return NULL;
}

/* Map a mouse event to a media region: motion updates the hover hint, a left
 * button press over a region opens its preview. */
static void handle_mouse(struct app *app) {
    MEVENT ev;
    if (getmouse(&ev) != OK) return;
    bool click = ev.bstate & (BUTTON1_PRESSED | BUTTON1_CLICKED);

    pthread_mutex_lock(&app->lock);
    const struct link_region *r = region_at(app, ev.x, ev.y);
    char url[MAX_LINE];
    bool is_video = false;
    bool hit = r != NULL;
    if (r) {
        snprintf(url, sizeof(url), "%s", r->url);
        is_video = r->is_video;
        snprintf(app->hover_url, sizeof(app->hover_url), "%s", r->url);
    } else {
        app->hover_url[0] = 0;
    }
    pthread_mutex_unlock(&app->lock);

    if (click && hit) {
        /* Clicking a media link previews it, using the terminal's
         * graphics protocol when there is one and character art when
         * there is not — the same path as /preview. */
        request_preview(app, url, is_video, false);
        pthread_mutex_lock(&app->lock);
        app->hover_url[0] = 0;
        pthread_mutex_unlock(&app->lock);
    }
}

static void event_loop(struct app *app) {
    setlocale(LC_ALL, "");
    initscr();
    init_theme();
    /* After init_theme: the mIRC pair pool sits above the theme's fixed
     * pairs and needs COLORS/COLOR_PAIRS, which start_color() populates. */
    mirc_colors_init();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    timeout(50);
    mouse_apply(app);
    app->running = true;
    while (app->running) {
        ws_pump(app);
        /* A requested preview displays as soon as the worker finishes.
         * Until then the client keeps running normally — that is the
         * whole point of splitting decode from display. */
        pthread_mutex_lock(&app->lock);
        bool preview_ready =
            app->preview_pending &&
            (app->preview.state == IM_READY || app->preview.state == IM_FAILED);
        pthread_mutex_unlock(&app->lock);
        if (preview_ready) show_preview(app);
        draw(app);
        int ch = getch();
        if (ch == ERR) continue;
        if (ch == '\n' || ch == '\r') {
            handle_enter(app);
        } else if (ch == 27) {
            pthread_mutex_lock(&app->lock);
            app->panel = PANEL_CHAT;
            pthread_mutex_unlock(&app->lock);
        } else if (ch == KEY_MOUSE) {
            handle_mouse(app);
        } else if (ch == 14) {
            cycle_window(app, 1);
        } else if (ch == 16) {
            cycle_window(app, -1);
#ifdef KEY_CTAB
        } else if (ch == KEY_CTAB) {
            cycle_window(app, 1);
#endif
        } else if (ch == KEY_PPAGE) {
            scroll_chat(app, 10);
        } else if (ch == KEY_NPAGE) {
            scroll_chat(app, -10);
        } else if (ch == KEY_HOME) {
            scroll_chat(app, 1000000);
        } else if (ch == KEY_END) {
            scroll_bottom(app);
        } else if (ch == '\t' || ch == KEY_BTAB) {
            complete_input(app);
        } else if (ch == KEY_UP) {
            history_prev(app);
        } else if (ch == KEY_DOWN) {
            history_next(app);
        } else if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
            if (app->input_len > 0) app->input[--app->input_len] = 0;
        } else if (isprint(ch) && app->input_len + 1 < sizeof(app->input)) {
            app->input[app->input_len++] = (char)ch;
            app->input[app->input_len] = 0;
        }
    }
    mouse_reporting(false);
    endwin();
}

/* Usage text, written to `out` so `--help` can go to stdout and exit 0
 * while a usage ERROR goes to stderr and exits 2 — the distinction every
 * other CLI makes, and the one that lets a packaging smoke test tell
 * "the binary runs" apart from "the binary is broken". */
static void print_usage(FILE *out, const char *prog) {
    fprintf(out, "usage: %s [--auto|--user|--visitor] https://grappa.example.net IDENTIFIER PASSWORD\n", prog);
    fprintf(out, "       %s --user --login-email user@example.net https://grappa.example.net PASSWORD\n", prog);
    fprintf(out, "       %s --share https://grappa.example.net/share/<token>\n", prog);
    fprintf(out, "\n");
    fprintf(out, "  --auto           let the server classify the identifier (default)\n");
    fprintf(out, "  --user           registered-user login; a plain account name becomes\n");
    fprintf(out, "                   name@shottino.local\n");
    fprintf(out, "  --visitor        visitor nick flow\n");
    fprintf(out, "  --login-email E  use E as the grappa login identifier; the IRC nick comes\n");
    fprintf(out, "                   from the network credential, not from the email\n");
    fprintf(out, "  --share URL      consume a visitor session-share link (mint one with /share);\n");
    fprintf(out, "                   both host and token are read from the URL\n");
    fprintf(out, "  --help, -h       show this help and exit\n");
    fprintf(out, "\nOnce connected, /help lists every command.\n");
}

/* #451/#324 — retain the deployment's HTTP host aliases at boot from the
 * same /api/server-settings payload cic reads (ServerSettings.public_view
 * → http_host_aliases). Used with app->url.host to classify first-party
 * /uploads/ links for inline auto-render. On any failure the set stays
 * empty, which is the restrictive fallback: only the connect host is
 * first-party. Fetched BEFORE the first scrollback render so seeded rows
 * classify correctly. */
static void load_http_host_aliases(struct app *app) {
    app->http_host_alias_count = 0;
    struct http_response r = http_request(app, "GET", "/api/server-settings", NULL);
    if (r.status >= 200 && r.status < 300 && r.body) {
        json_doc *doc = json_parse(r.body, r.body_len, NULL, 0);
        if (doc) {
            const json_value *list = json_get(json_root(doc), "http_host_aliases");
            if (list)
                for (size_t i = 0; i < json_len(list) &&
                                   app->http_host_alias_count < MAX_HTTP_ALIASES;
                     i++) {
                    const char *h = json_string(json_at(list, i));
                    if (h && h[0])
                        snprintf(app->http_host_aliases[app->http_host_alias_count++],
                                 sizeof(app->http_host_aliases[0]), "%s", h);
                }
            json_free(doc);
        }
    }
    free(r.body);
}

int main(int argc, char **argv) {
    const char *mode = "auto";
    const char *login_override = NULL;
    /* Checked before the option loop so --help works from any position and
     * never requires the other arguments to be present. */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(stdout, argv[0]);
            return 0;
        }
    }
    /* Options are accepted ANYWHERE, not only before the first positional.
     *
     * The old loop stopped at the first non-option argument, so
     * `shottino https://host --user name pass` silently ignored --user:
     * the client fell back to auto mode and the server classified the
     * name as a VISITOR nick. Nothing said so — the run looked
     * successful, just as the wrong kind of session, with different
     * persistence and a different subject key.
     *
     * A flag that is read in one position and ignored in another is worse
     * than one that is rejected: the failure is silent and the result is
     * plausible. Positionals are collected separately so order stops
     * mattering. */
    const char *positional[8];
    int positional_count = 0;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strncmp(a, "--", 2) != 0) {
            if (positional_count < (int)(sizeof(positional) / sizeof(positional[0])))
                positional[positional_count++] = a;
            continue;
        }
        if (strcmp(a, "--user") == 0) mode = "user";
        else if (strcmp(a, "--visitor") == 0) mode = "visitor";
        else if (strcmp(a, "--share") == 0) mode = "share";
        else if (strcmp(a, "--auto") == 0) mode = "auto";
        else if (strcmp(a, "--login-email") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "--login-email requires an email-like identifier\n");
                return 2;
            }
            mode = "user";
            login_override = argv[++i];
        } else if (strncmp(a, "--login-email=", 14) == 0) {
            mode = "user";
            login_override = a + 14;
        } else {
            fprintf(stderr, "unknown option: %s\n", a);
            return 2;
        }
    }
    bool share_mode = strcmp(mode, "share") == 0;
    int expected = share_mode ? 1 : (login_override ? 2 : 3);
    if (positional_count != expected) {
        /* Usage ERROR: stderr + exit 2. One definition of the text,
         * shared with --help, so the two cannot drift. */
        print_usage(stderr, argv[0]);
        return 2;
    }

    startup("starting (%s mode)", mode);
    SSL_library_init();
    SSL_load_error_strings();
    struct app *app = calloc(1, sizeof(*app));
    if (!app) die("out of memory");
    pthread_mutex_init(&app->lock, NULL);
    pthread_mutex_init(&app->jobs_lock, NULL);
    pthread_cond_init(&app->jobs_cond, NULL);
    app->ws.fd = -1;
    app->mouse_enabled = false;
    app->inline_media_enabled = true;
    char *share_base = NULL, *share_token = NULL;
    const char *server_url;
    if (share_mode) {
        if (!split_share_url(positional[0], &share_base, &share_token))
            die("invalid share URL; expected https://host/share/<token>");
        server_url = share_base;
    } else {
        server_url = positional[0];
    }
    startup("parsing server URL %s", server_url);
    if (!parse_url(server_url, &app->url)) die("invalid base URL: %s", server_url);
    startup("initializing TLS context");
    app->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!app->ssl_ctx) die("failed to create TLS context");
    SSL_CTX_set_default_verify_paths(app->ssl_ctx);
    SSL_CTX_set_verify(app->ssl_ctx, SSL_VERIFY_PEER, NULL);

    bool authed;
    if (share_mode) {
        startup("consuming share link");
        authed = attach_or_consume(app, app->url.base, share_token);
        free(share_base);
        free(share_token);
    } else {
        const char *identifier = login_override ? login_override : positional[1];
        const char *password = login_override ? positional[1] : positional[2];
        if (!login_override && strchr(identifier, '@') == NULL) snprintf(app->login_nick, sizeof(app->login_nick), "%s", identifier);
        char *login_id = login_identifier_for_mode(mode, identifier);
        startup("authenticating as %s", login_id);
        authed = attach_or_login(app, login_id, password);
        free(login_id);
    }
    if (!authed) {
        pthread_cond_destroy(&app->jobs_cond);
        pthread_mutex_destroy(&app->jobs_lock);
        pthread_mutex_destroy(&app->lock);
        SSL_CTX_free(app->ssl_ctx);
        free(app);
        return 1;
    }
    startup("authenticated as %s", app->subject);
    startup("loading networks and channels");
    /* Probe BEFORE the first scrollback fetch. Detection has to precede
     * ncurses anyway (the sixel DA1 query needs the raw tty), and it has
     * to precede parsing too: rows parsed while the protocol is unknown
     * and the feature still off get no image attached, which is why the
     * first screenful used to come up pictureless. */
    app->proto = media_detect(STDIN_FILENO, 120);
    startup("terminal graphics: %s", media_protocol_name(app->proto));
    /* Retain the deployment's upload host set BEFORE any scrollback
     * renders, so first-party /uploads/ links classify from frame one. */
    load_http_host_aliases(app);
    startup("first-party upload hosts: %s + %zu alias(es)", app->url.host,
            app->http_host_alias_count);
    seed_state(app);
    startup("loading initial scrollback for %zu windows", app->window_count);
    for (size_t i = 0; i < app->window_count; i++) fetch_scrollback(app, &app->windows[i]);
    startup("connecting websocket");
    if (ws_connect(app)) {
        startup("joining websocket topics");
        ws_join_topics(app);
        log_line(app, "websocket connected");
    } else {
        /* Arm the retry timer rather than settling permanently into
         * REST-only mode: a server still coming up is the common cause of
         * a failed first connect, and it will be ready in seconds. */
        ws_schedule_retry(app);
        startup("websocket unavailable; will retry");
        log_line(app, "websocket unavailable; retrying in %ds (REST send/fetch still works)",
                 (int)(app->ws_retry_at - time(NULL)));
    }
    startup("starting background worker");
    pthread_create(&app->worker, NULL, worker_main, app);
    startup("entering terminal UI");
    event_loop(app);
    pthread_mutex_lock(&app->jobs_lock);
    app->worker_stop = true;
    pthread_cond_signal(&app->jobs_cond);
    pthread_mutex_unlock(&app->jobs_lock);
    pthread_join(app->worker, NULL);
    if (app->ws_connected) conn_close(&app->ws);
    for (size_t i = 0; i < app->log_count; i++) free(app->log[i]);
    pthread_cond_destroy(&app->jobs_cond);
    pthread_mutex_destroy(&app->jobs_lock);
    pthread_mutex_destroy(&app->lock);
    SSL_CTX_free(app->ssl_ctx);
    free(app);
    return 0;
}
