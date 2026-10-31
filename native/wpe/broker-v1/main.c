#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <glib-unix.h>
#include <glib.h>
#include <gio/gio.h>
#include <limits.h>
#include <libsoup/soup.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <wpe/webkit.h>
#include <wpe/wpe-platform.h>
#include <wpe/WPEKeysyms.h>

extern void webkit_web_view_bojangles_context_menu_for_key(WebKitWebView *);

extern gboolean webkit_web_context_register_bojangles_http_v1(
    WebKitWebContext *, WebKitURISchemeRequestCallback, gpointer);

/* BoJangles' WPE 2.54 engine exports these bounded navigation/body helpers.
 * Linkage is mandatory so a missing trust-boundary API fails the build. */
extern GBytes *webkit_uri_scheme_request_get_bojangles_inline_http_body(
    WebKitURISchemeRequest *, gsize);
extern gboolean webkit_uri_scheme_request_bojangles_http_body_contains_blob(
    WebKitURISchemeRequest *);
extern gboolean webkit_navigation_action_should_download(
    WebKitNavigationAction *);
extern gboolean webkit_navigation_action_is_main_frame(
    WebKitNavigationAction *);

#define OUTER_MARKER "BOJANGLES_WPE_OUTER_SANDBOX"
#define BOJANGLES_BROWSER_USER_AGENT "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/60.5 Safari/605.1.15"
#define DEFAULT_HOLD_SECONDS 12
#define HARD_TIMEOUT_SECONDS 30

struct Stage4State {
    GMainLoop *loop;
    WebKitWebView *view;
    gboolean snapshot_ok;
    gboolean timed_out;
    unsigned hold_seconds;
};

static gboolean bojangles_permission_request(
    WebKitWebView *view,
    WebKitPermissionRequest *request,
    gpointer user_data)
{
    (void)view;
    (void)user_data;

    if (!WEBKIT_IS_MEDIA_KEY_SYSTEM_PERMISSION_REQUEST(request))
        return FALSE;

    WebKitMediaKeySystemPermissionRequest *media_request =
        WEBKIT_MEDIA_KEY_SYSTEM_PERMISSION_REQUEST(request);
    const char *key_system =
        webkit_media_key_system_permission_get_name(media_request);

    if (key_system && strcmp(key_system, "org.w3.clearkey") == 0) {
        webkit_permission_request_allow(request);
        return TRUE;
    }

    webkit_permission_request_deny(request);
    return TRUE;
}


/* Stage 6 cookie hygiene remains event-driven inside the WPE process. Stage 7
 * may supply a persistent NetworkSession, but cookie names and values are never
 * printed or exported from this policy path. */
#define BJ_STAGE6_MAX_COOKIE_BYTES 4096U

struct Stage6CookieHygiene {
    WebKitCookieManager *manager;
    gboolean audit_active;
    gboolean audit_pending;
    guint changed_count;
    guint audit_count;
    guint delete_count;
};

static gboolean stage6_cookie_should_delete(SoupCookie *cookie)
{
    const char *domain = soup_cookie_get_domain(cookie);
    const char *name = soup_cookie_get_name(cookie);
    const char *path = soup_cookie_get_path(cookie);
    gboolean secure = soup_cookie_get_secure(cookie);

    if (!domain || !*domain)
        return TRUE;

    char *serialized = soup_cookie_to_set_cookie_header(cookie);
    if (!serialized)
        return TRUE;
    gsize serialized_size = strlen(serialized);
    char *lower = g_ascii_strdown(serialized, -1);
    gboolean same_site_none = lower && strstr(lower, "samesite=none") != NULL;
    g_free(lower);
    g_free(serialized);

    if (serialized_size > BJ_STAGE6_MAX_COOKIE_BYTES)
        return TRUE;
    if (same_site_none && !secure)
        return TRUE;

    if (name && g_str_has_prefix(name, "__Secure-") && !secure)
        return TRUE;
    if (name && g_str_has_prefix(name, "__Host-")) {
        if (!secure)
            return TRUE;
        if (!path || strcmp(path, "/") != 0)
            return TRUE;
        if (domain[0] == '.')
            return TRUE;
    }
    return FALSE;
}

static void stage6_cookie_audit_start(struct Stage6CookieHygiene *state);

static void stage6_cookie_audit_ready(GObject *source,
                                      GAsyncResult *result,
                                      gpointer user_data)
{
    struct Stage6CookieHygiene *state = user_data;
    GError *error = NULL;
    GList *cookies = webkit_cookie_manager_get_all_cookies_finish(
        WEBKIT_COOKIE_MANAGER(source), result, &error);
    state->audit_count++;

    if (error) {
        fputs("WPE_STAGE6_COOKIE_AUDIT_FAIL\n", stderr);
        g_error_free(error);
    } else {
        for (GList *node = cookies; node; node = node->next) {
            SoupCookie *cookie = node->data;
            if (!stage6_cookie_should_delete(cookie))
                continue;
            state->delete_count++;
            webkit_cookie_manager_delete_cookie(
                state->manager, cookie, NULL, NULL, NULL);
        }
    }
    if (cookies)
        g_list_free_full(cookies, (GDestroyNotify)soup_cookie_free);

    state->audit_active = FALSE;
    if (state->audit_pending) {
        state->audit_pending = FALSE;
        stage6_cookie_audit_start(state);
    }
}

static void stage6_cookie_audit_start(struct Stage6CookieHygiene *state)
{
    if (state->audit_active) {
        state->audit_pending = TRUE;
        return;
    }
    state->audit_active = TRUE;
    webkit_cookie_manager_get_all_cookies(
        state->manager, NULL, stage6_cookie_audit_ready, state);
}

static void stage6_cookie_changed(WebKitCookieManager *manager, gpointer user_data)
{
    struct Stage6CookieHygiene *state = user_data;
    if (manager != state->manager)
        return;
    state->changed_count++;
    stage6_cookie_audit_start(state);
}

static gboolean stage6_configure_network_session(
    WebKitNetworkSession *network_session,
    struct Stage6CookieHygiene *hygiene)
{
    if (!network_session)
        return FALSE;

    webkit_network_session_set_itp_enabled(network_session, TRUE);
    webkit_network_session_set_persistent_credential_storage_enabled(
        network_session, FALSE);
    if (!webkit_network_session_get_itp_enabled(network_session))
        return FALSE;
    if (webkit_network_session_get_persistent_credential_storage_enabled(network_session))
        return FALSE;

    WebKitCookieManager *manager = webkit_network_session_get_cookie_manager(network_session);
    if (!manager)
        return FALSE;
    *hygiene = (struct Stage6CookieHygiene) {
        .manager = manager,
        .audit_active = FALSE,
        .audit_pending = FALSE,
        .changed_count = 0U,
        .audit_count = 0U,
        .delete_count = 0U,
    };
    g_signal_connect(manager, "changed", G_CALLBACK(stage6_cookie_changed), hygiene);
    return TRUE;
}

#define BJ_STAGE7_HTTP_DISK_BUDGET (64ULL * 1024ULL * 1024ULL)
#define BJ_STAGE7_DOM_CACHE_BUDGET (32ULL * 1024ULL * 1024ULL)

struct Stage7CacheRetention {
    WebKitWebsiteDataManager *manager;
    gboolean audit_active;
    gboolean audit_pending;
    guint audit_count;
    guint clear_count;
};

static void stage7_cache_audit_start(struct Stage7CacheRetention *state);

static void stage7_cache_clear_ready(GObject *source, GAsyncResult *result, gpointer user_data)
{
    struct Stage7CacheRetention *state = user_data;
    GError *error = NULL;
    if (!webkit_website_data_manager_clear_finish(WEBKIT_WEBSITE_DATA_MANAGER(source), result, &error)) {
        fputs("WPE_STAGE7_CACHE_CLEAR_FAIL\n", stderr);
        g_clear_error(&error);
    } else {
        state->clear_count++;
    }
}

static void stage7_cache_fetch_ready(GObject *source, GAsyncResult *result, gpointer user_data)
{
    struct Stage7CacheRetention *state = user_data;
    GError *error = NULL;
    GList *items = webkit_website_data_manager_fetch_finish(
        WEBKIT_WEBSITE_DATA_MANAGER(source), result, &error);
    guint64 disk_total = 0, dom_total = 0;
    state->audit_count++;
    if (error) {
        fputs("WPE_STAGE7_CACHE_AUDIT_FAIL\n", stderr);
        g_clear_error(&error);
    } else {
        for (GList *node = items; node; node = node->next) {
            WebKitWebsiteData *data = node->data;
            disk_total += webkit_website_data_get_size(data, WEBKIT_WEBSITE_DATA_DISK_CACHE);
            dom_total += webkit_website_data_get_size(data, WEBKIT_WEBSITE_DATA_DOM_CACHE);
        }
        if (disk_total > BJ_STAGE7_HTTP_DISK_BUDGET)
            webkit_website_data_manager_clear(
                state->manager, WEBKIT_WEBSITE_DATA_DISK_CACHE, 0, NULL,
                stage7_cache_clear_ready, state);
        if (dom_total > BJ_STAGE7_DOM_CACHE_BUDGET)
            webkit_website_data_manager_clear(
                state->manager, WEBKIT_WEBSITE_DATA_DOM_CACHE, 0, NULL,
                stage7_cache_clear_ready, state);
    }
    if (items)
        g_list_free_full(items, (GDestroyNotify)webkit_website_data_unref);
    state->audit_active = FALSE;
    if (state->audit_pending) {
        state->audit_pending = FALSE;
        stage7_cache_audit_start(state);
    }
}

static void stage7_cache_audit_start(struct Stage7CacheRetention *state)
{
    if (!state || !state->manager)
        return;
    if (state->audit_active) {
        state->audit_pending = TRUE;
        return;
    }
    state->audit_active = TRUE;
    webkit_website_data_manager_fetch(
        state->manager,
        WEBKIT_WEBSITE_DATA_DISK_CACHE | WEBKIT_WEBSITE_DATA_DOM_CACHE,
        NULL, stage7_cache_fetch_ready, state);
}

static gboolean stage7_configure_persistent_profile(
    WebKitNetworkSession *network_session, struct Stage7CacheRetention *state)
{
    if (!network_session || webkit_network_session_is_ephemeral(network_session))
        return FALSE;
    WebKitWebsiteDataManager *manager =
        webkit_network_session_get_website_data_manager(network_session);
    if (!manager || webkit_website_data_manager_is_ephemeral(manager))
        return FALSE;
    const char *data_dir = webkit_website_data_manager_get_base_data_directory(manager);
    const char *cache_dir = webkit_website_data_manager_get_base_cache_directory(manager);
    if (!data_dir || !*data_dir || !cache_dir || !*cache_dir)
        return FALSE;
    *state = (struct Stage7CacheRetention) {
        .manager = manager, .audit_active = FALSE, .audit_pending = FALSE,
        .audit_count = 0U, .clear_count = 0U,
    };
    stage7_cache_audit_start(state);
    return TRUE;
}

static void die_errno(const char *what)
{
    fprintf(stderr, "WPE_STAGE4A_FAIL %s: %s\n", what, strerror(errno));
    exit(2);
}

static void add_arg(GPtrArray *args, const char *value)
{
    g_ptr_array_add(args, g_strdup(value));
}

static void add_pair(GPtrArray *args, const char *a, const char *b)
{
    add_arg(args, a);
    add_arg(args, b);
}

static void add_ro_bind_if_exists(GPtrArray *args, const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return;
    add_pair(args, "--ro-bind", path);
    add_arg(args, path);
}

static void add_ro_bind_file_if_exists(GPtrArray *args, const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return;
    add_pair(args, "--ro-bind", path);
    add_arg(args, path);
}


static char *real_path_required(const char *value, const char *label)
{
    if (!value || !*value) {
        fprintf(stderr, "WPE_STAGE4A_FAIL missing %s\n", label);
        exit(2);
    }
    char *resolved = realpath(value, NULL);
    if (!resolved) {
        fprintf(stderr, "WPE_STAGE4A_FAIL invalid %s: %s\n", label, value);
        exit(2);
    }
    return resolved;
}

#include "sandbox_boundary.h"

static int bj_sealed_config(const char *contents)
{
    int fd = memfd_create("bojangles-renderer-config", MFD_ALLOW_SEALING);
    if (fd < 0)
        die_errno("renderer config");
    size_t length = strlen(contents), offset = 0;
    while (offset < length) {
        ssize_t written = write(fd, contents + offset, length - offset);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            die_errno("renderer config write");
        offset += (size_t)written;
    }
    if (lseek(fd, 0, SEEK_SET) != 0 || fcntl(fd, F_ADD_SEALS,
            F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) != 0)
        die_errno("renderer config seal");
    return fd;
}

static void bj_add_config(GPtrArray *args, const char *path, const char *contents)
{
    int fd = bj_sealed_config(contents);
    char value[32];
    snprintf(value, sizeof(value), "%d", fd);
    add_pair(args, "--ro-bind-data", value);
    add_arg(args, path);
}

static void enter_outer_sandbox(int argc, char **argv)
{
    if (g_strcmp0(g_getenv(OUTER_MARKER), "1") == 0) {
        bj_require_boundary();
        return;
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        die_errno("PR_SET_NO_NEW_PRIVS");

    umask(0077);

    char self_buffer[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", self_buffer, sizeof(self_buffer) - 1);
    if (n <= 0 || (size_t)n >= sizeof(self_buffer) - 1)
        die_errno("readlink-/proc/self/exe");
    self_buffer[n] = '\0';

    char *self = real_path_required(self_buffer, "frontend executable");
    char *prefix = real_path_required(g_getenv("BOJANGLES_WPE_PREFIX"), "BOJANGLES_WPE_PREFIX");
    char *extensions = real_path_required(g_getenv("BOJANGLES_WPE_EXTENSION_DIR"), "BOJANGLES_WPE_EXTENSION_DIR");
    const char *profile_data_env = g_getenv("BOJANGLES_WPE_DATA_DIR");
    const char *profile_cache_env = g_getenv("BOJANGLES_WPE_CACHE_DIR");
    const char *upload_dir_env = g_getenv("BOJANGLES_WPE_UPLOAD_DIR");
    if (!!(profile_data_env && *profile_data_env) != !!(profile_cache_env && *profile_cache_env)) {
        fputs("WPE_STAGE7_FAIL incomplete-profile-directories\n", stderr);
        exit(2);
    }
    char *profile_data = NULL;
    char *profile_cache = NULL;
    char *upload_dir = NULL;
    if (upload_dir_env && *upload_dir_env) {
        upload_dir = real_path_required(upload_dir_env, "BOJANGLES_WPE_UPLOAD_DIR");
        struct stat upload_st;
        if (stat(upload_dir, &upload_st) != 0 || !S_ISDIR(upload_st.st_mode)) {
            fputs("WPE_DIALOG_FAIL upload-staging-not-directory\n", stderr);
            exit(2);
        }
    }
    if (profile_data_env && *profile_data_env) {
        profile_data = real_path_required(profile_data_env, "BOJANGLES_WPE_DATA_DIR");
        profile_cache = real_path_required(profile_cache_env, "BOJANGLES_WPE_CACHE_DIR");
        struct stat data_st, cache_st;
        if (stat(profile_data, &data_st) != 0 || !S_ISDIR(data_st.st_mode) ||
            stat(profile_cache, &cache_st) != 0 || !S_ISDIR(cache_st.st_mode)) {
            fputs("WPE_STAGE7_FAIL profile-path-not-directory\n", stderr);
            exit(2);
        }
    }

    int origin_fds[G_N_ELEMENTS(bj_namespace_checks)];
    bj_capture_origins(origin_fds);

    GPtrArray *args = g_ptr_array_new_with_free_func(g_free);
    add_arg(args, "bwrap");
    add_arg(args, "--die-with-parent");
    add_arg(args, "--new-session");
    add_arg(args, "--unshare-pid");
    add_arg(args, "--unshare-ipc");
    add_arg(args, "--unshare-uts");
    add_pair(args, "--hostname", "bojangles");
    add_arg(args, "--unshare-net");
    add_arg(args, "--unshare-cgroup-try");
    add_arg(args, "--clearenv");

    add_pair(args, "--proc", "/proc");
    add_pair(args, "--dev", "/dev");
    add_pair(args, "--tmpfs", "/tmp");
    add_pair(args, "--dir", "/run");
    add_pair(args, "--dir", "/var");
    add_pair(args, "--dir", "/var/tmp");
    add_pair(args, "--dir", "/etc");
    add_pair(args, "--dir", "/app");
    add_pair(args, "--dir", "/app/extensions");
    add_pair(args, "--dir", "/wpe");
    add_pair(args, "--dir", "/sys");
    if (profile_data || upload_dir)
        add_pair(args, "--dir", "/state");
    if (profile_data) {
        add_pair(args, "--dir", "/state/data");
        add_pair(args, "--dir", "/state/cache");
        add_pair(args, "--bind", profile_data);
        add_arg(args, "/state/data");
        add_pair(args, "--bind", profile_cache);
        add_arg(args, "/state/cache");
    }
    if (upload_dir) {
        add_pair(args, "--ro-bind", upload_dir);
        add_arg(args, "/state/uploads");
    }

    /* WebKit requires these sysfs source paths, not host hardware metadata. */
    add_pair(args, "--tmpfs", "/sys");
    add_pair(args, "--dir", "/sys/block");
    add_pair(args, "--dir", "/sys/bus");
    add_pair(args, "--dir", "/sys/class");
    add_pair(args, "--dir", "/sys/dev");
    add_pair(args, "--dir", "/sys/devices");
    add_pair(args, "--remount-ro", "/sys");

    add_ro_bind_if_exists(args, "/usr");
    add_ro_bind_if_exists(args, "/bin");
    add_ro_bind_if_exists(args, "/lib");
    add_ro_bind_if_exists(args, "/lib64");
    add_ro_bind_if_exists(args, "/sbin");

    add_ro_bind_if_exists(args, "/etc/fonts");
    add_ro_bind_if_exists(args, "/etc/ssl");
    add_ro_bind_file_if_exists(args, "/etc/ld.so.cache");
    bj_add_config(args, "/etc/resolv.conf", BJ_RENDERER_RESOLVER);
    bj_add_config(args, "/etc/hosts", BJ_RENDERER_HOSTS);
    add_ro_bind_file_if_exists(args, "/etc/nsswitch.conf");
    add_ro_bind_file_if_exists(args, "/etc/gai.conf");
    add_ro_bind_file_if_exists(args, "/etc/localtime");

    /*
     * libgstlibav -> libavfilter resolves BLAS/LAPACK through Ubuntu's
     * /etc/alternatives symlinks.  Do not expose the alternatives tree:
     * materialize only the two resolved library files at the exact lookup
     * paths needed by the dynamic loader inside this namespace.
     */
    add_pair(args, "--dir", "/etc/alternatives");
    if (access("/usr/lib/x86_64-linux-gnu/blas/libblas.so.3.12.0", R_OK) == 0) {
        add_pair(args, "--ro-bind", "/usr/lib/x86_64-linux-gnu/blas/libblas.so.3.12.0");
        add_arg(args, "/etc/alternatives/libblas.so.3-x86_64-linux-gnu");
    }
    if (access("/usr/lib/x86_64-linux-gnu/lapack/liblapack.so.3.12.0", R_OK) == 0) {
        add_pair(args, "--ro-bind", "/usr/lib/x86_64-linux-gnu/lapack/liblapack.so.3.12.0");
        add_arg(args, "/etc/alternatives/liblapack.so.3-x86_64-linux-gnu");
    }

    /* Resolve the engine's compiled /wpe helper and data paths to this
     * selected package. Its host installation path is not baked into WPE. */
    add_pair(args, "--ro-bind", prefix);
    add_arg(args, "/wpe");
    add_pair(args, "--ro-bind", self);
    add_arg(args, "/app/bojangles-wpe-stage4a");
    add_pair(args, "--ro-bind", extensions);
    add_arg(args, "/app/extensions");

    for (unsigned int i = 0; i < G_N_ELEMENTS(bj_namespace_checks); ++i) {
        char value[32];
        snprintf(value, sizeof(value), "%d", origin_fds[i]);
        add_pair(args, "--setenv", bj_namespace_checks[i].environment);
        add_arg(args, value);
    }

    add_pair(args, "--setenv", OUTER_MARKER);
    add_arg(args, "1");
    add_pair(args, "--setenv", "PATH");
    add_arg(args, "/usr/bin:/bin");
    add_pair(args, "--setenv", "LANG");
    add_arg(args, "C.UTF-8");
    add_pair(args, "--setenv", "LC_ALL");
    add_arg(args, "C.UTF-8");
    add_pair(args, "--setenv", "HOME");
    add_arg(args, "/tmp/home");
    add_pair(args, "--setenv", "XDG_CACHE_HOME");
    add_arg(args, "/tmp/cache");
    add_pair(args, "--setenv", "XDG_DATA_HOME");
    add_arg(args, "/tmp/data");
    add_pair(args, "--setenv", "XDG_CONFIG_HOME");
    add_arg(args, "/tmp/config");
    add_pair(args, "--setenv", "XDG_RUNTIME_DIR");
    add_arg(args, "/tmp/runtime");
    add_pair(args, "--setenv", "WPE_PLATFORM");
    add_arg(args, "headless");
    add_pair(args, "--setenv", "BOJANGLES_WPE_PREFIX");
    add_arg(args, "/wpe");
    add_pair(args, "--setenv", "BOJANGLES_WPE_EXTENSION_DIR");
    add_arg(args, "/app/extensions");
    if (profile_data) {
        add_pair(args, "--setenv", "BOJANGLES_WPE_DATA_DIR");
        add_arg(args, "/state/data");
        add_pair(args, "--setenv", "BOJANGLES_WPE_CACHE_DIR");
        add_arg(args, "/state/cache");
    }
    if (upload_dir) {
        add_pair(args, "--setenv", "BOJANGLES_WPE_UPLOAD_DIR");
        add_arg(args, "/state/uploads");
        add_pair(args, "--setenv", "BOJANGLES_WPE_NETWORK_STATE_FILE");
        add_arg(args, "/state/uploads/.network-state");
    }
    add_pair(args, "--setenv", "LD_LIBRARY_PATH");
    add_arg(args, "/wpe/lib");
    g_free(upload_dir);
    add_pair(args, "--setenv", "WEBKIT_EXEC_PATH");
    add_arg(args, "/wpe/libexec/wpe-webkit-2.0");

    add_pair(args, "--dir", "/tmp/home");
    add_pair(args, "--dir", "/tmp/cache");
    add_pair(args, "--dir", "/tmp/data");
    add_pair(args, "--dir", "/tmp/config");
    add_pair(args, "--dir", "/tmp/runtime");

    add_arg(args, "--");
    add_arg(args, "/app/bojangles-wpe-stage4a");
    for (int i = 1; i < argc; ++i)
        add_arg(args, argv[i]);
    g_ptr_array_add(args, NULL);

    execv("/usr/bin/bwrap", (char *const *)args->pdata);
    die_errno("execvp-bwrap");
}

static guint64 fnv1a64(const guint8 *data, gsize length)
{
    guint64 hash = G_GUINT64_CONSTANT(1469598103934665603);
    for (gsize i = 0; i < length; ++i) {
        hash ^= data[i];
        hash *= G_GUINT64_CONSTANT(1099511628211);
    }
    return hash;
}

static gboolean finish_hold(gpointer user_data)
{
    struct Stage4State *state = user_data;
    g_main_loop_quit(state->loop);
    return G_SOURCE_REMOVE;
}

static gboolean hard_timeout(gpointer user_data)
{
    struct Stage4State *state = user_data;
    state->timed_out = TRUE;
    fputs("WPE_STAGE4A_FAIL hard-timeout\n", stderr);
    g_main_loop_quit(state->loop);
    return G_SOURCE_REMOVE;
}

static void snapshot_ready(GObject *source, GAsyncResult *result, gpointer user_data)
{
    struct Stage4State *state = user_data;
    GError *error = NULL;
    WebKitImage *image = webkit_web_view_get_snapshot_finish(
        WEBKIT_WEB_VIEW(source), result, &error);
    if (!image) {
        fprintf(stderr, "WPE_STAGE4A_FAIL snapshot %s\n",
                error ? error->message : "unknown");
        g_clear_error(&error);
        g_main_loop_quit(state->loop);
        return;
    }

    GBytes *bytes = webkit_image_as_bytes(image);
    gsize length = 0;
    const guint8 *data = g_bytes_get_data(bytes, &length);
    guint64 hash = fnv1a64(data, length);

    printf("WPE_STAGE4A_SNAPSHOT width=%d height=%d stride=%u bytes=%zu fnv64=%016" PRIx64 "\n",
           webkit_image_get_width(image),
           webkit_image_get_height(image),
           webkit_image_get_stride(image),
           (size_t)length,
           hash);
    printf("WPE_STAGE4A_READY pid=%ld hold=%u\n", (long)getpid(), state->hold_seconds);
    state->snapshot_ok = TRUE;
    g_object_unref(image);

    g_timeout_add_seconds(state->hold_seconds, finish_hold, state);
}

static void load_changed(WebKitWebView *view, WebKitLoadEvent event, gpointer user_data)
{
    struct Stage4State *state = user_data;
    if (event != WEBKIT_LOAD_FINISHED)
        return;

    fputs("WPE_STAGE4A_LOAD_FINISHED\n", stdout);
    webkit_web_view_get_snapshot(
        view,
        WEBKIT_SNAPSHOT_REGION_VISIBLE,
        WEBKIT_SNAPSHOT_OPTIONS_NONE,
        NULL,
        snapshot_ready,
        state);
}

static gboolean load_failed(WebKitWebView *view,
                            WebKitLoadEvent event,
                            const char *failing_uri,
                            GError *error,
                            gpointer user_data)
{
    (void)view;
    (void)event;
    struct Stage4State *state = user_data;
    fprintf(stderr, "WPE_STAGE4A_FAIL load uri=%s error=%s\n",
            failing_uri ? failing_uri : "",
            error ? error->message : "");
    g_main_loop_quit(state->loop);
    return TRUE;
}

static void web_process_terminated(WebKitWebView *view,
                                   WebKitWebProcessTerminationReason reason,
                                   gpointer user_data)
{
    (void)view;
    struct Stage4State *state = user_data;
    fprintf(stderr, "WPE_STAGE4A_FAIL web-process-terminated reason=%d\n", (int)reason);
    g_main_loop_quit(state->loop);
}

static unsigned parse_hold_seconds(int argc, char **argv)
{
    unsigned value = DEFAULT_HOLD_SECONDS;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--hold-seconds") != 0)
            continue;
        if (i + 1 >= argc) {
            fputs("WPE_STAGE4A_FAIL --hold-seconds requires a value\n", stderr);
            exit(2);
        }
        char *end = NULL;
        errno = 0;
        unsigned long parsed = strtoul(argv[++i], &end, 10);
        if (errno || !end || *end || parsed < 5 || parsed > 120) {
            fputs("WPE_STAGE4A_FAIL invalid --hold-seconds\n", stderr);
            exit(2);
        }
        value = (unsigned)parsed;
    }
    return value;
}

static int run_stage4a_probe(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    enter_outer_sandbox(argc, argv);

    if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) {
        fputs("WPE_STAGE4A_FAIL no-new-privs-not-set\n", stderr);
        return 3;
    }

    const char *extension_dir = g_getenv("BOJANGLES_WPE_EXTENSION_DIR");
    if (!extension_dir || !*extension_dir) {
        fputs("WPE_STAGE4A_FAIL extension-dir-unset\n", stderr);
        return 3;
    }

    unsigned hold_seconds = parse_hold_seconds(argc, argv);

    printf("WPE_STAGE4A_OUTER_SANDBOX pid=%ld no_new_privs=1\n", (long)getpid());
    printf("WPE_STAGE4A_EXTENSION_DIR %s\n", extension_dir);

    WebKitWebContext *context = WEBKIT_WEB_CONTEXT(
        g_object_new(WEBKIT_TYPE_WEB_CONTEXT, NULL));
    if (!context) {
        fputs("WPE_STAGE4A_FAIL web-context\n", stderr);
        return 3;
    }

    webkit_web_context_set_web_process_extensions_directory(context, extension_dir);

    WebKitNetworkSession *network_session = webkit_network_session_new_ephemeral();
    if (!network_session) {
        fputs("WPE_STAGE4A_FAIL network-session\n", stderr);
        g_object_unref(context);
        return 3;
    }
    struct Stage6CookieHygiene hygiene;
    if (!stage6_configure_network_session(network_session, &hygiene)) {
        fputs("WPE_STAGE6_FAIL network-session-policy\n", stderr);
        g_object_unref(network_session);
        g_object_unref(context);
        return 3;
    }

    WebKitWebView *view = WEBKIT_WEB_VIEW(g_object_new(
        WEBKIT_TYPE_WEB_VIEW,
        "web-context", context,
        "network-session", network_session,
        NULL));
    if (!view) {
        fputs("WPE_STAGE4A_FAIL web-view\n", stderr);
        g_object_unref(network_session);
        g_object_unref(context);
        return 3;
    }

    WPEView *wpe_view = webkit_web_view_get_wpe_view(view);
    if (!wpe_view || !wpe_view_get_toplevel(wpe_view)) {
        fputs("WPE_STAGE4A_FAIL no-headless-toplevel\n", stderr);
        g_object_unref(view);
        g_object_unref(network_session);
        g_object_unref(context);
        return 3;
    }
    wpe_toplevel_resize(wpe_view_get_toplevel(wpe_view), 800, 600);

    struct Stage4State state = {
        .loop = g_main_loop_new(NULL, FALSE),
        .view = view,
        .snapshot_ok = FALSE,
        .timed_out = FALSE,
        .hold_seconds = hold_seconds,
    };

    g_signal_connect(view, "permission-request", G_CALLBACK(bojangles_permission_request), &state);
    g_signal_connect(view, "load-changed", G_CALLBACK(load_changed), &state);
    g_signal_connect(view, "load-failed", G_CALLBACK(load_failed), &state);
    g_signal_connect(view, "web-process-terminated", G_CALLBACK(web_process_terminated), &state);

    const char *html =
        "<!doctype html><meta charset=utf-8>"
        "<title>BoJangles WPE Stage 4A</title>"
        "<style>html,body{margin:0;background:#101418;color:#f4f7fa;font:24px sans-serif}"
        ".card{margin:48px;padding:36px;border:4px solid #7fd1ae;border-radius:16px}"
        "canvas{display:block;margin-top:20px}</style>"
        "<div class=card><strong>BoJangles WPE 2.54.0</strong>"
        "<div id=status>Stage 4A native frontend</div><canvas id=c width=256 height=64></canvas></div>"
        "<script>const c=document.getElementById('c'),x=c.getContext('2d');"
        "x.fillStyle='#7fd1ae';x.fillRect(0,0,256,64);"
        "x.fillStyle='#101418';x.font='20px sans-serif';x.fillText('DMZ render probe',42,39);"
        "document.body.dataset.bojanglesStage='4a';</script>";

    webkit_web_view_load_html(view, html, "https://stage4a.invalid/");
    g_timeout_add_seconds(HARD_TIMEOUT_SECONDS, hard_timeout, &state);
    g_main_loop_run(state.loop);

    gboolean ok = state.snapshot_ok && !state.timed_out;

    g_main_loop_unref(state.loop);
    g_object_unref(view);
    g_object_unref(network_session);
    g_object_unref(context);

    if (!ok)
        return 4;

    fputs("WPE_STAGE4A_COMPLETE\n", stdout);
    return 0;
}

/* Stage 5B direct RendererBackend protocol.  This channel carries lifecycle,
 * viewport/input, and restorable frontend state only.  It does not carry the
 * trusted RequestChannel.  The existing WPE WebProcess extension remains the
 * independent fail-closed position-one hook for renderer-originated network
 * requests.  Only trusted-side authorized document bytes cross by sealed fd. */
#define BJ_MAGIC UINT32_C(0x424A4E31)
#define BJ_VERSION UINT16_C(1)
#define BJ_MAX_PACKET (1024U * 1024U)

#define BJ_READY 1U
#define BJ_LOAD 2U
#define BJ_RESIZE 3U
#define BJ_INPUT 4U
#define BJ_SNAPSHOT 5U
#define BJ_SNAPSHOT_RESULT 6U
#define BJ_RESTORE 7U
#define BJ_RESTORE_RESULT 8U
#define BJ_STOP 9U
#define BJ_LOAD_DATA 10U
#define BJ_NAV_BACK 11U
#define BJ_NAV_FORWARD 12U
#define BJ_NAV_RELOAD 13U
#define BJ_NAV_STOP 14U
#define BJ_NAVIGATE 15U
#define BJ_STATE_REQUEST 16U
#define BJ_STATE_RESULT 17U
#define BJ_TERMINATE 18U
#define BJ_SET_DRM 19U
#define BJ_NAVIGATION_STARTED 20U
#define BJ_NAVIGATION_FINISHED 22U
#define BJ_TITLE_CHANGED 24U
#define BJ_URL_CHANGED 25U
#define BJ_CLIPBOARD_COPY_REQUEST 30U
#define BJ_CLIPBOARD_COPY_RESULT 31U
#define BJ_CLIPBOARD_PASTE_TEXT 32U
#define BJ_FILE_CHOOSER_REQUEST 33U
#define BJ_FILE_CHOOSER_RESULT 34U
#define BJ_SCRIPT_DIALOG_REQUEST 35U
#define BJ_SCRIPT_DIALOG_RESULT 36U
#define BJ_NEW_WINDOW_REQUESTED 37U
#define BJ_SPELLING_MENU_REQUEST 38U
#define BJ_SPELLING_MENU_RESULT 39U
#define BJ_DOWNLOAD_OFFER 43U
#define BJ_CREDENTIAL_FILL 44U
#define BJ_CREDENTIAL_FILL_RESULT 45U
#define BJ_LOAD_DATA_HEADERS 46U
#define BJ_COOKIE_SYNC 47U
#define BJ_PRINT_PDF_REQUEST 51U
#define BJ_PRINT_PDF_RESULT 52U
#define BJ_PAGE_EXPORT_REQUEST 72U
#define BJ_PAGE_EXPORT_RESULT 73U
#define BJ_TRANSLATION_EXTRACT 54U
#define BJ_TRANSLATION_APPLY 55U
#define BJ_TRANSLATION_RESTORE 56U
#define BJ_TRANSLATION_RESULT 57U
#define BJ_LINK_CONTEXT_MENU_REQUEST 58U
#define BJ_SITE_RULES 59U
#define BJ_NAVIGATION_INTENT 60U
#define BJ_STYLE_APPLIED 61U
#define BJ_RESOURCE_STOPPED 62U
#define BJ_IMAGE_CONTEXT_MENU_REQUEST 63U
#define BJ_IMAGE_DATA_REQUEST 64U
#define BJ_IMAGE_DATA_RESULT 65U
#define BJ_CLIPBOARD_PASTE_RICH 66U
#define BJ_CLIPBOARD_COPY_RICH 67U
#define BJ_CLIPBOARD_COPY_RICH_RESULT 68U
#define BJ_CLIPBOARD_CUT_RICH 69U
#define BJ_EDIT_CONTEXT_MENU_REQUEST 70U
#define BJ_REGION_CONTEXT_MENU_REQUEST 71U
#define BJ_CLIPBOARD_PASTE_PNG 48U
#define BJ_CLIPBOARD_PASTE_RESULT 49U
#define BJ_ERROR 50U
#define BJ_RESOURCE_REQUEST 40U
#define BJ_RESOURCE_DECISION 41U
#define BJ_RESOURCE_DATA 42U
#define BJ_RESOURCE_REDIRECT 53U

struct BackendOptions {
    int control_fd;
    int resource_fd;
    int fb_fd;
    unsigned width;
    unsigned height;
    unsigned stride;
    const char *pixel_format;
};

struct BackendState {
    char *site_rule_document;
    char *site_rule_uri;
    char *site_rule_css;
    WebKitUserStyleSheet *site_rule_sheet;
    guint32 statistics_group;
    gboolean print_active;
    GMainLoop *loop;
    WebKitWebContext *context;
    WebKitNetworkSession *network_session;
    WebKitWebView *view;
    int control_fd;
    int resource_fd;
    guint8 *framebuffer;
    size_t framebuffer_length;
    guint64 frame_serial;
    unsigned width;
    unsigned height;
    unsigned stride;
    const char *pixel_format;
    char *document_id;
    char *uri;
    char *pending_main_navigation_uri;
    GBytes *pending_document_bytes;
    char *pending_document_uri;
    char *pending_document_content_type;
    guint pending_document_status;
    SoupMessageHeaders *pending_document_headers;
    gboolean stopping;
    gboolean trusted_document_load;
    gboolean surface_focused;
    gboolean cookie_sync_pending;
    gboolean cookie_sync_dirty;
    GHashTable *cookie_sync_snapshot;
    char *cookie_sync_document;
    GHashTable *subframe_origins;
    char *subframe_document;
    gint64 last_operator_gesture_us;
    gboolean operator_gesture_claimed;
    gboolean automatic_same_origin_used;
    gboolean automatic_cross_origin_used;
    guint32 next_resource_request_id;
    GHashTable *pending_resources;
    gboolean persistent_profile;
    struct Stage7CacheRetention retention;
    GCancellable *operations;
    WebKitFileChooserRequest *pending_file_chooser;
    guint32 pending_file_chooser_id;
    WebKitScriptDialog *pending_script_dialog;
    guint32 pending_script_dialog_id;
    GPtrArray *image_resources;
    WebKitWebResource *context_image;
    GPtrArray *spelling_actions;
    char *spelling_document_id;
    guint32 spelling_menu_id;
    gint64 spelling_menu_us;
    guint32 next_ui_request_id;
};

static void bj_clear_pending_document(struct BackendState *state)
{
    if (state->pending_document_bytes) {
        g_bytes_unref(state->pending_document_bytes);
        state->pending_document_bytes = NULL;
    }
    g_clear_pointer(&state->pending_document_uri, g_free);
    g_clear_pointer(&state->pending_document_content_type, g_free);
    state->pending_document_status = 0U;
    if (state->pending_document_headers) {
        soup_message_headers_unref(state->pending_document_headers);
        state->pending_document_headers = NULL;
    }
}

static gboolean bj_send_packet(int fd, guint16 kind, guint32 request_id,
                               const void *payload, guint32 length);
static GByteArray *bj_pack_strings(const char *const *values, size_t count);

static void backend_cookie_changed(WebKitCookieManager *manager, gpointer user_data);

static void backend_cookie_sync_ready(GObject *source, GAsyncResult *result, gpointer data)
{
    struct BackendState *state = data;
    state->cookie_sync_pending = FALSE;
    GError *error = NULL;
    GList *cookies = webkit_cookie_manager_get_all_cookies_finish(
        WEBKIT_COOKIE_MANAGER(source), result, &error);

    if (!error && !state->stopping && state->document_id && state->uri) {
        if (g_strcmp0(state->cookie_sync_document, state->document_id)) {
            g_clear_pointer(&state->cookie_sync_snapshot, g_hash_table_unref);
            g_free(state->cookie_sync_document);
            state->cookie_sync_document = g_strdup(state->document_id);
        }
        GHashTable *snapshot = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
        GUri *uri = g_uri_parse(state->uri, G_URI_FLAGS_ENCODED, NULL);
        for (GList *node = cookies; uri && node; node = node->next) {
            SoupCookie *cookie = node->data;
            if (stage6_cookie_should_delete(cookie) ||
                !soup_cookie_applies_to_uri(cookie, uri))
                continue;

            char *serialized = soup_cookie_to_set_cookie_header(cookie);
            if (!serialized || strlen(serialized) > BJ_STAGE6_MAX_COOKIE_BYTES) {
                g_free(serialized);
                continue;
            }

            g_hash_table_add(snapshot, g_strdup(serialized));
            if (state->cookie_sync_snapshot && g_hash_table_contains(state->cookie_sync_snapshot, serialized)) {
                g_free(serialized);
                continue;
            }
            const char *values[] = { state->document_id, state->uri, serialized };
            GByteArray *payload = bj_pack_strings(values, G_N_ELEMENTS(values));
            if (payload->len <= BJ_MAX_PACKET)
                bj_send_packet(state->control_fd, BJ_COOKIE_SYNC, 0,
                               payload->data, (guint32)payload->len);
            g_byte_array_unref(payload);
            g_free(serialized);
        }
        if (uri)
            g_uri_unref(uri);
        g_clear_pointer(&state->cookie_sync_snapshot, g_hash_table_unref);
        state->cookie_sync_snapshot = snapshot;
    }

    if (cookies)
        g_list_free_full(cookies, (GDestroyNotify)soup_cookie_free);
    if (error)
        g_error_free(error);
    if (state->cookie_sync_dirty && !state->stopping) {
        state->cookie_sync_dirty = FALSE;
        backend_cookie_changed(WEBKIT_COOKIE_MANAGER(source), state);
    }
}

static void backend_cookie_changed(WebKitCookieManager *manager, gpointer user_data)
{
    struct BackendState *state = user_data;
    if (state->stopping || !state->document_id || !state->uri)
        return;
    /* One snapshot in flight; repeated notifications neither queue duplicate
     * full-cookie scans nor replay unchanged records into trusted persistence. */
    if (state->cookie_sync_pending) {
        state->cookie_sync_dirty = TRUE;
        return;
    }
    state->cookie_sync_pending = TRUE;
    webkit_cookie_manager_get_all_cookies(
        manager, state->operations, backend_cookie_sync_ready, state);
}

static guint32 backend_next_ui_request_id(struct BackendState *state)
{
    state->next_ui_request_id++;
    if (!state->next_ui_request_id)
        state->next_ui_request_id = 1U;
    return state->next_ui_request_id;
}

static gboolean backend_run_file_chooser(WebKitWebView *view,
                                         WebKitFileChooserRequest *request,
                                         gpointer user_data)
{
    (void)view;
    struct BackendState *state = user_data;
    if (state->pending_file_chooser) {
        webkit_file_chooser_request_cancel(state->pending_file_chooser);
        g_clear_object(&state->pending_file_chooser);
    }
    state->pending_file_chooser = g_object_ref(request);
    state->pending_file_chooser_id = backend_next_ui_request_id(state);
    const gchar *const *mimes = webkit_file_chooser_request_get_mime_types(request);
    size_t mime_count = 0;
    while (mimes && mimes[mime_count] && mime_count < 64)
        mime_count++;
    const char **values = g_new0(const char *, mime_count + 1U);
    values[0] = webkit_file_chooser_request_get_select_multiple(request) ? "1" : "0";
    for (size_t i = 0; i < mime_count; ++i)
        values[i + 1U] = mimes[i];
    GByteArray *payload = bj_pack_strings(values, mime_count + 1U);
    g_free(values);
    gboolean ok = bj_send_packet(state->control_fd, BJ_FILE_CHOOSER_REQUEST,
                                 state->pending_file_chooser_id,
                                 payload->data, (guint32)payload->len);
    g_byte_array_unref(payload);
    if (!ok) {
        webkit_file_chooser_request_cancel(state->pending_file_chooser);
        g_clear_object(&state->pending_file_chooser);
        state->pending_file_chooser_id = 0;
    }
    return TRUE;
}

static gboolean backend_script_dialog(WebKitWebView *view,
                                      WebKitScriptDialog *dialog,
                                      gpointer user_data)
{
    (void)view;
    struct BackendState *state = user_data;
    if (state->pending_script_dialog) {
        webkit_script_dialog_close(state->pending_script_dialog);
        webkit_script_dialog_unref(state->pending_script_dialog);
        state->pending_script_dialog = NULL;
    }
    state->pending_script_dialog = webkit_script_dialog_ref(dialog);
    state->pending_script_dialog_id = backend_next_ui_request_id(state);
    char type[16];
    g_snprintf(type, sizeof(type), "%u", (unsigned)webkit_script_dialog_get_dialog_type(dialog));
    const char *message = webkit_script_dialog_get_message(dialog);
    const char *def = "";
    if (webkit_script_dialog_get_dialog_type(dialog) == WEBKIT_SCRIPT_DIALOG_PROMPT)
        def = webkit_script_dialog_prompt_get_default_text(dialog);
    const char *values[] = { type, message ? message : "", def ? def : "" };
    GByteArray *payload = bj_pack_strings(values, G_N_ELEMENTS(values));
    gboolean ok = bj_send_packet(state->control_fd, BJ_SCRIPT_DIALOG_REQUEST,
                                 state->pending_script_dialog_id,
                                 payload->data, (guint32)payload->len);
    g_byte_array_unref(payload);
    if (!ok) {
        webkit_script_dialog_close(state->pending_script_dialog);
        webkit_script_dialog_unref(state->pending_script_dialog);
        state->pending_script_dialog = NULL;
        state->pending_script_dialog_id = 0;
    }
    return TRUE;
}

struct SpellingAction {
    GAction *action;
    GVariant *target;
};

static void backend_spelling_action_free(gpointer data)
{
    struct SpellingAction *choice = data;
    g_clear_object(&choice->action);
    if (choice->target)
        g_variant_unref(choice->target);
    g_free(choice);
}

static void backend_clear_spelling_menu(struct BackendState *state)
{
    g_clear_object(&state->context_image);
    g_clear_pointer(&state->spelling_actions, g_ptr_array_unref);
    g_clear_pointer(&state->spelling_document_id, g_free);
    state->spelling_menu_id = 0;
    state->spelling_menu_us = 0;
}

static void backend_resource_started(WebKitWebView *view, WebKitWebResource *resource,
                                     WebKitURIRequest *request, gpointer user_data)
{
    (void)view;
    struct BackendState *state = user_data;
    if (!state->image_resources)
        state->image_resources = g_ptr_array_new_with_free_func(g_object_unref);
    if (state->image_resources->len >= 4096)
        g_ptr_array_remove_index(state->image_resources, 0);
    g_object_set_data_full(G_OBJECT(resource), "bojangles-image-request-uri",
                           g_strdup(webkit_uri_request_get_uri(request)), g_free);
    g_ptr_array_add(state->image_resources, g_object_ref(resource));
}

/* Only stock actions may cross into trusted chrome. No page-provided command
 * strings or scripting. Targets are retained GActions, document/request-bound. */
static void backend_collect_region_actions(struct BackendState *state,
    WebKitContextMenu *menu, char **labels, guint *count, gboolean spelling_only)
{
    for (GList *node = webkit_context_menu_get_items(menu);
         node && *count < 48; node = node->next) {
        WebKitContextMenuItem *item = node->data;
        WebKitContextMenu *submenu = webkit_context_menu_item_get_submenu(item);
        if (submenu) {
            backend_collect_region_actions(state, submenu, labels, count, spelling_only);
            continue;
        }
        WebKitContextMenuAction stock = webkit_context_menu_item_get_stock_action(item);
        if (stock < WEBKIT_CONTEXT_MENU_ACTION_OPEN_LINK ||
            stock > WEBKIT_CONTEXT_MENU_ACTION_DOWNLOAD_AUDIO_TO_DISK ||
            stock == WEBKIT_CONTEXT_MENU_ACTION_COPY_IMAGE_TO_CLIPBOARD ||
            stock == WEBKIT_CONTEXT_MENU_ACTION_OPEN_FRAME_IN_NEW_WINDOW ||
            stock == WEBKIT_CONTEXT_MENU_ACTION_INSPECT_ELEMENT ||
            stock == WEBKIT_CONTEXT_MENU_ACTION_NO_GUESSES_FOUND)
            continue;
        gboolean spelling = stock == WEBKIT_CONTEXT_MENU_ACTION_SPELLING_GUESS ||
            stock == WEBKIT_CONTEXT_MENU_ACTION_IGNORE_SPELLING ||
            stock == WEBKIT_CONTEXT_MENU_ACTION_LEARN_SPELLING;
        if (spelling != spelling_only || (spelling_only && *count >= 8)) continue;
        GAction *action = webkit_context_menu_item_get_gaction(item);
        const char *label = webkit_context_menu_item_get_title(item);
        if (!action || !label || !*label || !g_utf8_validate(label, -1, NULL) ||
            strlen(label) > 96 || strchr(label, '\n') || strchr(label, '\r'))
            continue;
        struct SpellingAction *choice = g_new0(struct SpellingAction, 1);
        choice->action = g_object_ref(action);
        GVariant *target = webkit_context_menu_item_get_gaction_target(item);
        choice->target = target ? g_variant_ref(target) : NULL;
        g_ptr_array_add(state->spelling_actions, choice);
        GVariant *checked = g_action_get_state(action);
        const char *mark = checked && g_variant_is_of_type(checked, G_VARIANT_TYPE_BOOLEAN) &&
            g_variant_get_boolean(checked) && strlen(label) <= 92 ? "✓ " : "";
        labels[*count] = g_strdup_printf("%u:%u:%s%s", (guint)stock,
            g_action_get_enabled(action) ? 1U : 0U, mark, label);
        if (checked) g_variant_unref(checked);
        ++*count;
    }
}

static gboolean backend_context_menu(WebKitWebView *view,
                                     WebKitContextMenu *menu,
                                     WebKitHitTestResult *hit,
                                     gpointer user_data)
{
    (void)view;
    struct BackendState *state = user_data;
    backend_clear_spelling_menu(state);
    if (!state->document_id)
        return TRUE;
    state->spelling_actions = g_ptr_array_new_with_free_func(backend_spelling_action_free);
    gboolean can_cut = FALSE;
    for (GList *node = webkit_context_menu_get_items(menu); node; node = node->next) {
        WebKitContextMenuItem *item = node->data;
        if (webkit_context_menu_item_get_stock_action(item) == WEBKIT_CONTEXT_MENU_ACTION_CUT) {
            GAction *action = webkit_context_menu_item_get_gaction(item);
            can_cut = action && g_action_get_enabled(action);
        }
    }
    char *labels[48] = { NULL };
    guint count = 0;
    backend_collect_region_actions(state, menu, labels, &count, TRUE);
    backend_collect_region_actions(state, menu, labels, &count, FALSE);
    /* Even without spelling choices, trusted chrome offers Paste. */
    state->spelling_document_id = g_strdup(state->document_id);
    state->spelling_menu_id = backend_next_ui_request_id(state);
    state->spelling_menu_us = g_get_monotonic_time();
    /* Hit testing resolves nested elements and relative addresses. Only trusted
     * chrome receives this text; copying never activates the link. */
    const char *link = webkit_hit_test_result_context_is_link(hit)
        ? webkit_hit_test_result_get_link_uri(hit) : NULL;
    gboolean has_link = link && *link && strlen(link) <= 8192 &&
        g_utf8_validate(link, -1, NULL) && !strchr(link, '\n') && !strchr(link, '\r');
    const char *image = webkit_hit_test_result_context_is_image(hit)
        ? webkit_hit_test_result_get_image_uri(hit) : NULL;
    gboolean has_image = image && *image &&
        g_utf8_validate(image, -1, NULL) && !strchr(image, '\n') && !strchr(image, '\r');
    const char *mime = "";
    if (has_image && state->image_resources) {
        for (guint i = state->image_resources->len; i > 0; --i) {
            WebKitWebResource *resource = g_ptr_array_index(state->image_resources, i - 1);
            const char *uri = webkit_web_resource_get_uri(resource);
            const char *initial = g_object_get_data(G_OBJECT(resource), "bojangles-image-request-uri");
            if ((uri && !strcmp(uri, image)) || (initial && !strcmp(initial, image))) {
                state->context_image = g_object_ref(resource);
                WebKitURIResponse *response = webkit_web_resource_get_response(resource);
                if (response && webkit_uri_response_get_mime_type(response))
                    mime = webkit_uri_response_get_mime_type(response);
                break;
            }
        }
    }
    const char *fields[55];
    guint field_count = 0;
    fields[field_count++] = state->document_id;
    fields[field_count++] = has_link ? link : "";
    fields[field_count++] = has_image ? (strlen(image) < BJ_MAX_PACKET / 2 ? image : "data:") : "";
    fields[field_count++] = mime;
    fields[field_count++] = can_cut ? "1" : "0";
    guint flags = (webkit_hit_test_result_context_is_editable(hit) ? 1U : 0U) |
        (webkit_hit_test_result_context_is_selection(hit) ? 2U : 0U) |
        (webkit_hit_test_result_context_is_media(hit) ? 4U : 0U);
    char region_flags[8];
    g_snprintf(region_flags, sizeof(region_flags), "%u", flags);
    fields[field_count++] = region_flags;
    const char *media = webkit_hit_test_result_context_is_media(hit)
        ? webkit_hit_test_result_get_media_uri(hit) : NULL;
    fields[field_count++] = media && strlen(media) <= 8192 &&
        g_utf8_validate(media, -1, NULL) && !strchr(media, '\n') && !strchr(media, '\r') ? media : "";
    for (guint i = 0; i < count; ++i)
        fields[field_count++] = labels[i];
    GByteArray *payload = bj_pack_strings(fields, field_count);
    if (!field_count) g_byte_array_append(payload, (const guint8 *)"", 1);
    gboolean sent = bj_send_packet(state->control_fd,
                                   BJ_REGION_CONTEXT_MENU_REQUEST,
                                   state->spelling_menu_id,
                                   payload->data, (guint32)payload->len);
    g_byte_array_unref(payload);
    for (guint i = 0; i < count; ++i) g_free(labels[i]);
    if (!sent)
        backend_clear_spelling_menu(state);
    return TRUE;
}

static gboolean parse_u32_arg(const char *text, unsigned *out)
{
    if (!text || !*text)
        return FALSE;
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(text, &end, 10);
    if (errno || !end || *end || value == 0 || value > UINT32_MAX)
        return FALSE;
    *out = (unsigned)value;
    return TRUE;
}

static gboolean parse_fd_arg(const char *text, int *out)
{
    if (!text || !*text)
        return FALSE;
    char *end = NULL;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (errno || !end || *end || value < 0 || value > INT_MAX)
        return FALSE;
    *out = (int)value;
    return TRUE;
}

static gboolean parse_backend_options(int argc, char **argv, struct BackendOptions *out)
{
    struct BackendOptions value = {
        .control_fd = -1,
        .resource_fd = -1,
        .fb_fd = -1,
        .width = 0,
        .height = 0,
        .stride = 0,
        .pixel_format = NULL,
    };
    gboolean saw_backend = FALSE;

    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (strcmp(arg, "--control-fd") == 0) {
            saw_backend = TRUE;
            if (++i >= argc || !parse_fd_arg(argv[i], &value.control_fd))
                return FALSE;
        } else if (strcmp(arg, "--resource-fd") == 0) {
            saw_backend = TRUE;
            if (++i >= argc || !parse_fd_arg(argv[i], &value.resource_fd))
                return FALSE;
        } else if (strcmp(arg, "--fb-fd") == 0) {
            saw_backend = TRUE;
            if (++i >= argc || !parse_fd_arg(argv[i], &value.fb_fd))
                return FALSE;
        } else if (strcmp(arg, "--width") == 0) {
            saw_backend = TRUE;
            if (++i >= argc || !parse_u32_arg(argv[i], &value.width))
                return FALSE;
        } else if (strcmp(arg, "--height") == 0) {
            saw_backend = TRUE;
            if (++i >= argc || !parse_u32_arg(argv[i], &value.height))
                return FALSE;
        } else if (strcmp(arg, "--stride") == 0) {
            saw_backend = TRUE;
            if (++i >= argc || !parse_u32_arg(argv[i], &value.stride))
                return FALSE;
        } else if (strcmp(arg, "--format") == 0) {
            saw_backend = TRUE;
            if (++i >= argc || !argv[i][0])
                return FALSE;
            value.pixel_format = argv[i];
        }
    }

    if (!saw_backend)
        return FALSE;
    if (value.control_fd < 0 || value.resource_fd < 0 ||
        value.control_fd == value.resource_fd || value.control_fd == value.fb_fd ||
        value.resource_fd == value.fb_fd || value.fb_fd < 0 || !value.width || !value.height ||
        !value.stride || !value.pixel_format)
        return FALSE;
    if (strcmp(value.pixel_format, "XRGB8888") != 0 &&
        strcmp(value.pixel_format, "ABGR8888") != 0)
        return FALSE;
    if (value.stride < value.width * 4U)
        return FALSE;
    int channels[] = { value.control_fd, value.resource_fd };
    for (unsigned i = 0; i < G_N_ELEMENTS(channels); ++i) {
        int type = 0;
        socklen_t size = sizeof(type);
        struct sockaddr_un address;
        socklen_t address_size = sizeof(address);
        if (getsockopt(channels[i], SOL_SOCKET, SO_TYPE, &type, &size) != 0 ||
            type != SOCK_SEQPACKET ||
            getsockname(channels[i], (struct sockaddr *)&address, &address_size) != 0 ||
            address.sun_family != AF_UNIX)
            return FALSE;
        /* Do not leak broker endpoints into subsequently exec'd engine helpers. */
        if (fcntl(channels[i], F_SETFD, FD_CLOEXEC) != 0)
            return FALSE;
    }
    struct stat control_stat, resource_stat;
    if (fstat(value.control_fd, &control_stat) != 0 ||
        fstat(value.resource_fd, &resource_stat) != 0 ||
        (control_stat.st_dev == resource_stat.st_dev && control_stat.st_ino == resource_stat.st_ino))
        return FALSE;
    struct timeval send_timeout = { .tv_sec = 1, .tv_usec = 0 };
    for (unsigned i = 0; i < G_N_ELEMENTS(channels); ++i) {
        if (setsockopt(channels[i], SOL_SOCKET, SO_SNDTIMEO,
                       &send_timeout, sizeof(send_timeout)) != 0)
            return FALSE;
    }
    *out = value;
    return TRUE;
}

static guint16 bj_get_u16(const guint8 *p)
{
    guint16 value;
    memcpy(&value, p, sizeof(value));
    return ntohs(value);
}

static guint32 bj_get_u32(const guint8 *p)
{
    guint32 value;
    memcpy(&value, p, sizeof(value));
    return ntohl(value);
}

static void bj_put_u16(guint8 *p, guint16 value)
{
    value = htons(value);
    memcpy(p, &value, sizeof(value));
}

static void bj_put_u32(guint8 *p, guint32 value)
{
    value = htonl(value);
    memcpy(p, &value, sizeof(value));
}

static gboolean bj_send_packet(int fd, guint16 kind, guint32 request_id,
                               const void *payload, guint32 length)
{
    if (length > BJ_MAX_PACKET)
        return FALSE;
    size_t total = 16U + (size_t)length;
    guint8 *packet = g_malloc(total);
    bj_put_u32(packet + 0, BJ_MAGIC);
    bj_put_u16(packet + 4, BJ_VERSION);
    bj_put_u16(packet + 6, kind);
    bj_put_u32(packet + 8, length);
    bj_put_u32(packet + 12, request_id);
    if (length && payload)
        memcpy(packet + 16, payload, length);
    ssize_t sent = send(fd, packet, total, MSG_NOSIGNAL);
    g_free(packet);
    return sent == (ssize_t)total;
}

static gboolean bj_send_packet_with_fd(int fd, guint16 kind, guint32 request_id,
                                       const void *payload, guint32 length,
                                       int attached_fd)
{
    if (length > BJ_MAX_PACKET || attached_fd < 0)
        return FALSE;
    size_t total = 16U + (size_t)length;
    guint8 *packet = g_malloc(total);
    bj_put_u32(packet + 0, BJ_MAGIC);
    bj_put_u16(packet + 4, BJ_VERSION);
    bj_put_u16(packet + 6, kind);
    bj_put_u32(packet + 8, length);
    bj_put_u32(packet + 12, request_id);
    if (length && payload)
        memcpy(packet + 16, payload, length);

    char control[CMSG_SPACE(sizeof(int))];
    memset(control, 0, sizeof(control));
    struct iovec iov = { .iov_base = packet, .iov_len = total };
    struct msghdr message = {0};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &attached_fd, sizeof(int));
    message.msg_controllen = CMSG_SPACE(sizeof(int));
    ssize_t sent = sendmsg(fd, &message, MSG_NOSIGNAL);
    g_free(packet);
    return sent == (ssize_t)total;
}

static GByteArray *bj_pack_strings(const char *const *values, size_t count)
{
    GByteArray *array = g_byte_array_new();
    for (size_t i = 0; i < count; ++i) {
        const char *value = values[i] ? values[i] : "";
        g_byte_array_append(array, (const guint8 *)value, strlen(value) + 1U);
    }
    return array;
}

static size_t bj_split_fields(char *payload, size_t length, char **fields, size_t maximum)
{
    if (!length || payload[length - 1] != '\0')
        return 0;
    size_t count = 0;
    size_t offset = 0;
    while (offset < length) {
        if (count == maximum)
            return 0;
        fields[count++] = payload + offset;
        size_t remaining = length - offset;
        size_t field_length = strnlen(payload + offset, remaining);
        if (field_length == remaining)
            return 0;
        offset += field_length + 1U;
    }
    return count;
}

static void backend_send_uri_event(struct BackendState *state, guint16 kind)
{
    const char *uri = state->uri ? state->uri : "";
    if (!bj_send_packet(state->control_fd, kind, 0, uri, (guint32)strlen(uri))) {
        fputs("WPE_STAGE4B_FAIL event-send\n", stderr);
        state->stopping = TRUE;
        g_main_loop_quit(state->loop);
    }
}

/* Headless WPE renders shared-memory frames as content changes. Publish those
 * bounded pixels immediately; page completion must not gate visible content. */
static void backend_buffer_rendered(WPEView *view, WPEBuffer *buffer, gpointer user_data)
{
    (void)view;
    struct BackendState *state = user_data;
    if (state->stopping || !state->document_id || !WPE_IS_BUFFER_SHM(buffer))
        return;
    WPEBufferSHM *shm = WPE_BUFFER_SHM(buffer);
    if (wpe_buffer_shm_get_format(shm) != WPE_PIXEL_FORMAT_ARGB8888)
        return;
    int width = wpe_buffer_get_width(buffer);
    int height = wpe_buffer_get_height(buffer);
    guint stride = wpe_buffer_shm_get_stride(shm);
    gsize length = 0;
    GBytes *bytes = wpe_buffer_shm_get_data(shm);
    const guint8 *data = bytes ? g_bytes_get_data(bytes, &length) : NULL;
    if (!data || width <= 0 || height <= 0 ||
        (guint64)stride < (guint64)width * 4U ||
        (guint64)length < (guint64)stride * (guint64)height)
        return;
    if (width != wpe_view_get_width(view) || height != wpe_view_get_height(view))
        return;
    ++state->frame_serial;
    unsigned rows = MIN(state->height, (unsigned)height);
    unsigned columns = MIN(state->width, (unsigned)width);
    for (unsigned y = 0; y < rows; ++y) {
        const guint8 *src = data + (gsize)y * stride;
        guint8 *dst = state->framebuffer + (gsize)y * state->stride;
        if (strcmp(state->pixel_format, "XRGB8888") == 0) {
            memcpy(dst, src, (gsize)columns * 4U);
        } else {
            for (unsigned x = 0; x < columns; ++x) {
                dst[4*x] = src[4*x+2]; dst[4*x+1] = src[4*x+1];
                dst[4*x+2] = src[4*x]; dst[4*x+3] = src[4*x+3];
            }
        }
    }
}

struct BackendSnapshot {
    struct BackendState *state;
    guint64 frame_serial;
};

static void backend_snapshot_ready(GObject *source, GAsyncResult *result, gpointer user_data)
{
    struct BackendSnapshot *request = user_data;
    struct BackendState *state = request->state;
    guint64 requested_serial = request->frame_serial;
    g_free(request);
    GError *error = NULL;
    WebKitImage *image = webkit_web_view_get_snapshot_finish(
        WEBKIT_WEB_VIEW(source), result, &error);
    if (state->stopping) {
        if (image) g_object_unref(image);
        g_clear_error(&error);
        return;
    }
    if (!image) {
        fprintf(stderr, "WPE_STAGE4B_FAIL render-snapshot %s\n",
                error ? error->message : "unknown");
        g_clear_error(&error);
        return;
    }

    GBytes *bytes = webkit_image_as_bytes(image);
    gsize length = 0;
    const guint8 *data = g_bytes_get_data(bytes, &length);
    int image_width = webkit_image_get_width(image);
    int image_height = webkit_image_get_height(image);
    guint image_stride = webkit_image_get_stride(image);

    /* WebKitImage snapshot bytes are BGRA8888.  BoJangles' established
     * frontend-owned shared plane defaults to ABGR8888, while XRGB8888 is
     * also part of the stable framebuffer API.  Convert deliberately instead
     * of changing the trusted frontend's plane contract. */
    if (image_width <= 0 || image_height <= 0 ||
        image_stride < (guint)image_width * 4U ||
        length < (gsize)image_stride * (gsize)image_height) {
        fputs("WPE_STAGE4B_FAIL malformed-snapshot-plane\n", stderr);
        g_object_unref(image);
        return;
    }

    WPEView *wpe_view = webkit_web_view_get_wpe_view(state->view);
    if (requested_serial != state->frame_serial ||
        (wpe_view && (image_width != wpe_view_get_width(wpe_view) ||
                      image_height != wpe_view_get_height(wpe_view)))) {
        g_object_unref(image);
        backend_send_uri_event(state, BJ_NAVIGATION_FINISHED);
        return;
    }
    memset(state->framebuffer, 0, state->framebuffer_length);
    unsigned rows = MIN(state->height, (unsigned)image_height);
    unsigned columns = MIN(state->width, (unsigned)image_width);
    for (unsigned y = 0; y < rows; ++y) {
        const guint8 *src_row = data + (gsize)y * image_stride;
        guint8 *dst_row = state->framebuffer + (gsize)y * state->stride;
        if (strcmp(state->pixel_format, "XRGB8888") == 0) {
            memcpy(dst_row, src_row, (gsize)columns * 4U);
            continue;
        }
        for (unsigned x = 0; x < columns; ++x) {
            const guint8 *src = src_row + (gsize)x * 4U;
            guint8 *dst = dst_row + (gsize)x * 4U;
            dst[0] = src[2];
            dst[1] = src[1];
            dst[2] = src[0];
            dst[3] = src[3];
        }
    }

    g_object_unref(image);
    backend_send_uri_event(state, BJ_NAVIGATION_FINISHED);
}

static void backend_load_changed(WebKitWebView *view, WebKitLoadEvent event, gpointer user_data)
{
    struct BackendState *state = user_data;
    if (event == WEBKIT_LOAD_COMMITTED)
        state->trusted_document_load = FALSE;
    if (event != WEBKIT_LOAD_FINISHED)
        return;

    /* Restore the host surface focus without changing page navigation mode.
     * Caret browsing moves DOM focus to the first link on focus-in, including
     * focus-only skip links. Ordinary keyboard editing needs no such mode. */
    WPEView *wpe_view = webkit_web_view_get_wpe_view(view);
    if (state->surface_focused && wpe_view)
        wpe_view_focus_in(wpe_view);

    stage7_cache_audit_start(&state->retention);
    struct BackendSnapshot *request = g_new(struct BackendSnapshot, 1);
    request->state = state;
    request->frame_serial = state->frame_serial;
    webkit_web_view_get_snapshot(
        view,
        WEBKIT_SNAPSHOT_REGION_VISIBLE,
        WEBKIT_SNAPSHOT_OPTIONS_NONE,
        state->operations,
        backend_snapshot_ready,
        request);
}

static gboolean backend_load_failed(WebKitWebView *view,
                                    WebKitLoadEvent event,
                                    const char *failing_uri,
                                    GError *error,
                                    gpointer user_data)
{
    (void)view;
    struct BackendState *state = user_data;
    g_clear_pointer(&state->pending_main_navigation_uri, g_free);
    gboolean cancelled = error && g_error_matches(error, WEBKIT_NETWORK_ERROR, WEBKIT_NETWORK_ERROR_CANCELLED);
    fprintf(stderr, "%s event=%d domain=%s code=%d uri=%s error=%s\n",
            cancelled ? "WPE_STAGE5B_RENDER_LOAD_CANCELLED" : "WPE_STAGE5B_RENDER_LOAD_FAILED",
            (int)event, error ? g_quark_to_string(error->domain) : "", error ? error->code : 0,
            failing_uri ? failing_uri : "", error ? error->message : "");
    /* HTTP/HTTPS never leaves WPE directly. Stage 5D keeps relative GET/POST resources on the private custom
     * scheme; raw HTTP/HTTPS and unsupported cases remain fail-closed. */
    return TRUE;
}

static char *bj_private_origin_token(const char *original_uri)
{
    if (!original_uri)
        return NULL;
    GError *error = NULL;
    GUri *uri = g_uri_parse(original_uri, G_URI_FLAGS_ENCODED, &error);
    if (!uri) {
        if (error) g_error_free(error);
        return NULL;
    }
    const char *scheme = g_uri_get_scheme(uri);
    const char *host = g_uri_get_host(uri);
    if (!scheme || !host ||
        (g_ascii_strcasecmp(scheme, "http") != 0 &&
         g_ascii_strcasecmp(scheme, "https") != 0)) {
        g_uri_unref(uri);
        return NULL;
    }
    int port = g_uri_get_port(uri);
    if (port < 0)
        port = g_ascii_strcasecmp(scheme, "https") == 0 ? 443 : 80;
    char *scheme_lower = g_ascii_strdown(scheme, -1);
    char *host_lower = g_ascii_strdown(host, -1);
    char *canonical = g_strdup_printf("%s://%s:%d", scheme_lower, host_lower, port);
    char *digest = g_compute_checksum_for_string(G_CHECKSUM_SHA256, canonical, -1);
    char *token = digest ? g_strconcat("o-", digest, NULL) : NULL;
    g_free(digest);
    g_free(canonical);
    g_free(host_lower);
    g_free(scheme_lower);
    g_uri_unref(uri);
    return token;
}

/* WebCore owns Origin (page script cannot set it). Bind a subframe's
 * network context to an HTTP origin admitted for this document, while keeping
 * the top-level document ID as the broker's independent authority. */
static void bj_refresh_subframe_context(struct BackendState *state)
{
    if (g_strcmp0(state->subframe_document, state->document_id)) {
        g_clear_pointer(&state->subframe_origins, g_hash_table_unref);
        g_free(state->subframe_document);
        state->subframe_document = g_strdup(state->document_id);
    }
    if (!state->subframe_origins)
        state->subframe_origins = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
}

static const char *bj_resource_initiator(struct BackendState *state, WebKitURISchemeRequest *request)
{
    bj_refresh_subframe_context(state);
    SoupMessageHeaders *headers = webkit_uri_scheme_request_get_http_headers(request);
    const char *origin = headers ? soup_message_headers_get_one(headers, "Origin") : NULL;
    char *token = origin ? bj_private_origin_token(origin) : NULL;
    gboolean known = token && g_hash_table_contains(state->subframe_origins, token);
    g_free(token);
    return known ? origin : state->uri;
}

static char *bj_private_base_uri(const char *original_uri)
{
    char *token = bj_private_origin_token(original_uri);
    if (!token)
        return NULL;
    GError *error = NULL;
    GUri *uri = g_uri_parse(original_uri, G_URI_FLAGS_ENCODED, &error);
    if (!uri) {
        if (error) g_error_free(error);
        g_free(token);
        return NULL;
    }
    const char *path = g_uri_get_path(uri);
    if (!path || !path[0]) path = "/";
    if (path[0] != '/') {
        g_uri_unref(uri);
        g_free(token);
        return NULL;
    }
    char *base = g_strdup_printf("bojangles-resource://%s%s", token, path);
    g_uri_unref(uri);
    g_free(token);
    return base;
}

static char *bj_private_navigation_uri(struct BackendState *state, const char *target_uri)
{
    if (!state || !state->uri || !target_uri)
        return NULL;

    char *current_token = bj_private_origin_token(state->uri);
    char *target_token = bj_private_origin_token(target_uri);
    if (!current_token || !target_token || g_strcmp0(current_token, target_token) != 0) {
        g_free(current_token);
        g_free(target_token);
        return NULL;
    }
    g_free(current_token);
    g_free(target_token);

    char *base = bj_private_base_uri(target_uri);
    if (!base)
        return NULL;

    GUri *target = g_uri_parse(target_uri, G_URI_FLAGS_ENCODED, NULL);
    if (!target) {
        g_free(base);
        return NULL;
    }
    const char *query = g_uri_get_query(target);
    char *private_uri = query && *query
        ? g_strdup_printf("%s?%s", base, query)
        : g_strdup(base);
    g_uri_unref(target);
    g_free(base);
    return private_uri;
}

static char *bj_decode_resource_uri(struct BackendState *state, const char *uri)
{
    if (!state || !state->uri || !uri)
        return NULL;
    GUri *absolute = g_uri_parse(uri, G_URI_FLAGS_ENCODED, NULL);
    if (absolute) {
        const char *scheme = g_uri_get_scheme(absolute);
        gboolean valid = scheme && (g_str_equal(scheme, "http") || g_str_equal(scheme, "https"))
            && g_uri_get_host(absolute) && !g_uri_get_userinfo(absolute);
        g_uri_unref(absolute);
        if (valid) return g_strdup(uri);
    }
    char *token = bj_private_origin_token(state->uri);
    if (!token)
        return NULL;
    char *prefix = g_strdup_printf("bojangles-resource://%s", token);
    g_free(token);
    size_t prefix_len = strlen(prefix);
    if (!g_str_has_prefix(uri, prefix) ||
        (uri[prefix_len] && uri[prefix_len] != '/')) {
        g_free(prefix);
        return NULL;
    }
    const char *relative = uri + prefix_len;
    if (!relative[0]) relative = "/";
    if (relative[0] != '/' || relative[1] == '/') {
        g_free(prefix);
        return NULL;
    }
    GError *error = NULL;
    char *resolved = g_uri_resolve_relative(
        state->uri, relative, G_URI_FLAGS_ENCODED, &error);
    g_free(prefix);
    if (!resolved) {
        if (error) g_error_free(error);
        return NULL;
    }
    if (!g_str_has_prefix(resolved, "http://") &&
        !g_str_has_prefix(resolved, "https://")) {
        g_free(resolved);
        return NULL;
    }
    return resolved;
}

/* Display metadata uses existing event slots and never changes state->uri,
 * which remains the frontend-authorized request/initiator identity. */
static void backend_title_changed(WebKitWebView *view, GParamSpec *property,
                                  gpointer user_data)
{
    (void)property;
    struct BackendState *state = user_data;
    if (state->stopping || !state->document_id)
        return;
    const char *title = webkit_web_view_get_title(view);
    if (!title) title = "";
    size_t length = strlen(title);
    if (length <= BJ_MAX_PACKET)
        bj_send_packet(state->control_fd, BJ_TITLE_CHANGED, 0, title, (guint32)length);
}

static void backend_uri_changed(WebKitWebView *view, GParamSpec *property,
                                gpointer user_data)
{
    (void)property;
    struct BackendState *state = user_data;
    if (state->stopping || !state->document_id || !state->uri)
        return;
    const char *private_uri = webkit_web_view_get_uri(view);
    char *original = bj_decode_resource_uri(state, private_uri);
    if (!original && g_strcmp0(private_uri, state->uri) == 0)
        original = g_strdup(state->uri);
    if (!original)
        return;
    size_t length = strlen(original);
    if (length <= BJ_MAX_PACKET)
        bj_send_packet(state->control_fd, BJ_URL_CHANGED, 0, original, (guint32)length);
    g_free(original);
}

static void backend_history_changed(WebKitBackForwardList *list,
                                     WebKitBackForwardListItem *added,
                                     GList *removed, gpointer user_data)
{
    (void)added;
    (void)removed;
    struct BackendState *state = user_data;
    if (state->stopping || !state->document_id)
        return;
    WebKitBackForwardListItem *item = webkit_back_forward_list_get_current_item(list);
    if (!item)
        return;
    char *original = bj_decode_resource_uri(
        state, webkit_back_forward_list_item_get_uri(item));
    if (original) {
        size_t length = strlen(original);
        if (length <= BJ_MAX_PACKET)
            bj_send_packet(state->control_fd, BJ_URL_CHANGED, 0, original, (guint32)length);
        g_free(original);
    }
}

static void backend_download_started(WebKitNetworkSession *session,
                                      WebKitDownload *download, gpointer user_data)
{
    (void)session;
    struct BackendState *state = user_data;
    /* Cancel before any destination is granted. The frontend receives intent
     * only and retains all download/file/host-execution authority. */
    WebKitURIRequest *request = webkit_download_get_request(download);
    char *original = request ? bj_decode_resource_uri(state,
        webkit_uri_request_get_uri(request)) : NULL;
    webkit_download_cancel(download);
    if (original && !state->stopping) {
        WebKitURIResponse *response = webkit_download_get_response(download);
        const char *fields[] = { original,
            response ? webkit_uri_response_get_suggested_filename(response) : "" };
        GByteArray *offer = bj_pack_strings(fields, 2);
        if (offer->len <= BJ_MAX_PACKET)
            bj_send_packet(state->resource_fd, BJ_DOWNLOAD_OFFER, 0,
                           offer->data, (guint32)offer->len);
        g_byte_array_unref(offer);
    }
    g_free(original);
}

static char *bj_html_to_utf8(const guint8 *body, gsize body_length,
                             const char *encoding)
{
    if (!body && body_length)
        return NULL;
    const char *source_encoding = (encoding && encoding[0]) ? encoding : "UTF-8";
    GError *error = NULL;
    gsize bytes_read = 0, bytes_written = 0;
    char *converted = g_convert((const char *)body, (gssize)body_length,
                                "UTF-8", source_encoding,
                                &bytes_read, &bytes_written, &error);
    if (!converted || bytes_read != body_length) {
        if (error) g_error_free(error);
        g_free(converted);
        return NULL;
    }
    return converted;
}

static void bj_scheme_fail(WebKitURISchemeRequest *request, const char *message)
{
    GError *error = g_error_new(G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED,
                                "%s", message ? message : "WPE resource denied");
    webkit_uri_scheme_request_finish_error(request, error);
    g_error_free(error);
}

#define BJ_STAGE5D_MAX_HEADERS 64U
#define BJ_STAGE5D_MAX_HEADER_BYTES (16U * 1024U)
#define BJ_STAGE5D_MAX_RESPONSE_HEADER_BYTES (32U * 1024U)
#define BJ_STAGE5D_MAX_RESPONSE_HEADER_VALUE_BYTES (8U * 1024U)
#define BJ_STAGE5D_MAX_REQUEST_BODY (1024U * 1024U * 1024U)
#define BJ_STAGE5D_MAX_CROSS_ORIGIN_POST (256U * 1024U)

static gboolean bj_header_field_safe(const char *value, size_t maximum)
{
    if (!value || strlen(value) > maximum)
        return FALSE;
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        if (*p == '\r' || *p == '\n' || *p == '\0')
            return FALSE;
    }
    return TRUE;
}

static gboolean bj_seal_request_body(WebKitURISchemeRequest *request,
                                     const char *method,
                                     gboolean inline_only,
                                     int *fd_out,
                                     size_t *length_out)
{
    *fd_out = -1;
    *length_out = 0;
    if (strcmp(method, "GET") == 0 || strcmp(method, "OPTIONS") == 0)
        return TRUE;
    if (strcmp(method, "POST") != 0)
        return FALSE;

    const size_t maximum = inline_only
        ? BJ_STAGE5D_MAX_CROSS_ORIGIN_POST
        : BJ_STAGE5D_MAX_REQUEST_BODY;
    int body_fd = memfd_create("bojangles-wpe-request-body", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (body_fd < 0)
        return FALSE;

    size_t total = 0;
    if (strcmp(method, "POST") == 0) {
        /* WPE custom-scheme request bodies live in the UI process. Resolving an
         * EncodedBlobData element there dereferences WebCore's absent global
         * BlobRegistry and crashes the renderer. Detect that body shape without
         * resolving it and fail this one request closed. */
        if (webkit_uri_scheme_request_bojangles_http_body_contains_blob(request)) {
            close(body_fd);
            return FALSE;
        }
    }
    if (inline_only) {
        GBytes *inline_body =
            webkit_uri_scheme_request_get_bojangles_inline_http_body(request, maximum);
        if (!inline_body) {
            close(body_fd);
            return FALSE;
        }
        gsize inline_size = 0;
        const guint8 *inline_data = g_bytes_get_data(inline_body, &inline_size);
        if (inline_size > maximum) {
            g_bytes_unref(inline_body);
            close(body_fd);
            return FALSE;
        }
        size_t offset = 0;
        while (offset < inline_size) {
            ssize_t written = write(body_fd, inline_data + offset, inline_size - offset);
            if (written <= 0) {
                g_bytes_unref(inline_body);
                close(body_fd);
                return FALSE;
            }
            offset += (size_t)written;
        }
        total = inline_size;
        g_bytes_unref(inline_body);
    } else {
        GInputStream *stream = webkit_uri_scheme_request_get_http_body(request);
        if (stream) {
            guint8 chunk[64U * 1024U];
            for (;;) {
                GError *error = NULL;
                gssize got = g_input_stream_read(stream, chunk, sizeof(chunk), NULL, &error);
                if (got < 0) {
                    if (error) g_error_free(error);
                    close(body_fd);
                    return FALSE;
                }
                if (got == 0)
                    break;
                if (total + (size_t)got > maximum) {
                    close(body_fd);
                    return FALSE;
                }
                size_t offset = 0;
                while (offset < (size_t)got) {
                    ssize_t written = write(body_fd, chunk + offset, (size_t)got - offset);
                    if (written <= 0) {
                        close(body_fd);
                        return FALSE;
                    }
                    offset += (size_t)written;
                }
                total += (size_t)got;
            }
        }
    }

    int seals = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;
    if (fcntl(body_fd, F_ADD_SEALS, seals) != 0 ||
        (fcntl(body_fd, F_GET_SEALS) & seals) != seals) {
        close(body_fd);
        return FALSE;
    }
    *length_out = total;
    *fd_out = body_fd;
    return TRUE;
}

/* The custom HTTP handler does not perform a CORS preflight. Reject any
 * cross-origin request that would require one before sending broker IPC. */
static GByteArray *bj_resource_request_payload_metadata(struct BackendState *state,
                                                        WebKitURISchemeRequest *request,
                                                        const char *original,
                                                        const char *resource_type,
                                                        size_t body_length)
{
    const char *method = webkit_uri_scheme_request_get_http_method(request);
    if (!method || (strcmp(method, "GET") != 0 && strcmp(method, "POST") != 0 && strcmp(method, "OPTIONS") != 0))
        return NULL;

    const char *names[BJ_STAGE5D_MAX_HEADERS];
    const char *values_seen[BJ_STAGE5D_MAX_HEADERS];
    size_t header_count = 0;
    size_t header_bytes = 0;
    SoupMessageHeaders *headers = webkit_uri_scheme_request_get_http_headers(request);
    if (headers) {
        SoupMessageHeadersIter iter;
        const char *name = NULL;
        const char *value = NULL;
        soup_message_headers_iter_init(&iter, headers);
        while (soup_message_headers_iter_next(&iter, &name, &value)) {
            if (header_count == BJ_STAGE5D_MAX_HEADERS ||
                !bj_header_field_safe(name, 128U) ||
                !bj_header_field_safe(value, 4096U))
                return NULL;
            header_bytes += strlen(name) + strlen(value) + 4U;
            if (header_bytes > BJ_STAGE5D_MAX_HEADER_BYTES)
                return NULL;
            if (g_ascii_strcasecmp(name, "Sec-BoJangles-Initiator") == 0)
                continue;
            names[header_count] = name;
            values_seen[header_count] = value;
            ++header_count;
        }
    }

    const char *network_initiator = bj_resource_initiator(state, request);
    if (network_initiator != state->uri) {
        if (header_count == BJ_STAGE5D_MAX_HEADERS)
            return NULL;
        names[header_count] = "Sec-BoJangles-Initiator";
        values_seen[header_count++] = network_initiator;
    }

    char body_length_text[32];
    char count_text[24];
    snprintf(body_length_text, sizeof(body_length_text), "%zu", body_length);
    snprintf(count_text, sizeof(count_text), "%zu", header_count);
    GByteArray *body = g_byte_array_new();
    const char *fixed[] = {
        state->document_id, original, resource_type, state->uri, method,
        "stage5d-stats", body_length_text, count_text
    };
    for (size_t index = 0; index < G_N_ELEMENTS(fixed); ++index)
        g_byte_array_append(body, (const guint8 *)fixed[index], strlen(fixed[index]) + 1U);
    for (size_t index = 0; index < header_count; ++index) {
        g_byte_array_append(body, (const guint8 *)names[index], strlen(names[index]) + 1U);
        g_byte_array_append(body, (const guint8 *)values_seen[index], strlen(values_seen[index]) + 1U);
    }
    guint group = GPOINTER_TO_UINT(g_object_get_data(G_OBJECT(request), "bojangles-stat-group"));
    if (!group && state->statistics_group < G_MAXUINT32) {
        group = ++state->statistics_group;
        g_object_set_data(G_OBJECT(request), "bojangles-stat-group", GUINT_TO_POINTER(group));
    }
    char group_text[16];
    snprintf(group_text, sizeof(group_text), "%u", group);
    g_byte_array_append(body, (const guint8 *)group_text, strlen(group_text) + 1U);
    if (body->len > BJ_MAX_PACKET) {
        g_byte_array_unref(body);
        return NULL;
    }
    return body;
}

static GByteArray *bj_resource_request_payload(struct BackendState *state,
                                               WebKitURISchemeRequest *request,
                                               const char *original,
                                               const char *resource_type,
                                               gboolean inline_body_only,
                                               int *body_fd_out)
{
    const char *method = webkit_uri_scheme_request_get_http_method(request);
    if (!method || (strcmp(method, "GET") != 0 && strcmp(method, "POST") != 0 && strcmp(method, "OPTIONS") != 0))
        return NULL;

    size_t body_length = 0;
    if (!bj_seal_request_body(request, method, inline_body_only, body_fd_out, &body_length))
        return NULL;
    GByteArray *body = bj_resource_request_payload_metadata(
        state, request, original, resource_type, body_length);
    if (!body && *body_fd_out >= 0) {
        close(*body_fd_out);
        *body_fd_out = -1;
    }
    return body;
}

static gboolean bj_append_response_headers(WebKitURISchemeResponse *response,
                                           char **fields, size_t field_count,
                                           SoupMessageHeaders **mirror_headers)
{
    *mirror_headers = NULL;
    if (field_count == 5U)
        return TRUE; /* Stage 5B compatibility envelope. */
    if (field_count < 6U)
        return FALSE;
    char *end = NULL;
    errno = 0;
    unsigned long count = strtoul(fields[5], &end, 10);
    if (errno || !end || *end || count > BJ_STAGE5D_MAX_HEADERS ||
        field_count != 6U + (size_t)count * 2U)
        return FALSE;

    SoupMessageHeaders *headers = soup_message_headers_new(SOUP_MESSAGE_HEADERS_RESPONSE);
    size_t header_bytes = 0;
    for (size_t index = 0; index < (size_t)count; ++index) {
        const char *name = fields[6U + index * 2U];
        const char *value = fields[7U + index * 2U];
        if (!bj_header_field_safe(name, 128U) ||
            !bj_header_field_safe(value, BJ_STAGE5D_MAX_RESPONSE_HEADER_VALUE_BYTES)) {
            soup_message_headers_unref(headers);
            return FALSE;
        }
        header_bytes += strlen(name) + strlen(value) + 4U;
        if (header_bytes > BJ_STAGE5D_MAX_RESPONSE_HEADER_BYTES) {
            soup_message_headers_unref(headers);
            return FALSE;
        }
        soup_message_headers_append(headers, name, value);
    }
    *mirror_headers = soup_message_headers_ref(headers);
    webkit_uri_scheme_response_set_http_headers(response, headers);
    return TRUE; /* transfer-full headers now owned by response */
}

/* Custom HTTP handlers bypass Soup's normal response cookie processing.
 * Mirror only cookies admitted by the trusted transport, before releasing
 * the response to page scripts. The trusted jar remains network authority. */
static void bj_finish_redirect(struct BackendState *, WebKitURISchemeRequest *,
                               const char *, guint, SoupMessageHeaders *);

struct BJCookieResponse {
    WebKitURISchemeRequest *request;
    WebKitURISchemeResponse *response;
    WebKitCookieManager *manager;
    GCancellable *cancellable;
    GPtrArray *cookies;
    guint next;
    struct BackendState *state;
    char *redirect_target;
    char *document_id;
    guint redirect_status;
    SoupMessageHeaders *redirect_headers;
};

static void bj_cookie_response_free(struct BJCookieResponse *pending)
{
    g_clear_object(&pending->request);
    g_clear_object(&pending->response);
    g_clear_object(&pending->manager);
    g_clear_object(&pending->cancellable);
    g_ptr_array_unref(pending->cookies);
    g_free(pending->redirect_target);
    g_free(pending->document_id);
    if (pending->redirect_headers) soup_message_headers_unref(pending->redirect_headers);
    g_free(pending);
}

static void bj_cookie_response_next(struct BJCookieResponse *pending);

static void bj_cookie_response_ready(GObject *source, GAsyncResult *result, gpointer data)
{
    struct BJCookieResponse *pending = data;
    GError *error = NULL;
    if (!webkit_cookie_manager_add_cookie_finish(WEBKIT_COOKIE_MANAGER(source), result, &error)) {
        g_clear_error(&error);
        bj_scheme_fail(pending->request, "trusted response cookie mirror failed");
        bj_cookie_response_free(pending);
        return;
    }
    bj_cookie_response_next(pending);
}

static void bj_cookie_response_next(struct BJCookieResponse *pending)
{
    if (g_cancellable_is_cancelled(pending->cancellable) ||
        (pending->redirect_target && (pending->state->stopping ||
         g_strcmp0(pending->document_id, pending->state->document_id)))) {
        bj_scheme_fail(pending->request, "trusted response cookie mirror cancelled");
        bj_cookie_response_free(pending);
        return;
    }
    if (pending->next == pending->cookies->len) {
        if (pending->redirect_target)
            bj_finish_redirect(pending->state, pending->request, pending->redirect_target,
                               pending->redirect_status, pending->redirect_headers);
        else
            webkit_uri_scheme_request_finish_with_response(pending->request, pending->response);
        bj_cookie_response_free(pending);
        return;
    }
    SoupCookie *cookie = g_ptr_array_index(pending->cookies, pending->next++);
    webkit_cookie_manager_add_cookie(pending->manager, cookie, pending->cancellable,
                                     bj_cookie_response_ready, pending);
}

static void bj_finish_cookie_response_or_redirect(struct BackendState *state,
                                     WebKitURISchemeRequest *request,
                                     WebKitURISchemeResponse *response,
                                     SoupMessageHeaders *headers,
                                     const char *redirect_target, guint redirect_status)
{
    const char *uri_text = webkit_uri_scheme_request_get_uri(request);
    GUri *uri = uri_text ? g_uri_parse(uri_text, G_URI_FLAGS_ENCODED, NULL) : NULL;
    GPtrArray *cookies = g_ptr_array_new_with_free_func((GDestroyNotify)soup_cookie_free);
    gboolean valid = TRUE;
    if (headers && uri) {
        SoupMessageHeadersIter iter;
        const char *name, *value;
        soup_message_headers_iter_init(&iter, headers);
        while (soup_message_headers_iter_next(&iter, &name, &value)) {
            if (g_ascii_strcasecmp(name, "Set-Cookie"))
                continue;
            SoupCookie *cookie = soup_cookie_parse(value, uri);
            const char *host = g_uri_get_host(uri);
            if (!cookie || !host || !soup_cookie_domain_matches(cookie, host)
                || stage6_cookie_should_delete(cookie) || cookies->len >= 16U) {
                if (cookie) soup_cookie_free(cookie);
                valid = FALSE;
                break;
            }
            g_ptr_array_add(cookies, cookie);
        }
    }
    if (uri) g_uri_unref(uri);
    if (!valid) {
        g_ptr_array_unref(cookies);
        bj_scheme_fail(request, "invalid trusted response cookie mirror");
        return;
    }
    if (!cookies->len) {
        g_ptr_array_unref(cookies);
        if (redirect_target)
            bj_finish_redirect(state, request, redirect_target, redirect_status, headers);
        else
            webkit_uri_scheme_request_finish_with_response(request, response);
        return;
    }
    WebKitNetworkSession *session = webkit_web_view_get_network_session(state->view);
    WebKitCookieManager *manager = session ? webkit_network_session_get_cookie_manager(session) : NULL;
    if (!manager) {
        g_ptr_array_unref(cookies);
        bj_scheme_fail(request, "trusted response cookie manager unavailable");
        return;
    }
    struct BJCookieResponse *pending = g_new0(struct BJCookieResponse, 1);
    pending->request = g_object_ref(request);
    pending->response = response ? g_object_ref(response) : NULL;
    pending->state = state;
    pending->redirect_target = g_strdup(redirect_target);
    pending->document_id = g_strdup(state->document_id);
    pending->redirect_status = redirect_status;
    pending->redirect_headers = redirect_target ? soup_message_headers_ref(headers) : NULL;
    pending->manager = g_object_ref(manager);
    pending->cancellable = g_object_ref(state->operations);
    pending->cookies = cookies;
    bj_cookie_response_next(pending);
}

static void bj_finish_cookie_response(struct BackendState *state,
                                     WebKitURISchemeRequest *request,
                                     WebKitURISchemeResponse *response,
                                     SoupMessageHeaders *headers)
{
    bj_finish_cookie_response_or_redirect(state, request, response, headers, NULL, 0);
}

struct PendingResourceRequest {
    WebKitURISchemeRequest *request;
};

static void
bj_pending_resource_free(gpointer data)
{
    struct PendingResourceRequest *pending = data;

    if (!pending)
        return;

    if (pending->request)
        g_object_unref(pending->request);

    g_free(pending);
}

static guint32
bj_allocate_resource_request_id(struct BackendState *state)
{
    for (;;) {
        guint32 request_id = state->next_resource_request_id++;

        if (!state->next_resource_request_id)
            state->next_resource_request_id = 1U;

        if (!request_id)
            continue;

        if (!g_hash_table_contains(
                state->pending_resources,
                GUINT_TO_POINTER(request_id)))
            return request_id;
    }
}

struct AsyncPostCapture {
    struct BackendState *state;
    WebKitURISchemeRequest *request;
    GInputStream *stream;
    char *original;
    char *resource_type;
    int body_fd;
    size_t body_length;
};

static void bj_async_post_capture_free(struct AsyncPostCapture *capture)
{
    if (!capture)
        return;
    if (capture->body_fd >= 0)
        close(capture->body_fd);
    g_clear_object(&capture->stream);
    g_clear_object(&capture->request);
    g_free(capture->original);
    g_free(capture->resource_type);
    g_free(capture);
}

static void bj_async_post_fail(struct AsyncPostCapture *capture, const char *message)
{
    if (!capture->state->stopping)
        bj_scheme_fail(capture->request, message);
    bj_async_post_capture_free(capture);
}

static gboolean bj_async_post_send(struct AsyncPostCapture *capture)
{
    int seals = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;
    if (fcntl(capture->body_fd, F_ADD_SEALS, seals) != 0 ||
        (fcntl(capture->body_fd, F_GET_SEALS) & seals) != seals) {
        bj_async_post_fail(capture, "failed to seal trusted POST body");
        return FALSE;
    }

    GByteArray *body = bj_resource_request_payload_metadata(
        capture->state, capture->request, capture->original,
        capture->resource_type, capture->body_length);
    if (!body) {
        bj_async_post_fail(capture, "invalid trusted POST metadata");
        return FALSE;
    }

    guint32 request_id = bj_allocate_resource_request_id(capture->state);
    struct PendingResourceRequest *pending = g_new0(struct PendingResourceRequest, 1);
    pending->request = g_object_ref(capture->request);
    g_hash_table_insert(
        capture->state->pending_resources,
        GUINT_TO_POINTER(request_id),
        pending);

    gboolean sent = bj_send_packet_with_fd(
        capture->state->resource_fd, BJ_RESOURCE_REQUEST, request_id,
        body->data, (guint32)body->len, capture->body_fd);
    g_byte_array_unref(body);

    if (!sent) {
        g_hash_table_steal(
            capture->state->pending_resources,
            GUINT_TO_POINTER(request_id));
        bj_scheme_fail(pending->request, "trusted POST handoff unavailable");
        bj_pending_resource_free(pending);
        bj_async_post_capture_free(capture);
        return FALSE;
    }

    bj_async_post_capture_free(capture);
    return TRUE;
}

static void bj_async_post_read_ready(GObject *source, GAsyncResult *result, gpointer data)
{
    struct AsyncPostCapture *capture = data;
    GError *error = NULL;
    GBytes *bytes = g_input_stream_read_bytes_finish(
        G_INPUT_STREAM(source), result, &error);
    if (!bytes) {
        if (error) g_error_free(error);
        bj_async_post_fail(capture, "trusted POST body read failed");
        return;
    }

    gsize length = 0;
    const guint8 *chunk = g_bytes_get_data(bytes, &length);
    if (!length) {
        g_bytes_unref(bytes);
        bj_async_post_send(capture);
        return;
    }
    if (capture->body_length + length > BJ_STAGE5D_MAX_REQUEST_BODY) {
        g_bytes_unref(bytes);
        bj_async_post_fail(capture, "trusted POST body exceeds same-origin limit");
        return;
    }

    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(capture->body_fd, chunk + offset, length - offset);
        if (written <= 0) {
            g_bytes_unref(bytes);
            bj_async_post_fail(capture, "trusted POST body spool failed");
            return;
        }
        offset += (size_t)written;
    }
    capture->body_length += length;
    g_bytes_unref(bytes);

    g_input_stream_read_bytes_async(
        capture->stream, 64U * 1024U, G_PRIORITY_DEFAULT,
        capture->state->operations, bj_async_post_read_ready, capture);
}

static gboolean bj_start_async_post_resource(struct BackendState *state,
                                             WebKitURISchemeRequest *request,
                                             const char *original,
                                             const char *resource_type)
{
    /* Do not ask WebKit to materialize a Blob-backed custom-scheme body in
     * the UI process. That path calls PlatformStrategies::blobRegistry(),
     * which is WebProcess-only in WPE and crashes the native renderer.
     * Reject only this request; ordinary same-origin POSTs keep the async
     * spool path below. */
    if (webkit_uri_scheme_request_bojangles_http_body_contains_blob(request)) {
        bj_scheme_fail(request, "Blob-backed POST body is unsupported by the trusted WPE broker");
        return FALSE;
    }

    GInputStream *stream = webkit_uri_scheme_request_get_http_body(request);
    struct AsyncPostCapture *capture = g_new0(struct AsyncPostCapture, 1);
    capture->state = state;
    capture->request = g_object_ref(request);
    capture->stream = stream ? g_object_ref(stream) : NULL;
    capture->original = g_strdup(original);
    capture->resource_type = g_strdup(resource_type);
    capture->body_fd = memfd_create(
        "bojangles-wpe-request-body", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (capture->body_fd < 0) {
        bj_async_post_fail(capture, "trusted POST spool unavailable");
        return FALSE;
    }
    if (!capture->stream)
        return bj_async_post_send(capture);

    g_input_stream_read_bytes_async(
        capture->stream, 64U * 1024U, G_PRIORITY_DEFAULT,
        state->operations, bj_async_post_read_ready, capture);
    return TRUE;
}


extern gboolean webkit_uri_scheme_request_bojangles_redirect(
    WebKitURISchemeRequest*, const gchar*, guint, SoupMessageHeaders*,
    void (*)(WebKitURISchemeRequest*, gboolean, gpointer), gpointer, GDestroyNotify);

static void backend_resource_scheme_request(WebKitURISchemeRequest*, gpointer);
struct RedirectCapture {
    struct BackendState* state;
    char* document_id;
};
static void bj_redirect_capture_free(gpointer data)
{
    struct RedirectCapture* capture = data;
    g_free(capture->document_id);
    g_free(capture);
}
static void bj_redirect_ready(WebKitURISchemeRequest* request, gboolean allowed, gpointer data)
{
    struct RedirectCapture* capture = data;
    if (!allowed || capture->state->stopping ||
        g_strcmp0(capture->document_id, capture->state->document_id) != 0) {
        bj_scheme_fail(request, "resource redirect lost document authority");
        return;
    }
    backend_resource_scheme_request(request, capture->state);
}

static void bj_finish_redirect(struct BackendState *state, WebKitURISchemeRequest *request,
                               const char *target, guint status, SoupMessageHeaders *headers)
{
    struct RedirectCapture *capture = g_new0(struct RedirectCapture, 1);
    capture->state = state;
    capture->document_id = g_strdup(state->document_id);
    if (!webkit_uri_scheme_request_bojangles_redirect(request, target, status, headers,
            bj_redirect_ready, capture, bj_redirect_capture_free))
        bj_scheme_fail(request, "WebKit resource redirect rejected");
}

static void
bj_complete_resource_reply(struct BackendState *state,
                           guint16 kind,
                           guint32 request_id,
                           char *payload,
                           guint32 length,
                           int received_fd)
{
    struct PendingResourceRequest *pending =
        g_hash_table_lookup(
            state->pending_resources,
            GUINT_TO_POINTER(request_id));

    if (!pending) {
        if (received_fd >= 0)
            close(received_fd);

        fputs(
            "WPE_CANDIDATE_FAIL unknown-resource-reply\n",
            stderr);

        return;
    }

    g_hash_table_steal(
        state->pending_resources,
        GUINT_TO_POINTER(request_id));

    WebKitURISchemeRequest *request = pending->request;

    if (kind == BJ_RESOURCE_DECISION) {
        if (received_fd >= 0)
            close(received_fd);

        bj_scheme_fail(
            request,
            "WPE resource denied by trusted gateway");

        bj_pending_resource_free(pending);
        return;
    }


    if (kind == BJ_RESOURCE_REDIRECT) {
        char* fields[4U + BJ_STAGE5D_MAX_HEADERS * 2U];
        size_t count = bj_split_fields(payload, length, fields, G_N_ELEMENTS(fields));
        char* end = NULL;
        char* header_end = NULL;
        unsigned long status = count >= 4 ? strtoul(fields[2], &end, 10) : 0;
        unsigned long header_count = count >= 4 ? strtoul(fields[3], &header_end, 10) : 0;
        gboolean valid = count >= 4 && received_fd < 0 && end && !*end &&
            header_end && !*header_end && header_count <= BJ_STAGE5D_MAX_HEADERS &&
            count == 4U + header_count * 2U &&
            g_strcmp0(fields[0], webkit_uri_scheme_request_get_uri(request)) == 0 &&
            (g_strcmp0(webkit_uri_scheme_request_get_http_method(request), "GET") == 0 ||
             g_strcmp0(webkit_uri_scheme_request_get_http_method(request), "POST") == 0);
        SoupMessageHeaders* headers = soup_message_headers_new(SOUP_MESSAGE_HEADERS_RESPONSE);
        if (valid) {
            for (unsigned long index = 0; index < header_count; ++index) {
                const char* name = fields[4U + index * 2U];
                const char* value = fields[5U + index * 2U];
                if (!*name || strchr(name, '\r') || strchr(name, '\n') ||
                    strchr(value, '\r') || strchr(value, '\n')) { valid = FALSE; break; }
                soup_message_headers_append(headers, name, value);
            }
        }
        if (received_fd >= 0) close(received_fd);
        if (valid) {
            guint hops = GPOINTER_TO_UINT(g_object_get_data(G_OBJECT(request), "bojangles-redirect-hops"));
            GHashTable *visited = g_object_get_data(G_OBJECT(request), "bojangles-redirect-visited");
            if (!visited) {
                visited = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
                g_hash_table_add(visited, g_strdup(fields[0]));
                g_object_set_data_full(G_OBJECT(request), "bojangles-redirect-visited", visited,
                                      (GDestroyNotify)g_hash_table_unref);
            }
            if (hops >= 6U || g_hash_table_contains(visited, fields[1])) {
                guint group = GPOINTER_TO_UINT(g_object_get_data(G_OBJECT(request), "bojangles-stat-group"));
                char group_text[16];
                snprintf(group_text, sizeof(group_text), "%u", group);
                GUri *destination = g_uri_parse(fields[1], G_URI_FLAGS_ENCODED, NULL);
                const char *host = destination ? g_uri_get_host(destination) : "";
                const char *stop_fields[] = {state->document_id, group_text,
                    hops >= 6U ? "redirect-limit" : "redirect-loop", host ? host : ""};
                GByteArray *stop = bj_pack_strings(stop_fields, 4);
                bj_send_packet(state->control_fd, BJ_RESOURCE_STOPPED, 0, stop->data, stop->len);
                g_byte_array_unref(stop);
                if (destination) g_uri_unref(destination);
                bj_scheme_fail(request, "Resource redirect chain stopped");
                soup_message_headers_unref(headers);
                bj_pending_resource_free(pending);
                return;
            }
            g_hash_table_add(visited, g_strdup(fields[1]));
            g_object_set_data(G_OBJECT(request), "bojangles-redirect-hops", GUINT_TO_POINTER(hops + 1U));
            bj_finish_cookie_response_or_redirect(state, request, NULL, headers,
                                                  fields[1], (guint)status);
        } else {
            bj_scheme_fail(request, "invalid trusted resource redirect metadata");
        }
        soup_message_headers_unref(headers);
        bj_pending_resource_free(pending);
        return;
    }

    if (kind != BJ_RESOURCE_DATA || received_fd < 0) {
        if (received_fd >= 0)
            close(received_fd);

        bj_scheme_fail(
            request,
            "unexpected trusted WPE resource reply");

        bj_pending_resource_free(pending);
        return;
    }

    char *fields[6U + BJ_STAGE5D_MAX_HEADERS * 2U];

    size_t field_count =
        bj_split_fields(
            payload,
            length,
            fields,
            G_N_ELEMENTS(fields));

    if (field_count < 5U) {
        close(received_fd);

        bj_scheme_fail(
            request,
            "malformed trusted WPE resource metadata");

        bj_pending_resource_free(pending);
        return;
    }

    char *end_status = NULL;
    char *end_length = NULL;

    errno = 0;

    unsigned long status =
        strtoul(fields[3], &end_status, 10);

    unsigned long long body_length =
        strtoull(fields[4], &end_length, 10);

    struct stat body_stat;

    int required_seals =
        F_SEAL_SEAL |
        F_SEAL_SHRINK |
        F_SEAL_GROW |
        F_SEAL_WRITE;

    int actual_seals =
        fcntl(received_fd, F_GET_SEALS);

    if (
        errno ||
        !end_status ||
        *end_status ||
        !end_length ||
        *end_length ||
        status < 200UL ||
        status >= 600UL ||
        (status >= 300UL && status < 400UL) ||
        body_length > 8ULL * 1024ULL * 1024ULL ||
        actual_seals < 0 ||
        (actual_seals & required_seals) != required_seals ||
        fstat(received_fd, &body_stat) != 0 ||
        body_stat.st_size < 0 ||
        (unsigned long long)body_stat.st_size != body_length
    ) {
        close(received_fd);

        bj_scheme_fail(
            request,
            "invalid trusted WPE resource memfd");

        bj_pending_resource_free(pending);
        return;
    }

    guint8 *resource =
        g_malloc(
            (gsize)body_length
                ? (gsize)body_length
                : 1U);

    size_t offset = 0;

    while (offset < (size_t)body_length) {
        ssize_t got =
            pread(
                received_fd,
                resource + offset,
                (size_t)body_length - offset,
                (off_t)offset);

        if (got <= 0) {
            g_free(resource);
            close(received_fd);

            bj_scheme_fail(
                request,
                "trusted WPE resource memfd read failed");

            bj_pending_resource_free(pending);
            return;
        }

        offset += (size_t)got;
    }

    close(received_fd);

    char *content_type =
        fields[2][0]
            ? g_strdup_printf(
                "%s%s%s",
                fields[1][0]
                    ? fields[1]
                    : "application/octet-stream",
                fields[2][0]
                    ? "; charset="
                    : "",
                fields[2])
            : g_strdup(
                fields[1][0]
                    ? fields[1]
                    : "application/octet-stream");

    GInputStream *stream =
        g_memory_input_stream_new_from_data(
            resource,
            (gssize)body_length,
            g_free);

    WebKitURISchemeResponse *response =
        webkit_uri_scheme_response_new(
            stream,
            (gint64)body_length);

    if (!response) {
        g_object_unref(stream);
        g_free(content_type);

        bj_scheme_fail(
            request,
            "failed to create trusted WPE response");

        bj_pending_resource_free(pending);
        return;
    }

    webkit_uri_scheme_response_set_status(
        response,
        (guint)status,
        NULL);

    webkit_uri_scheme_response_set_content_type(
        response,
        content_type);

    SoupMessageHeaders *mirror_headers = NULL;
    if (!bj_append_response_headers(
            response,
            fields,
            field_count, &mirror_headers)) {
        g_object_unref(response);
        g_object_unref(stream);
        g_free(content_type);

        bj_scheme_fail(
            request,
            "invalid trusted WPE response headers");

        bj_pending_resource_free(pending);
        return;
    }

    bj_finish_cookie_response(state, request, response, mirror_headers);
    if (mirror_headers) soup_message_headers_unref(mirror_headers);

    g_object_unref(response);
    g_object_unref(stream);
    g_free(content_type);

    bj_pending_resource_free(pending);
}

static void
backend_resource_scheme_request(WebKitURISchemeRequest *request,
                                gpointer user_data)
{
    struct BackendState *state = user_data;

    const char *scheme_uri =
        webkit_uri_scheme_request_get_uri(request);

    if (
        state->pending_document_bytes &&
        state->pending_document_uri &&
        scheme_uri &&
        g_strcmp0(state->pending_document_uri, scheme_uri) == 0 &&
        g_strcmp0(webkit_uri_scheme_request_get_http_method(request), "GET") == 0
    ) {
        gsize body_length = 0;
        g_bytes_get_data(state->pending_document_bytes, &body_length);
        GInputStream *stream =
            g_memory_input_stream_new_from_bytes(state->pending_document_bytes);
        WebKitURISchemeResponse *response =
            webkit_uri_scheme_response_new(stream, (gint64)body_length);
        if (!response) {
            g_object_unref(stream);
            bj_scheme_fail(request, "failed to create trusted main-document response");
            bj_clear_pending_document(state);
            return;
        }
        webkit_uri_scheme_response_set_status(
            response,
            state->pending_document_status ? state->pending_document_status : 200U,
            NULL);
        webkit_uri_scheme_response_set_content_type(
            response,
            state->pending_document_content_type
                ? state->pending_document_content_type
                : "application/octet-stream");
        if (state->pending_document_headers)
            webkit_uri_scheme_response_set_http_headers(
                response, soup_message_headers_ref(state->pending_document_headers));
        bj_finish_cookie_response(state, request, response, state->pending_document_headers);
        g_object_unref(response);
        g_object_unref(stream);
        bj_clear_pending_document(state);
        return;
    }

    SoupMessageHeaders *metadata = webkit_uri_scheme_request_get_http_headers(request);
    const char *main_navigation = metadata ? soup_message_headers_get_one(metadata, "X-BoJangles-Main-Navigation") : NULL;
    gboolean trusted_main_navigation =
        state->pending_main_navigation_uri &&
        g_strcmp0(state->pending_main_navigation_uri, scheme_uri) == 0;
    if (trusted_main_navigation)
        g_clear_pointer(&state->pending_main_navigation_uri, g_free);
    if (trusted_main_navigation || g_strcmp0(main_navigation, "1") == 0) {
        /* Re-enter trusted frontend navigation; never borrow the old document ID. */
        const char *method = webkit_uri_scheme_request_get_http_method(request);
        if (g_strcmp0(method, "POST") == 0) {
            char *original = bj_decode_resource_uri(state, scheme_uri);
            int body_fd = -1;
            GByteArray *body = original ? bj_resource_request_payload(
                state, request, original, "DOCUMENT", FALSE, &body_fd) : NULL;
            guint32 request_id = bj_allocate_resource_request_id(state);
            gboolean sent = body && body_fd >= 0 && bj_send_packet_with_fd(
                state->resource_fd, BJ_RESOURCE_REQUEST, request_id,
                body->data, (guint32)body->len, body_fd);
            if (body_fd >= 0) close(body_fd);
            if (body) g_byte_array_unref(body);
            g_free(original);
            bj_scheme_fail(request, sent ? "POST requires fresh frontend document authority"
                                         : "trusted POST navigation handoff unavailable");
            return;
        }
        char *original = bj_decode_resource_uri(state, scheme_uri);
        char *intent = g_strcmp0(method, "GET") == 0 && original
            ? g_strconcat("redirect requires new frontend document authority: ", original, NULL)
            : g_strdup("Top-level form submission currently supports GET only; POST was not sent");
        bj_send_packet(state->control_fd, 23U, ++state->next_ui_request_id, intent, (guint32)strlen(intent));
        g_free(original);
        g_free(intent);
        bj_scheme_fail(request, "navigation requires frontend authority");
        return;
    }
    char *original =
        bj_decode_resource_uri(
            state,
            scheme_uri);

    if (
        !original ||
        !state->document_id ||
        !state->uri ||
        state->stopping
    ) {
        g_free(original);

        bj_scheme_fail(
            request,
            "invalid WPE private resource request");

        return;
    }

    /* Cross-origin POST bodies must never use the general createBodyStream()
     * path: blob/file resolution can cross the trust boundary or crash pinned
     * WebKit.  BoJangles permits only bounded, inline byte-vector FormData for
     * this case (the EME license-request shape). */
    const char *method = webkit_uri_scheme_request_get_http_method(request);
    char *document_origin = bj_private_origin_token(bj_resource_initiator(state, request));
    char *request_origin = bj_private_origin_token(original);
    gboolean same_origin = document_origin && request_origin &&
                           g_str_equal(document_origin, request_origin);
    g_free(document_origin);
    g_free(request_origin);
    /* The trusted gateway performs credential-free CORS preflight for
     * non-simple cross-origin resources before any actual request. WebCore
     * still owns redirect/final-response policy. WPE has no origin route. */
    gboolean cross_origin_post = g_strcmp0(method, "POST") == 0 && !same_origin;

    if (g_strcmp0(method, "POST") == 0 && !cross_origin_post) {
        gboolean started = bj_start_async_post_resource(
            state, request, original, "OTHER");
        g_free(original);
        if (!started && !state->stopping)
            fputs("WPE_POST_ASYNC_FAIL start\n", stderr);
        return;
    }

    int request_body_fd = -1;

    GByteArray *body =
        bj_resource_request_payload(
            state,
            request,
            original,
            "OTHER",
            cross_origin_post,
            &request_body_fd);

    if (!body) {
        g_free(original);

        bj_scheme_fail(
            request,
            "WPE resource request requires bounded GET/POST metadata and an allowed body shape");

        return;
    }

    guint32 request_id =
        bj_allocate_resource_request_id(state);

    struct PendingResourceRequest *pending =
        g_new0(
            struct PendingResourceRequest,
            1);

    pending->request =
        g_object_ref(request);

    g_hash_table_insert(
        state->pending_resources,
        GUINT_TO_POINTER(request_id),
        pending);

    gboolean sent =
        request_body_fd >= 0
            ? bj_send_packet_with_fd(
                state->resource_fd,
                BJ_RESOURCE_REQUEST,
                request_id,
                body->data,
                (guint32)body->len,
                request_body_fd)
            : bj_send_packet(
                state->resource_fd,
                BJ_RESOURCE_REQUEST,
                request_id,
                body->data,
                (guint32)body->len);

    if (request_body_fd >= 0)
        close(request_body_fd);

    g_byte_array_unref(body);
    g_free(original);

    if (!sent) {
        g_hash_table_remove(
            state->pending_resources,
            GUINT_TO_POINTER(request_id));

        bj_scheme_fail(
            request,
            "trusted WPE resource gateway unavailable");
        state->stopping = TRUE;
        g_main_loop_quit(state->loop);
    }
}

/* Some search pages dispatch the clicked link through an asynchronous script,
 * losing WebKit's transient gesture bit. A single recent physical click/Enter
 * may authorize one GET navigation intent; the frontend still grants the new
 * document authority. A page timer without operator input gains nothing. */
static gboolean backend_navigation_has_operator_gesture(struct BackendState *state,
                                                        WebKitNavigationAction *action)
{
    /* WebKit may retain the gesture bit across multiple scripted opens.
     * Require and consume our own typed physical input even in that case. */
    (void)action;
    gint64 now = g_get_monotonic_time();
    if (!state->last_operator_gesture_us || state->operator_gesture_claimed ||
        now < state->last_operator_gesture_us ||
        now - state->last_operator_gesture_us > 2 * G_TIME_SPAN_SECOND)
        return FALSE;
    state->operator_gesture_claimed = TRUE;
    return TRUE;
}

/* A page may legitimately perform one same-origin GET after loading (for
 * example a consent/challenge transition). The trusted frontend still creates
 * the destination document. New windows and cross-origin targets never inherit
 * this allowance. */
static gboolean backend_once_same_origin_get(struct BackendState *state,
                                              const char *target_uri,
                                              const char *method)
{
    if (state->automatic_same_origin_used || g_strcmp0(method, "GET") != 0)
        return FALSE;
    char *source = bj_private_origin_token(state->uri);
    char *target = bj_private_origin_token(target_uri);
    gboolean allowed = source && target && g_str_equal(source, target);
    g_free(source);
    g_free(target);
    if (allowed)
        state->automatic_same_origin_used = TRUE;
    return allowed;
}

/* New browsing contexts remain distinct from same-tab navigation. Return a
 * typed, user-gesture-gated intent so trusted BoJangles can create another
 * browser window without retiring the page that initiated it. */
static void backend_handoff_new_window(struct BackendState *state,
                                        WebKitNavigationAction *action)
{
    WebKitURIRequest *request = webkit_navigation_action_get_request(action);
    const char *request_uri = webkit_uri_request_get_uri(request);
    char *decoded_uri = bj_decode_resource_uri(state, request_uri);
    const char *uri = decoded_uri ? decoded_uri : request_uri;
    const char *method = webkit_uri_request_get_http_method(request);
    guint16 kind = 23U;
    char *message = NULL;
    if (!backend_navigation_has_operator_gesture(state, action))
        message = g_strdup("New-window navigation requires a user gesture");
    else if (!uri || !(g_str_has_prefix(uri, "https://") || g_str_has_prefix(uri, "http://")))
        message = g_strdup("New-window navigation requires an HTTP(S) destination");
    else if (g_strcmp0(method, "GET") == 0 ||
             ((!method || !method[0]) && strchr(uri, '?'))) {
        kind = BJ_NEW_WINDOW_REQUESTED;
        message = g_strdup(uri);
    } else
        message = g_strdup("Top-level form submission currently supports GET only; POST was not sent");
    if (strlen(message) > BJ_MAX_PACKET ||
        !bj_send_packet(state->control_fd, kind, kind == BJ_NEW_WINDOW_REQUESTED ? ++state->next_ui_request_id : 0, message, (guint32)strlen(message))) {
        state->stopping = TRUE;
        g_main_loop_quit(state->loop);
    }
    g_free(message);
    g_free(decoded_uri);
}

static gboolean backend_navigation_policy(WebKitWebView *view,
                                           WebKitPolicyDecision *decision,
                                           WebKitPolicyDecisionType type,
                                           gpointer user_data)
{
    (void)view;
    struct BackendState *state = user_data;
    if (type == WEBKIT_POLICY_DECISION_TYPE_RESPONSE) {
        WebKitResponsePolicyDecision *response_decision = WEBKIT_RESPONSE_POLICY_DECISION(decision);
        /* WebKit's default ignores unsupported MIME types. That produces an
         * apparently finished, empty browser for PDFs and other static files.
         * Offer only the authorized main response to the trusted frontend;
         * never grant a native download destination or direct network access. */
        if (!webkit_response_policy_decision_is_main_frame_main_resource(response_decision) ||
            webkit_response_policy_decision_is_mime_type_supported(response_decision))
            return FALSE;
        WebKitURIRequest *request = webkit_response_policy_decision_get_request(response_decision);
        WebKitURIResponse *response = webkit_response_policy_decision_get_response(response_decision);
        char *original = request ? bj_decode_resource_uri(state, webkit_uri_request_get_uri(request)) : NULL;
        const char *method = request ? webkit_uri_request_get_http_method(request) : NULL;
        guint status = response ? webkit_uri_response_get_status_code(response) : 0;
        /* Preserve WebKit's existing no-content response semantics. */
        if (status == 204) {
            g_free(original);
            return FALSE;
        }
        webkit_policy_decision_ignore(decision);
        if (original && g_strcmp0(original, state->uri) == 0 &&
            g_strcmp0(method, "GET") == 0 && status >= 200 && status < 300 && status != 204) {
            const char *fields[] = { original, webkit_uri_response_get_suggested_filename(response) };
            GByteArray *offer = bj_pack_strings(fields, 2);
            if (offer->len <= BJ_MAX_PACKET && !state->stopping)
                bj_send_packet(state->resource_fd, BJ_DOWNLOAD_OFFER, 0, offer->data, (guint32)offer->len);
            g_byte_array_unref(offer);
        } else {
            const char *message = "Unsupported document response cannot be displayed or downloaded";
            bj_send_packet(state->control_fd, 23U, ++state->next_ui_request_id, message, (guint32)strlen(message));
        }
        g_free(original);
        return TRUE;
    }
    if (type != WEBKIT_POLICY_DECISION_TYPE_NEW_WINDOW_ACTION &&
        type != WEBKIT_POLICY_DECISION_TYPE_NAVIGATION_ACTION)
        return FALSE;

    WebKitNavigationAction *action = webkit_navigation_policy_decision_get_navigation_action(
        WEBKIT_NAVIGATION_POLICY_DECISION(decision));

    if (type == WEBKIT_POLICY_DECISION_TYPE_NEW_WINDOW_ACTION) {
        webkit_policy_decision_ignore(decision);
        backend_handoff_new_window(state, action);
        return TRUE;
    }

    if (state->trusted_document_load) {
        state->trusted_document_load = FALSE;
        return FALSE;
    }

    WebKitURIRequest *request = webkit_navigation_action_get_request(action);
    const char *request_uri = webkit_uri_request_get_uri(request);
    char *decoded_uri = bj_decode_resource_uri(state, request_uri);
    const char *uri = decoded_uri ? decoded_uri : request_uri;
    const char *method = webkit_uri_request_get_http_method(request);
    gboolean user_gesture = webkit_navigation_action_is_user_gesture(action);
    gboolean operator_gesture = FALSE;
    gboolean automatic_same_origin = FALSE;
    gboolean automatic_cross_origin = FALSE;

    if (!webkit_navigation_action_is_main_frame(action)) {
        /* WebKit uses inert and in-memory documents for editor/canvas
         * subframes. Preserve WebKit frame/SOP semantics for those documents;
         * HTTP(S) child resources still pass through the resource gateway. */
        if (uri && (g_str_has_prefix(uri, "https://") ||
                    g_str_has_prefix(uri, "http://") ||
                    g_str_has_prefix(uri, "data:") ||
                    g_str_has_prefix(uri, "blob:") ||
                    g_str_equal(uri, "about:blank") ||
                    g_str_equal(uri, "about:srcdoc"))) {
            bj_refresh_subframe_context(state);
            char *frame_origin = bj_private_origin_token(uri);
            if (frame_origin)
                g_hash_table_add(state->subframe_origins, frame_origin);
            webkit_policy_decision_use(decision);
        } else {
            webkit_policy_decision_ignore(decision);
            const char *message = "Subframe navigation requires HTTP(S) or an inert local document";
            bj_send_packet(state->control_fd, 23U, ++state->next_ui_request_id, message, (guint32)strlen(message));
        }
        g_free(decoded_uri);
        return TRUE;
    }

    if (uri && g_str_has_prefix(uri, "magnet:?")) {
        /* A magnet URI is never executed by WebKit or passed to a generic OS
         * protocol handler. Surface the untrusted target to the trusted
         * frontend, which requires recent physical user intent and an explicit
         * operator confirmation before invoking the fixed torrent queue. */
        webkit_policy_decision_ignore(decision);
        char *message = g_strconcat(
            "magnet link requires frontend decision: ", uri, NULL);
        if (strlen(message) <= BJ_MAX_PACKET)
            bj_send_packet(state->control_fd, 23U, ++state->next_ui_request_id, message, (guint32)strlen(message));
        g_free(message);
        g_free(decoded_uri);
        return TRUE;
    }

    if (!uri || !(g_str_has_prefix(uri, "https://") || g_str_has_prefix(uri, "http://"))) {
        webkit_policy_decision_ignore(decision);
        const char *message = "Top-level navigation requires an HTTP(S) destination";
        bj_send_packet(state->control_fd, 23U, ++state->next_ui_request_id, message, (guint32)strlen(message));
        g_free(decoded_uri);
        return TRUE;
    }

    if (webkit_navigation_action_should_download(action)) {
        if (!user_gesture) {
            webkit_policy_decision_ignore(decision);
            const char *message = "Download requires a user gesture";
            bj_send_packet(state->control_fd, 23U, ++state->next_ui_request_id, message, (guint32)strlen(message));
            g_free(decoded_uri);
            return TRUE;
        }
        webkit_policy_decision_download(decision);
        g_free(decoded_uri);
        return TRUE;
    }

    if (g_strcmp0(method, "POST") != 0) {
        operator_gesture = backend_navigation_has_operator_gesture(state, action);
        if (!operator_gesture) {
            automatic_same_origin = backend_once_same_origin_get(state, uri, method);
            if (!automatic_same_origin && g_strcmp0(method, "GET") == 0 &&
                !state->automatic_cross_origin_used) {
                char *source = bj_private_origin_token(state->uri);
                char *target = bj_private_origin_token(uri);
                automatic_cross_origin = source && target && !g_str_equal(source, target);
                g_free(source);
                g_free(target);
                if (automatic_cross_origin)
                    state->automatic_cross_origin_used = TRUE;
            }
        }
    }
    if (automatic_cross_origin) {
        webkit_policy_decision_ignore(decision);
        const char *fields[] = {state->document_id, uri, "cross-origin"};
        GByteArray *intent = bj_pack_strings(fields, 3);
        if (intent->len <= 8704U)
            bj_send_packet(state->control_fd, BJ_NAVIGATION_INTENT, ++state->next_ui_request_id, intent->data, intent->len);
        g_byte_array_unref(intent);
        g_free(decoded_uri);
        return TRUE;
    }
    if (g_strcmp0(method, "POST") != 0 &&
        !operator_gesture && !automatic_same_origin) {
        webkit_policy_decision_ignore(decision);
        const char *message = "Top-level navigation requires a user gesture";
        bj_send_packet(state->control_fd, 23U, ++state->next_ui_request_id, message, (guint32)strlen(message));
        g_free(decoded_uri);
        return TRUE;
    }

    if (request_uri && g_str_has_prefix(request_uri, "bojangles-resource://")) {
        if (state->pending_main_navigation_uri) {
            webkit_policy_decision_ignore(decision);
            const char *message = "Top-level navigation already pending; request was not sent";
            bj_send_packet(state->control_fd, 23U, ++state->next_ui_request_id, message, (guint32)strlen(message));
            g_free(decoded_uri);
            return TRUE;
        }
        state->pending_main_navigation_uri = g_strdup(request_uri);
        g_free(decoded_uri);
        webkit_policy_decision_use(decision);
        return TRUE;
    }

    if (g_strcmp0(method, "POST") == 0) {
        char *private_uri = bj_private_navigation_uri(state, uri);
        if (!private_uri || state->pending_main_navigation_uri) {
            g_free(private_uri);
            webkit_policy_decision_ignore(decision);
            const char *message = "Top-level POST crossed origin or another navigation is pending; POST was not sent";
            bj_send_packet(state->control_fd, 23U, ++state->next_ui_request_id, message, (guint32)strlen(message));
            g_free(decoded_uri);
            return TRUE;
        }

        state->pending_main_navigation_uri = g_strdup(private_uri);
        webkit_uri_request_set_uri(request, private_uri);
        g_free(private_uri);
        g_free(decoded_uri);
        webkit_policy_decision_use(decision);
        return TRUE;
    }

    webkit_policy_decision_ignore(decision);
    if (g_strcmp0(method, "GET") == 0) {
        const char *fields[] = {state->document_id, uri, automatic_same_origin ? "automatic" : "operator"};
        GByteArray *intent = bj_pack_strings(fields, 3);
        if (intent->len <= 8704U)
            bj_send_packet(state->control_fd, BJ_NAVIGATION_INTENT, ++state->next_ui_request_id, intent->data, intent->len);
        g_byte_array_unref(intent);
        g_free(decoded_uri);
        return TRUE;
    }

    const char *message = "Top-level navigation method is unsupported; request was not sent";
    bj_send_packet(state->control_fd, 23U, ++state->next_ui_request_id, message, (guint32)strlen(message));
    g_free(decoded_uri);
    return TRUE;
}

static WebKitWebView *backend_create_view(WebKitWebView *view,
                                          WebKitNavigationAction *action,
                                          gpointer user_data)
{
    (void)view;
    /* Scripted window.open uses create; target=_blank forms use decide-policy.
     * Neither may create a view carrying the old document's authority. */
    backend_handoff_new_window(user_data, action);
    return NULL;
}


static void backend_web_process_terminated(WebKitWebView *view,
                                           WebKitWebProcessTerminationReason reason,
                                           gpointer user_data)
{
    (void)view;
    struct BackendState *state = user_data;
    fprintf(stderr, "WPE_STAGE4B_FAIL web-process-terminated reason=%d\n", (int)reason);
    state->stopping = TRUE;
    g_main_loop_quit(state->loop);
}


#define BJ_STATE_MAX_FIELDS 64U
#define BJ_STATE_MAX_BYTES 65536U

struct BackendStateRequest {
    struct BackendState *state;
    guint32 request_id;
    char *document_id;
    char *uri;
    gboolean restore;
};

static gboolean bj_state_fields_valid(char **fields, size_t count, size_t offset)
{
    if (count < offset + 3)
        return FALSE;
    for (size_t i = 0; i < count; ++i)
        if (!g_utf8_validate(fields[i], -1, NULL)) return FALSE;
    for (size_t i = offset; i < offset + 3; ++i) {
        char *end = NULL;
        errno = 0;
        long value = strtol(fields[i], &end, 10);
        if (errno || end == fields[i] || *end || value < 0 || value > INT_MAX)
            return FALSE;
    }
    unsigned long forms = strtoul(fields[offset + 2], NULL, 10);
    if (forms > BJ_STATE_MAX_FIELDS || count != offset + 3 + forms * 2)
        return FALSE;
    for (size_t i = offset + 3; i < count; i += 2) {
        if (!*fields[i] || strlen(fields[i]) > 1024 || strlen(fields[i + 1]) > 4096)
            return FALSE;
        for (size_t previous = offset + 3; previous < i; previous += 2)
            if (!strcmp(fields[previous], fields[i])) return FALSE;
    }
    return TRUE;
}

static void backend_state_ready(GObject *source, GAsyncResult *result, gpointer data)
{
    struct BackendStateRequest *request = data;
    struct BackendState *state = request->state;
    GError *error = NULL;
    JSCValue *value = request->restore
        ? webkit_web_view_call_async_javascript_function_finish(WEBKIT_WEB_VIEW(source), result, &error)
        : webkit_web_view_evaluate_javascript_finish(WEBKIT_WEB_VIEW(source), result, &error);
    gboolean current = !state->stopping &&
        g_strcmp0(request->document_id, state->document_id) == 0 &&
        g_strcmp0(request->uri, state->uri) == 0;
    gboolean sent = FALSE;
    if (request->restore) {
        char answer = current && !error && value && jsc_value_is_boolean(value) &&
                      jsc_value_to_boolean(value) ? '1' : '0';
        sent = bj_send_packet(state->control_fd, BJ_RESTORE_RESULT, request->request_id, &answer, 1);
    } else if (current && !error && value && jsc_value_is_string(value)) {
        GBytes *bytes = jsc_value_to_string_as_bytes(value);
        if (bytes) {
            gsize size = 0;
            const char *raw = g_bytes_get_data(bytes, &size);
            if (size && size <= BJ_STATE_MAX_BYTES) {
                char *copy = g_memdup2(raw, size);
                char *fields[3 + 2 * BJ_STATE_MAX_FIELDS];
                size_t count = bj_split_fields(copy, size, fields, G_N_ELEMENTS(fields));
                if (bj_state_fields_valid(fields, count, 0)) {
                    const char *identity[] = {request->document_id, request->uri};
                    GByteArray *body = bj_pack_strings(identity, 2);
                    g_byte_array_append(body, (const guint8 *)raw, size);
                    if (body->len <= BJ_STATE_MAX_BYTES)
                        sent = bj_send_packet(state->control_fd, BJ_SNAPSHOT_RESULT,
                                              request->request_id, body->data, body->len);
                    g_byte_array_unref(body);
                }
                g_free(copy);
            }
            g_bytes_unref(bytes);
        }
    }
    if (!sent && !state->stopping) {
        const char *message = "bounded document state unavailable";
        bj_send_packet(state->control_fd, BJ_ERROR, request->request_id, message, strlen(message));
    }
    if (value) g_object_unref(value);
    if (error) g_error_free(error);
    g_free(request->document_id);
    g_free(request->uri);
    g_free(request);
}

static struct BackendStateRequest *backend_state_request(struct BackendState *state,
                                                         guint32 request_id,
                                                         gboolean restore)
{
    struct BackendStateRequest *request = g_new0(struct BackendStateRequest, 1);
    request->state = state;
    request->request_id = request_id;
    request->document_id = g_strdup(state->document_id);
    request->uri = g_strdup(state->uri);
    request->restore = restore;
    return request;
}

#define BJ_CREDENTIAL_MAX_FIELD 4096U

struct BackendCredentialRequest {
    struct BackendState *state;
    guint32 request_id;
    char *document_id;
};

static void backend_credential_fill_ready(GObject *source, GAsyncResult *result, gpointer data)
{
    struct BackendCredentialRequest *request = data;
    GError *error = NULL;
    JSCValue *value = webkit_web_view_call_async_javascript_function_finish(
        WEBKIT_WEB_VIEW(source), result, &error);
    gboolean current = !request->state->stopping &&
        request->state->document_id &&
        g_strcmp0(request->document_id, request->state->document_id) == 0;
    char answer = current && !error && value && jsc_value_is_boolean(value) &&
                  jsc_value_to_boolean(value) ? '1' : '0';
    bj_send_packet(request->state->control_fd, BJ_CREDENTIAL_FILL_RESULT,
                   request->request_id, &answer, 1);
    if (value) g_object_unref(value);
    if (error) g_error_free(error);
    g_free(request->document_id);
    g_free(request);
}

static gboolean backend_fill_credentials(struct BackendState *state, guint32 request_id,
                                         char *payload, guint32 length)
{
    char *fields[4];
    size_t count = bj_split_fields(payload, length, fields, G_N_ELEMENTS(fields));
    if (count != 4U || !state->document_id || strcmp(fields[0], state->document_id) ||
        !g_str_has_prefix(fields[1], "https://") ||
        !*fields[2] || !*fields[3] ||
        strlen(fields[1]) > 2048U || strlen(fields[2]) > 1024U ||
        strlen(fields[3]) > BJ_CREDENTIAL_MAX_FIELD)
        return FALSE;
    for (size_t i = 0; i < count; ++i)
        if (!g_utf8_validate(fields[i], -1, NULL)) return FALSE;

    GVariantBuilder arguments;
    g_variant_builder_init(&arguments, G_VARIANT_TYPE_VARDICT);
    g_variant_builder_add(&arguments, "{sv}", "origin", g_variant_new_string(fields[1]));
    g_variant_builder_add(&arguments, "{sv}", "username", g_variant_new_string(fields[2]));
    g_variant_builder_add(&arguments, "{sv}", "password", g_variant_new_string(fields[3]));
    GVariant *args = g_variant_ref_sink(g_variant_builder_end(&arguments));

    const char *script =
        "if(location.origin!==origin)return false;"
        "const visible=e=>{const r=e.getBoundingClientRect(),s=getComputedStyle(e);"
        "return r.width>0&&r.height>0&&s.display!=='none'&&s.visibility!=='hidden';};"
        "const usable=e=>!e.disabled&&!e.readOnly&&visible(e);"
        "let passwords=[...document.querySelectorAll('input[type=password]')].filter(usable);"
        "const current=passwords.filter(e=>(e.autocomplete||'').toLowerCase()==='current-password');"
        "if(current.length===1)passwords=current;"
        "if(passwords.length!==1)return false;"
        "const p=passwords[0];if(p.value)return false;"
        "const scope=p.form||document;"
        "let users=[...scope.querySelectorAll('input[autocomplete=username]')].filter(e=>e!==p&&usable(e)&&!e.value);"
        "if(users.length!==1){"
        "users=[...scope.querySelectorAll('input[type=email],input[type=text]')].filter(e=>e!==p&&usable(e)&&!e.value);"
        "users=[...new Set(users)];}"
        "if(users.length!==1)return false;"
        "const nativeSet=(e,v)=>{"
        "const proto=Object.getPrototypeOf(e);"
        "const d=Object.getOwnPropertyDescriptor(proto,'value')||"
        "Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value');"
        "if(!d||typeof d.set!=='function')return false;"
        "e.focus();d.set.call(e,v);"
        "e.dispatchEvent(new Event('input',{bubbles:true}));"
        "e.dispatchEvent(new Event('change',{bubbles:true}));return true;};"
        "if(!nativeSet(users[0],username)||!nativeSet(p,password))return false;"
        "p.focus();return true;";

    struct BackendCredentialRequest *request = g_new0(struct BackendCredentialRequest, 1);
    request->state = state;
    request->request_id = request_id;
    request->document_id = g_strdup(state->document_id);
    webkit_web_view_call_async_javascript_function(
        state->view, script, -1, args, "bojangles-credential-fill", NULL,
        state->operations, backend_credential_fill_ready, request);
    g_variant_unref(args);
    return TRUE;
}

struct BackendTranslationRequest {
    struct BackendState *state;
    guint32 request_id;
    char *document_id;
    char *uri;
};

static void backend_translation_ready(GObject *source, GAsyncResult *result, gpointer data)
{
    struct BackendTranslationRequest *request = data;
    GError *error = NULL;
    WebKitUserMessage *reply = webkit_web_view_send_message_to_page_finish(WEBKIT_WEB_VIEW(source), result, &error);
    const char *answer = "{\"error\":\"Page changed or translation extension unavailable\"}";
    GVariant *parameters = reply ? webkit_user_message_get_parameters(reply) : NULL;
    if (!error && g_strcmp0(request->document_id, request->state->document_id) == 0 &&
        g_strcmp0(request->uri, request->state->uri) == 0 && reply &&
        g_str_equal(webkit_user_message_get_name(reply), "bojangles-translation-result") &&
        parameters && g_variant_is_of_type(parameters, G_VARIANT_TYPE_STRING)) {
        const char *value = g_variant_get_string(parameters, NULL);
        if (strlen(value) <= 196608U) answer = value;
    }
    if (!request->state->stopping) {
        const char *fields[] = {request->document_id, answer};
        GByteArray *payload = bj_pack_strings(fields, 2);
        bj_send_packet(request->state->control_fd, BJ_TRANSLATION_RESULT, request->request_id, payload->data, payload->len);
        g_byte_array_unref(payload);
    }
    g_clear_object(&reply);
    g_clear_error(&error);
    g_free(request->document_id); g_free(request->uri); g_free(request);
}

static gboolean backend_translation(struct BackendState *state, guint16 kind, char *payload,
                                     guint32 length, guint32 request_id)
{
    char *fields[2];
    if (length > 197000U || bj_split_fields(payload, length, fields, 2) != 2U ||
        !state->document_id || strcmp(fields[0], state->document_id) ||
        !g_utf8_validate(fields[1], -1, NULL)) return FALSE;
    const char *name = kind == BJ_TRANSLATION_EXTRACT ? "bojangles-translation-extract" :
                       kind == BJ_TRANSLATION_APPLY ? "bojangles-translation-apply" : "bojangles-translation-restore";
    struct BackendTranslationRequest *request = g_new0(struct BackendTranslationRequest, 1);
    request->state = state; request->request_id = request_id;
    request->document_id = g_strdup(state->document_id); request->uri = g_strdup(state->uri);
    WebKitUserMessage *message = webkit_user_message_new(name, g_variant_new_string(fields[1]));
    webkit_web_view_send_message_to_page(state->view, message, state->operations, backend_translation_ready, request);
    return TRUE;
}

#define BJ_CLIPBOARD_MAX_BYTES 65536U

struct BackendClipboardRequest {
    struct BackendState *state;
    guint32 request_id;
    char *document_id;
    char *uri;
    WPEClipboard *clipboard;
    gulong changed_handler;
    guint timeout_source;
    gboolean rich;
    gboolean cut;
};

static gboolean backend_clipboard_request_current(struct BackendClipboardRequest *request)
{
    return request && request->state && !request->state->stopping &&
        g_strcmp0(request->document_id, request->state->document_id) == 0 &&
        g_strcmp0(request->uri, request->state->uri) == 0;
}

static void backend_clipboard_request_free(struct BackendClipboardRequest *request)
{
    if (!request)
        return;
    if (request->changed_handler && request->clipboard)
        g_signal_handler_disconnect(request->clipboard, request->changed_handler);
    if (request->timeout_source)
        g_source_remove(request->timeout_source);
    g_clear_object(&request->clipboard);
    g_free(request->document_id);
    g_free(request->uri);
    g_free(request);
}

static gboolean backend_clipboard_send_copy(struct BackendClipboardRequest *request,
                                            const char *failure)
{
    struct BackendState *state = request->state;
    gboolean sent = FALSE;

    if (!backend_clipboard_request_current(request)) {
        backend_clipboard_request_free(request);
        return G_SOURCE_REMOVE;
    }

    if (!failure && request->rich) {
        gsize size = 0, html_size = 0;
        char *text = wpe_clipboard_read_text(request->clipboard, "text/plain;charset=utf-8", &size);
        if (!text) text = wpe_clipboard_read_text(request->clipboard, "text/plain", &size);
        char *html = wpe_clipboard_read_text(request->clipboard, "text/html", &html_size);
        if (size <= BJ_CLIPBOARD_MAX_BYTES && html_size <= 524288U &&
            (!text || (!memchr(text, '\0', size) && g_utf8_validate(text, size, NULL))) &&
            (!html || (!memchr(html, '\0', html_size) && g_utf8_validate(html, html_size, NULL)))) {
            char *plain = text ? g_strndup(text, size) : g_strdup("");
            char *markup = html ? g_strndup(html, html_size) : g_strdup("");
            const char *fields[] = {plain, markup};
            GByteArray *answer = bj_pack_strings(fields, 2);
            sent = bj_send_packet(state->control_fd, BJ_CLIPBOARD_COPY_RICH_RESULT,
                                 request->request_id, answer->data, answer->len);
            g_byte_array_unref(answer); g_free(plain); g_free(markup);
        } else failure = "page selection exceeds trusted clipboard bound";
        g_free(text); g_free(html);
    } else if (!failure) {
        gsize size = 0;
        char *text = wpe_clipboard_read_text(
            request->clipboard, "text/plain;charset=utf-8", &size);
        if (!text)
            text = wpe_clipboard_read_text(request->clipboard, "text/plain", &size);
        if (!text) {
            sent = bj_send_packet(
                state->control_fd, BJ_CLIPBOARD_COPY_RESULT,
                request->request_id, NULL, 0);
        } else if (size <= BJ_CLIPBOARD_MAX_BYTES &&
                   !memchr(text, '\0', size) &&
                   g_utf8_validate(text, size, NULL)) {
            sent = bj_send_packet(
                state->control_fd, BJ_CLIPBOARD_COPY_RESULT,
                request->request_id, text, (guint32)size);
        } else {
            failure = "page selection exceeds trusted clipboard bound";
        }
        g_free(text);
    }

    if (!sent && !state->stopping) {
        const char *message = failure ? failure : "page selection unavailable";
        bj_send_packet(
            state->control_fd, BJ_ERROR, request->request_id,
            message, (guint32)strlen(message));
    }

    backend_clipboard_request_free(request);
    return G_SOURCE_REMOVE;
}

static void backend_clipboard_changed(GObject *object, GParamSpec *property, gpointer data)
{
    (void)object;
    (void)property;
    backend_clipboard_send_copy(data, NULL);
}

static gboolean backend_clipboard_copy_timeout(gpointer data)
{
    struct BackendClipboardRequest *request = data;
    request->timeout_source = 0;
    return backend_clipboard_send_copy(
        request, "copy command did not produce clipboard data");
}

static void backend_clipboard_can_copy_ready(GObject *source,
                                             GAsyncResult *result,
                                             gpointer data)
{
    struct BackendClipboardRequest *request = data;
    GError *error = NULL;
    gboolean enabled = webkit_web_view_can_execute_editing_command_finish(
        WEBKIT_WEB_VIEW(source), result, &error);

    if (!backend_clipboard_request_current(request)) {
        if (error)
            g_error_free(error);
        backend_clipboard_request_free(request);
        return;
    }

    if (error || !enabled) {
        if (error)
            g_error_free(error);
        if (!request->state->stopping)
            bj_send_packet(
                request->state->control_fd, request->rich ? BJ_CLIPBOARD_COPY_RICH_RESULT : BJ_CLIPBOARD_COPY_RESULT,
                request->request_id, request->rich ? "\0\0" : NULL, request->rich ? 2 : 0);
        backend_clipboard_request_free(request);
        return;
    }

    request->changed_handler = g_signal_connect(
        request->clipboard, "notify::change-count",
        G_CALLBACK(backend_clipboard_changed), request);
    request->timeout_source = g_timeout_add(
        1000, backend_clipboard_copy_timeout, request);
    webkit_web_view_execute_editing_command(
        WEBKIT_WEB_VIEW(source), request->cut ? WEBKIT_EDITING_COMMAND_CUT : WEBKIT_EDITING_COMMAND_COPY);
}

static WPEClipboard *backend_clipboard_for_view(WebKitWebView *view)
{
    WPEView *wpe_view = webkit_web_view_get_wpe_view(view);
    WPEDisplay *display = wpe_view ? wpe_view_get_display(wpe_view) : NULL;
    return display ? wpe_display_get_clipboard(display) : NULL;
}

static gboolean backend_clipboard_begin_copy(struct BackendState *state,
                                             guint32 request_id, gboolean rich, gboolean cut)
{
    WPEClipboard *clipboard = backend_clipboard_for_view(state->view);
    if (!clipboard)
        return FALSE;

    struct BackendClipboardRequest *request =
        g_new0(struct BackendClipboardRequest, 1);
    request->state = state;
    request->request_id = request_id;
    request->document_id = g_strdup(state->document_id);
    request->uri = g_strdup(state->uri);
    request->clipboard = g_object_ref(clipboard);
    request->rich = rich;
    request->cut = cut;

    webkit_web_view_can_execute_editing_command(
        state->view, cut ? WEBKIT_EDITING_COMMAND_CUT : WEBKIT_EDITING_COMMAND_COPY,
        state->operations, backend_clipboard_can_copy_ready, request);
    return TRUE;
}

struct BackendPrintRequest {
    struct BackendState *state;
    guint32 request_id;
    int output_fd;
    char *document_id;
    guint16 result_kind;
};

static void backend_export_complete(struct BackendPrintRequest *request, GBytes *output)
{
    struct BackendState *state = request->state;
    gsize size = 0;
    const guint8 *bytes = output ? g_bytes_get_data(output, &size) : NULL;
    gboolean valid = !state->stopping && state->document_id &&
        !strcmp(state->document_id, request->document_id) &&
        bytes && size >= 8 && size <= 64U * 1024U * 1024U;
    size_t written = 0;
    while (valid && written < size) {
        ssize_t count = pwrite(request->output_fd, bytes + written, size - written, (off_t)written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { valid = FALSE; break; }
        written += (size_t)count;
    }
    if (valid && fcntl(request->output_fd, F_ADD_SEALS,
                        F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE) < 0)
        valid = FALSE;
    char length[32];
    g_snprintf(length, sizeof(length), "%zu", valid ? (size_t)size : 0);
    const char *fields[] = {request->document_id, length};
    GByteArray *payload = bj_pack_strings(fields, G_N_ELEMENTS(fields));
    if (!state->stopping)
        bj_send_packet(state->control_fd, request->result_kind, request->request_id, payload->data, payload->len);
    g_byte_array_unref(payload);
    if (output) g_bytes_unref(output);
    close(request->output_fd);
    g_free(request->document_id);
    state->print_active = FALSE;
    g_free(request);
}


static void backend_print_pdf_ready(GObject *object, GAsyncResult *result, gpointer data)
{
    GError *error = NULL;
    GBytes *output = webkit_web_view_print_to_pdf_finish(WEBKIT_WEB_VIEW(object), result, &error);
    if (output) {
        gsize size = 0;
        const guint8 *bytes = g_bytes_get_data(output, &size);
        if (size < 8 || memcmp(bytes, "%PDF-", 5)) {
            g_bytes_unref(output);
            output = NULL;
        }
    }
    g_clear_error(&error);
    backend_export_complete(data, output);
}

static void backend_page_image_ready(GObject *object, GAsyncResult *result, gpointer data)
{
    GError *error = NULL;
    WebKitImage *image = webkit_web_view_get_snapshot_finish(WEBKIT_WEB_VIEW(object), result, &error);
    GBytes *output = NULL;
    if (image) {
        GBytes *pixels = webkit_image_as_bytes(image);
        gsize size = 0;
        const guint8 *bytes = g_bytes_get_data(pixels, &size);
        int width = webkit_image_get_width(image), height = webkit_image_get_height(image);
        guint stride = webkit_image_get_stride(image);
        if (width > 0 && height > 0 && stride >= (guint64)width * 4 &&
            size == (guint64)stride * height && size <= 64U * 1024U * 1024U - 128) {
            char header[128];
            int n = g_snprintf(header, sizeof(header), "%d %d %u\n", width, height, stride);
            GByteArray *buffer = g_byte_array_sized_new(size + n);
            g_byte_array_append(buffer, (guint8 *)header, n);
            g_byte_array_append(buffer, bytes, size);
            output = g_byte_array_free_to_bytes(buffer);
        }
        g_object_unref(image);
    }
    g_clear_error(&error);
    backend_export_complete(data, output);
}

static void backend_page_archive_ready(GObject *object, GAsyncResult *result, gpointer data)
{
    GError *error = NULL;
    GInputStream *stream = webkit_web_view_save_finish(WEBKIT_WEB_VIEW(object), result, &error);
    GBytes *output = NULL;
    if (stream) {
        /* WebKit returns a memory input stream; never fetch missing resources here. */
        GByteArray *buffer = g_byte_array_new();
        guint8 chunk[65536];
        gssize count;
        while ((count = g_input_stream_read(stream, chunk, sizeof(chunk), NULL, &error)) > 0) {
            if (buffer->len > 64U * 1024U * 1024U - count) break;
            g_byte_array_append(buffer, chunk, count);
        }
        if (count == 0 && !error) output = g_byte_array_free_to_bytes(buffer);
        else g_byte_array_unref(buffer);
        g_object_unref(stream);
    }
    g_clear_error(&error);
    backend_export_complete(data, output);
}

struct BackendImageRequest {
    struct BackendState *state;
    guint32 request_id;
    int output_fd;
    char *document_id;
};

static void backend_image_ready(GObject *object, GAsyncResult *result, gpointer data)
{
    struct BackendImageRequest *request = data;
    struct BackendState *state = request->state;
    GError *error = NULL;
    gsize size = 0;
    guint8 *bytes = webkit_web_resource_get_data_finish(WEBKIT_WEB_RESOURCE(object), result, &size, &error);
    WebKitURIResponse *response = webkit_web_resource_get_response(WEBKIT_WEB_RESOURCE(object));
    gboolean valid = response && webkit_uri_response_get_status_code(response) < 400 && !state->stopping && state->document_id &&
        !strcmp(state->document_id, request->document_id) && bytes &&
        size >= 8 && size <= 64U * 1024U * 1024U;
    size_t written = 0;
    while (valid && written < size) {
        ssize_t count = pwrite(request->output_fd, bytes + written, size - written, (off_t)written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { valid = FALSE; break; }
        written += (size_t)count;
    }
    if (valid && fcntl(request->output_fd, F_ADD_SEALS,
                        F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE) < 0)
        valid = FALSE;
    char length[32];
    g_snprintf(length, sizeof(length), "%zu", valid ? (size_t)size : 0);
    const char *fields[] = {request->document_id, length};
    GByteArray *payload = bj_pack_strings(fields, 2);
    if (!state->stopping)
        bj_send_packet(state->control_fd, BJ_IMAGE_DATA_RESULT, request->request_id, payload->data, payload->len);
    g_byte_array_unref(payload);
    g_clear_error(&error);
    g_free(bytes);
    close(request->output_fd);
    g_free(request->document_id);
    g_free(request);
}

static gboolean backend_image_data(struct BackendState *state, char *payload,
                                   guint32 length, guint32 request_id, int output_fd)
{
    char *fields[2];
    struct stat info;
    if (output_fd < 0 || bj_split_fields(payload, length, fields, 2) != 2 ||
        !state->document_id || strcmp(fields[0], state->document_id) ||
        !state->spelling_document_id || strcmp(fields[0], state->spelling_document_id) ||
        !state->context_image || g_ascii_strtoull(fields[1], NULL, 10) != state->spelling_menu_id ||
        g_get_monotonic_time() - state->spelling_menu_us > 120 * G_TIME_SPAN_SECOND ||
        fstat(output_fd, &info) < 0 || !S_ISREG(info.st_mode) || info.st_size != 0 ||
        fcntl(output_fd, F_GET_SEALS) != 0)
        return FALSE;
    struct BackendImageRequest *request = g_new0(struct BackendImageRequest, 1);
    request->state = state; request->request_id = request_id;
    request->output_fd = output_fd; request->document_id = g_strdup(fields[0]);
    webkit_web_resource_get_data(state->context_image, state->operations, backend_image_ready, request);
    return TRUE;
}

static gboolean backend_print_pdf(struct BackendState *state, char *payload,
                                  guint32 length, guint32 request_id, int output_fd)
{
    char *fields[2];
    struct stat info;
    if (state->print_active || output_fd < 0 ||
        bj_split_fields(payload, length, fields, 2) != 2U ||
        !state->document_id || strcmp(fields[0], state->document_id) ||
        (strcmp(fields[1], "letter") && strcmp(fields[1], "a4")) ||
        fstat(output_fd, &info) < 0 || !S_ISREG(info.st_mode) || info.st_size != 0 ||
        fcntl(output_fd, F_GET_SEALS) != 0)
        return FALSE;
    struct BackendPrintRequest *request = g_new0(struct BackendPrintRequest, 1);
    request->state = state; request->request_id = request_id;
    request->output_fd = output_fd; request->document_id = g_strdup(fields[0]);
    request->result_kind = BJ_PRINT_PDF_RESULT;
    state->print_active = TRUE;
    webkit_web_view_print_to_pdf(state->view, !strcmp(fields[1], "a4"), NULL,
                                backend_print_pdf_ready, request);
    return TRUE;
}

static gboolean backend_page_export(struct BackendState *state, char *payload,
                                    guint32 length, guint32 request_id, int output_fd)
{
    char *fields[2];
    struct stat info;
    if (state->print_active || output_fd < 0 ||
        bj_split_fields(payload, length, fields, 2) != 2 ||
        !state->document_id || strcmp(fields[0], state->document_id) ||
        (strcmp(fields[1], "png") && strcmp(fields[1], "mhtml")) ||
        fstat(output_fd, &info) < 0 || !S_ISREG(info.st_mode) || info.st_size != 0 ||
        fcntl(output_fd, F_GET_SEALS) != 0) return FALSE;
    struct BackendPrintRequest *request = g_new0(struct BackendPrintRequest, 1);
    request->state = state; request->request_id = request_id;
    request->output_fd = output_fd; request->document_id = g_strdup(fields[0]);
    request->result_kind = BJ_PAGE_EXPORT_RESULT;
    state->print_active = TRUE;
    if (!strcmp(fields[1], "png"))
        webkit_web_view_get_snapshot(state->view, WEBKIT_SNAPSHOT_REGION_FULL_DOCUMENT,
            WEBKIT_SNAPSHOT_OPTIONS_NONE, state->operations, backend_page_image_ready, request);
    else
        webkit_web_view_save(state->view, WEBKIT_SAVE_MODE_MHTML, state->operations,
            backend_page_archive_ready, request);
    return TRUE;
}

static gboolean backend_clipboard_paste_png(struct BackendState *state,
                                            char *payload, guint32 length,
                                            int image_fd)
{
    char *fields[2];
    if (image_fd < 0 || bj_split_fields(payload, length, fields, 2) != 2U ||
        !state->document_id || strcmp(fields[0], state->document_id))
        return FALSE;
    errno = 0;
    char *end = NULL;
    unsigned long long size = strtoull(fields[1], &end, 10);
    int seals = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;
    int actual = fcntl(image_fd, F_GET_SEALS);
    struct stat info;
    if (errno || !*fields[1] || !end || *end || size < 24 || size > 16ULL * 1024 * 1024 ||
        actual < 0 || (actual & seals) != seals || fstat(image_fd, &info) ||
        info.st_size < 0 || (unsigned long long)info.st_size != size)
        return FALSE;
    guint8 *image = g_malloc((gsize)size);
    size_t offset = 0;
    while (offset < size) {
        ssize_t got = pread(image_fd, image + offset, (size_t)size - offset, (off_t)offset);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0) { g_free(image); return FALSE; }
        offset += (size_t)got;
    }
    guint32 width = bj_get_u32(image + 16), height = bj_get_u32(image + 20);
    if (memcmp(image, "\211PNG\r\n\032\n", 8) || memcmp(image + 12, "IHDR", 4) ||
        !width || !height || (guint64)width * height > 40000000ULL) {
        g_free(image);
        return FALSE;
    }
    WPEClipboard *clipboard = backend_clipboard_for_view(state->view);
    if (!clipboard) { g_free(image); return FALSE; }
    GBytes *bytes = g_bytes_new_take(image, (gsize)size);
    WPEClipboardContent *content = wpe_clipboard_content_new();
    wpe_clipboard_content_set_bytes(content, "image/png", bytes);
    wpe_clipboard_set_content(clipboard, content);
    wpe_clipboard_content_unref(content);
    g_bytes_unref(bytes);
    webkit_web_view_execute_editing_command(state->view, WEBKIT_EDITING_COMMAND_PASTE);
    return TRUE;
}

static gboolean backend_clipboard_paste_text(struct BackendState *state,
                                             const char *payload,
                                             guint32 length)
{
    if (!length || length > BJ_CLIPBOARD_MAX_BYTES ||
        memchr(payload, '\0', length) ||
        !g_utf8_validate(payload, length, NULL))
        return FALSE;

    WPEClipboard *clipboard = backend_clipboard_for_view(state->view);
    if (!clipboard)
        return FALSE;

    char *text = g_strndup(payload, length);
    WPEClipboardContent *content = wpe_clipboard_content_new();
    wpe_clipboard_content_set_text(content, text);
    wpe_clipboard_set_content(clipboard, content);
    wpe_clipboard_content_unref(content);
    g_free(text);

    /* Keep replacement ordered inside WebKit; keyboard input is asynchronous. */
    webkit_web_view_execute_editing_command(state->view, WEBKIT_EDITING_COMMAND_SELECT_ALL);
    webkit_web_view_execute_editing_command(
        state->view, WEBKIT_EDITING_COMMAND_PASTE);
    return TRUE;
}


/*
 * BoJangles WPE input candidate.
 *
 * NONPRODUCTION.
 *
 * This translates only the bounded typed BJ_INPUT messages already emitted by
 * the trusted BoJangles frontend into the public WPE input API.
 */

#define BJ_INPUT_TEXT_MAX 4096U

static double bj_input_pointer_x = 0.0;
static double bj_input_pointer_y = 0.0;
static gboolean bj_input_pointer_valid = FALSE;
static WPEModifiers bj_input_pointer_modifiers = 0;

static guint32
bj_candidate_input_time(void)
{
    return (guint32)(g_get_monotonic_time() / 1000);
}

static const char *
bj_candidate_input_field(char **fields,
                         size_t count,
                         const char *name)
{
    size_t name_length = strlen(name);

    for (size_t i = 1; i < count; ++i) {
        if (!strncmp(fields[i], name, name_length) &&
            fields[i][name_length] == '=')
            return fields[i] + name_length + 1U;
    }

    return NULL;
}

static gboolean
bj_candidate_parse_i64(const char *value,
                       gint64 minimum,
                       gint64 maximum,
                       gint64 *result)
{
    char *end = NULL;
    gint64 parsed;

    if (!value || !*value || !result)
        return FALSE;

    errno = 0;
    parsed = g_ascii_strtoll(value, &end, 10);

    if (errno || !end || *end ||
        parsed < minimum || parsed > maximum)
        return FALSE;

    *result = parsed;
    return TRUE;
}

static gboolean
bj_candidate_parse_bool(const char *value,
                        gboolean *result)
{
    if (!value || !result)
        return FALSE;

    if (!strcmp(value, "True") ||
        !strcmp(value, "true") ||
        !strcmp(value, "1")) {
        *result = TRUE;
        return TRUE;
    }

    if (!strcmp(value, "False") ||
        !strcmp(value, "false") ||
        !strcmp(value, "0")) {
        *result = FALSE;
        return TRUE;
    }

    return FALSE;
}

static WPEModifiers
bj_candidate_button_modifier(guint button)
{
    switch (button) {
    case WPE_BUTTON_PRIMARY:
        return WPE_MODIFIER_POINTER_BUTTON1;
    case WPE_BUTTON_MIDDLE:
        return WPE_MODIFIER_POINTER_BUTTON2;
    case WPE_BUTTON_SECONDARY:
        return WPE_MODIFIER_POINTER_BUTTON3;
    default:
        return 0;
    }
}

static guint
bj_candidate_named_keyval(const char *name)
{
    if (!name)
        return 0;

    if (!strcmp(name, "Enter"))
        return WPE_KEY_Return;
    if (!strcmp(name, "Backspace"))
        return WPE_KEY_BackSpace;
    if (!strcmp(name, "Tab"))
        return WPE_KEY_Tab;
    if (!strcmp(name, "Escape"))
        return WPE_KEY_Escape;
    if (!strcmp(name, "ArrowLeft"))
        return WPE_KEY_Left;
    if (!strcmp(name, "ArrowRight"))
        return WPE_KEY_Right;
    if (!strcmp(name, "ArrowUp"))
        return WPE_KEY_Up;
    if (!strcmp(name, "ArrowDown"))
        return WPE_KEY_Down;
    if (!strcmp(name, "Home"))
        return WPE_KEY_Home;
    if (!strcmp(name, "End"))
        return WPE_KEY_End;
    if (!strcmp(name, "PageUp"))
        return WPE_KEY_Page_Up;
    if (!strcmp(name, "PageDown"))
        return WPE_KEY_Page_Down;
    if (!strcmp(name, "Menu"))
        return WPE_KEY_Menu;
    if (!strcmp(name, "Delete"))
        return WPE_KEY_Delete;
    if (!strcmp(name, "a"))
        return WPE_KEY_a;
    if (!strcmp(name, "z"))
        return WPE_KEY_z;
    if (!strcmp(name, "y"))
        return WPE_KEY_y;

    return 0;
}

static guint
bj_candidate_unicode_keyval(gunichar codepoint)
{
    if (codepoint <= 0xffU)
        return (guint)codepoint;

    if (codepoint <= 0x10ffffU)
        return 0x01000000U | (guint)codepoint;

    return 0;
}

static void
bj_candidate_deliver(WPEView *view,
                     WPEEvent *event)
{
    if (!view || !event)
        return;

    wpe_view_event(view, event);
    wpe_event_unref(event);
}

static void
bj_candidate_keyboard(WPEView *view,
                      WPEEventType type,
                      guint keyval,
                      WPEModifiers modifiers)
{
    WPEEvent *event;
    guint keycode = 0;
    WPEDisplay *display;
    WPEKeymap *keymap;
    WPEKeymapEntry *entries = NULL;
    guint entries_count = 0;

    if (!view || !keyval)
        return;

    display = wpe_view_get_display(view);
    keymap = display ? wpe_display_get_keymap(display) : NULL;
    if (keymap && wpe_keymap_get_entries_for_keyval(
            keymap, keyval, &entries, &entries_count) && entries_count)
        keycode = entries[0].keycode;
    g_free(entries);

    event = wpe_event_keyboard_new(
        type,
        view,
        WPE_INPUT_SOURCE_KEYBOARD,
        bj_candidate_input_time(),
        modifiers,
        keycode,
        keyval);

    bj_candidate_deliver(view, event);
}

static gboolean
bj_candidate_text(WPEView *view,
                  const char *text)
{
    const char *cursor;

    if (!view || !text)
        return FALSE;

    if (strlen(text) > BJ_INPUT_TEXT_MAX)
        return FALSE;

    if (!g_utf8_validate(text, -1, NULL))
        return FALSE;

    cursor = text;

    while (*cursor) {
        gunichar codepoint = g_utf8_get_char(cursor);
        guint keyval = 0;

        if (codepoint == '\n' || codepoint == '\r')
            keyval = WPE_KEY_Return;
        else if (codepoint == '\t')
            keyval = WPE_KEY_Tab;
        else if (codepoint >= 0x20U)
            keyval = bj_candidate_unicode_keyval(codepoint);

        if (keyval) {
            bj_candidate_keyboard(
                view,
                WPE_EVENT_KEYBOARD_KEY_DOWN,
                keyval,
                0);

            bj_candidate_keyboard(
                view,
                WPE_EVENT_KEYBOARD_KEY_UP,
                keyval,
                0);
        }

        cursor = g_utf8_next_char(cursor);
    }

    return TRUE;
}

static gboolean
bj_candidate_handle_input(struct BackendState *state,
                          char *payload,
                          size_t length)
{
    char *fields[8];
    size_t count;
    WPEView *view;

    if (!state || !state->view || !payload || !length)
        return FALSE;

    count = bj_split_fields(
        payload,
        length,
        fields,
        G_N_ELEMENTS(fields));

    if (!count)
        return FALSE;

    view = webkit_web_view_get_wpe_view(state->view);

    if (!view)
        return FALSE;

    if (!strcmp(fields[0], "pointer")) {
        const char *x_value =
            bj_candidate_input_field(fields, count, "x");

        const char *y_value =
            bj_candidate_input_field(fields, count, "y");

        gint64 x;
        gint64 y;
        double dx = 0.0;
        double dy = 0.0;

        if (!bj_candidate_parse_i64(
                x_value,
                0,
                (gint64)state->width - 1,
                &x) ||
            !bj_candidate_parse_i64(
                y_value,
                0,
                (gint64)state->height - 1,
                &y))
            return FALSE;

        if (bj_input_pointer_valid) {
            dx = (double)x - bj_input_pointer_x;
            dy = (double)y - bj_input_pointer_y;
        }

        WPEEvent *event =
            wpe_event_pointer_move_new(
                WPE_EVENT_POINTER_MOVE,
                view,
                WPE_INPUT_SOURCE_MOUSE,
                bj_candidate_input_time(),
                bj_input_pointer_modifiers,
                (double)x,
                (double)y,
                dx,
                dy);

        bj_input_pointer_x = (double)x;
        bj_input_pointer_y = (double)y;
        bj_input_pointer_valid = TRUE;

        bj_candidate_deliver(view, event);
        return TRUE;
    }

    if (!strcmp(fields[0], "button")) {
        const char *button_value =
            bj_candidate_input_field(
                fields, count, "button");

        const char *pressed_value =
            bj_candidate_input_field(
                fields, count, "pressed");

        gint64 parsed_button;
        gboolean pressed;
        guint button;
        guint32 time;
        guint press_count;
        WPEModifiers bit;
        WPEModifiers modifiers;
        WPEEvent *event;

        if (!bj_input_pointer_valid)
            return FALSE;

        if (!bj_candidate_parse_i64(
                button_value,
                WPE_BUTTON_PRIMARY,
                WPE_BUTTON_SECONDARY,
                &parsed_button))
            return FALSE;

        if (!bj_candidate_parse_bool(
                pressed_value,
                &pressed))
            return FALSE;

        button = (guint)parsed_button;
        bit = bj_candidate_button_modifier(button);

        if (!bit)
            return FALSE;

        time = bj_candidate_input_time();

        press_count = pressed
            ? wpe_view_compute_press_count(
                view,
                bj_input_pointer_x,
                bj_input_pointer_y,
                button,
                time)
            : 0U;

        if (pressed && !press_count)
            press_count = 1U;

        /* WPE button events carry the state AFTER this transition. Keeping
         * the released bit set suppresses WebCore pointerup and leaves the
         * page's Pointer Events state held after its first selection. */
        modifiers = pressed
            ? (WPEModifiers)(bj_input_pointer_modifiers | bit)
            : (WPEModifiers)(bj_input_pointer_modifiers & ~bit);

        event = wpe_event_pointer_button_new(
            pressed
                ? WPE_EVENT_POINTER_DOWN
                : WPE_EVENT_POINTER_UP,
            view,
            WPE_INPUT_SOURCE_MOUSE,
            time,
            modifiers,
            button,
            bj_input_pointer_x,
            bj_input_pointer_y,
            press_count);

        if (pressed && button == WPE_BUTTON_PRIMARY) {
            state->last_operator_gesture_us = g_get_monotonic_time();
            state->operator_gesture_claimed = FALSE;
        }
        bj_candidate_deliver(view, event);

        bj_input_pointer_modifiers = modifiers;

        return TRUE;
    }

    if (!strcmp(fields[0], "scroll")) {
        const char *dx_value =
            bj_candidate_input_field(
                fields, count, "dx");

        const char *dy_value =
            bj_candidate_input_field(
                fields, count, "dy");

        gint64 dx;
        gint64 dy;

        if (!bj_candidate_parse_i64(
                dx_value, -100000, 100000, &dx) ||
            !bj_candidate_parse_i64(
                dy_value, -100000, 100000, &dy))
            return FALSE;

        WPEEvent *event =
            wpe_event_scroll_new(
                view,
                WPE_INPUT_SOURCE_MOUSE,
                bj_candidate_input_time(),
                bj_input_pointer_modifiers,
                -(double)dx,
                -(double)dy,
                TRUE,
                FALSE,
                bj_input_pointer_x,
                bj_input_pointer_y);

        bj_candidate_deliver(view, event);
        return TRUE;
    }

    if (!strcmp(fields[0], "focus")) {
        const char *focused_value =
            bj_candidate_input_field(
                fields, count, "focused");
        gboolean focused;

        if (!bj_candidate_parse_bool(focused_value, &focused))
            return FALSE;

        state->surface_focused = focused;
        if (focused)
            wpe_view_focus_in(view);
        else
            wpe_view_focus_out(view);
        return TRUE;
    }

    if (!strcmp(fields[0], "key")) {
        const char *key =
            bj_candidate_input_field(
                fields, count, "key");

        const char *pressed_value =
            bj_candidate_input_field(
                fields, count, "pressed");

        const char *modifiers_value =
            bj_candidate_input_field(
                fields, count, "modifiers");

        gboolean pressed;
        guint keyval;
        gint64 parsed_modifiers = 0;
        WPEModifiers modifiers = 0;

        if (!bj_candidate_parse_bool(
                pressed_value,
                &pressed))
            return FALSE;

        if (modifiers_value &&
            !bj_candidate_parse_i64(
                modifiers_value, 0, 31, &parsed_modifiers))
            return FALSE;
        modifiers = (WPEModifiers)parsed_modifiers;

        keyval = bj_candidate_named_keyval(key);

        if (!keyval)
            return FALSE;

        if (keyval == WPE_KEY_Menu) {
            if (pressed) webkit_web_view_bojangles_context_menu_for_key(state->view);
            return TRUE;
        }
        if (pressed && keyval == WPE_KEY_Return) {
            state->last_operator_gesture_us = g_get_monotonic_time();
            state->operator_gesture_claimed = FALSE;
        }
        bj_candidate_keyboard(
            view,
            pressed
                ? WPE_EVENT_KEYBOARD_KEY_DOWN
                : WPE_EVENT_KEYBOARD_KEY_UP,
            keyval,
            modifiers);

        return TRUE;
    }

    if (!strcmp(fields[0], "text")) {
        if (count != 2U)
            return FALSE;

        return bj_candidate_text(
            view,
            fields[1]);
    }

    return FALSE;
}


static gboolean backend_ipc_ready(gint fd, GIOCondition condition, gpointer user_data)
{
    struct BackendState *state = user_data;
    if (condition & (G_IO_HUP | G_IO_ERR | G_IO_NVAL)) {
        state->stopping = TRUE;
        g_main_loop_quit(state->loop);
        return G_SOURCE_REMOVE;
    }

    guint8 packet[16U + BJ_MAX_PACKET];
    char control[CMSG_SPACE(sizeof(int) * 2U)];
    struct iovec iov = { .iov_base = packet, .iov_len = sizeof(packet) };
    struct msghdr message = {0};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    ssize_t received = recvmsg(fd, &message, MSG_CMSG_CLOEXEC);
    if (received < 0 && errno == EINTR)
        return G_SOURCE_CONTINUE;
    if (received < 0) {
        state->stopping = TRUE;
        g_main_loop_quit(state->loop);
        return G_SOURCE_REMOVE;
    }
    int received_fd = -1;
    unsigned fd_count = 0;
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message); cmsg; cmsg = CMSG_NXTHDR(&message, cmsg)) {
        if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
            continue;
        size_t count = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        int *fds = (int *)CMSG_DATA(cmsg);
        for (size_t index = 0; index < count; ++index) {
            ++fd_count;
            if (received_fd < 0)
                received_fd = fds[index];
            else
                close(fds[index]);
        }
    }

    if ((message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) || fd_count > 1 ||
        received < 16 || bj_get_u32(packet) != BJ_MAGIC ||
        bj_get_u16(packet + 4) != BJ_VERSION) {
        if (received_fd >= 0) close(received_fd);
        fputs("WPE_STAGE5A_FAIL malformed-ipc-header\n", stderr);
        state->stopping = TRUE;
        g_main_loop_quit(state->loop);
        return G_SOURCE_REMOVE;
    }

    guint16 kind = bj_get_u16(packet + 6);
    guint32 length = bj_get_u32(packet + 8);
    guint32 request_id = bj_get_u32(packet + 12);
    if (length > BJ_MAX_PACKET || (size_t)received != 16U + (size_t)length) {
        if (received_fd >= 0) close(received_fd);
        fputs("WPE_STAGE5A_FAIL malformed-ipc-length\n", stderr);
        state->stopping = TRUE;
        g_main_loop_quit(state->loop);
        return G_SOURCE_REMOVE;
    }
    gboolean resource_kind = kind == BJ_SITE_RULES || kind == BJ_LOAD_DATA || kind == BJ_LOAD_DATA_HEADERS ||
                             kind == BJ_RESOURCE_DATA || kind == BJ_RESOURCE_DECISION ||
                             kind == BJ_RESOURCE_REDIRECT;
    gboolean control_kind = kind == BJ_STOP || kind == BJ_LOAD || kind == BJ_RESIZE ||
                            kind == BJ_INPUT || kind == BJ_SNAPSHOT || kind == BJ_RESTORE ||
                            kind == BJ_SET_DRM || kind == BJ_IMAGE_DATA_REQUEST || kind == BJ_PRINT_PDF_REQUEST || kind == BJ_PAGE_EXPORT_REQUEST || kind == BJ_CLIPBOARD_COPY_REQUEST ||
                            kind == BJ_CLIPBOARD_CUT_RICH || kind == BJ_CLIPBOARD_PASTE_TEXT || kind == BJ_CLIPBOARD_PASTE_RICH || kind == BJ_CLIPBOARD_COPY_RICH || kind == BJ_CLIPBOARD_PASTE_PNG || kind == BJ_FILE_CHOOSER_RESULT ||
                            kind == BJ_SCRIPT_DIALOG_RESULT || kind == BJ_SPELLING_MENU_RESULT ||
                            kind == BJ_CREDENTIAL_FILL || kind == BJ_TRANSLATION_EXTRACT ||
                            kind == BJ_TRANSLATION_APPLY || kind == BJ_TRANSLATION_RESTORE ||
                            (kind >= BJ_NAV_BACK && kind <= BJ_TERMINATE && kind != BJ_STATE_RESULT);
    if ((!resource_kind && !control_kind) || resource_kind != (fd == state->resource_fd) ||
        kind == BJ_RESOURCE_REQUEST ||
        (received_fd >= 0 && kind != BJ_LOAD_DATA &&
         kind != BJ_LOAD_DATA_HEADERS && kind != BJ_RESOURCE_DATA && kind != BJ_RESIZE && kind != BJ_CLIPBOARD_PASTE_PNG && kind != BJ_IMAGE_DATA_REQUEST && kind != BJ_PRINT_PDF_REQUEST && kind != BJ_PAGE_EXPORT_REQUEST)) {
        if (received_fd >= 0) close(received_fd);
        fputs("WPE_STEP12_FAIL wrong-channel-or-descriptor\n", stderr);
        state->stopping = TRUE;
        g_main_loop_quit(state->loop);
        return G_SOURCE_REMOVE;
    }
    char *payload = (char *)(packet + 16);

    if (kind == BJ_TRANSLATION_EXTRACT || kind == BJ_TRANSLATION_APPLY || kind == BJ_TRANSLATION_RESTORE) {
        if (!backend_translation(state, kind, payload, length, request_id)) {
            const char *fields[] = {state->document_id, "{\"error\":\"Translation request rejected\"}"};
            GByteArray *answer = bj_pack_strings(fields, 2);
            bj_send_packet(state->control_fd, BJ_TRANSLATION_RESULT, request_id, answer->data, answer->len);
            g_byte_array_unref(answer);
            fputs("WPE_TRANSLATION_REJECTED\n", stderr);
        }
        return G_SOURCE_CONTINUE;
    }

    if (kind == BJ_IMAGE_DATA_REQUEST) {
        if (!backend_image_data(state, payload, length, request_id, received_fd)) {
            if (received_fd >= 0) close(received_fd);
            bj_send_packet(state->control_fd, BJ_IMAGE_DATA_RESULT, request_id, "", 0);
        }
        return G_SOURCE_CONTINUE;
    }

    if (kind == BJ_PAGE_EXPORT_REQUEST) {
        if (!backend_page_export(state, payload, length, request_id, received_fd)) {
            if (received_fd >= 0) close(received_fd);
            bj_send_packet(state->control_fd, BJ_PAGE_EXPORT_RESULT, request_id, "", 0);
            fputs("WPE_PAGE_EXPORT_REJECTED\n", stderr);
        }
        return G_SOURCE_CONTINUE;
    }

    if (kind == BJ_PRINT_PDF_REQUEST) {
        if (!backend_print_pdf(state, payload, length, request_id, received_fd)) {
            if (received_fd >= 0) close(received_fd);
            bj_send_packet(state->control_fd, BJ_PRINT_PDF_RESULT, request_id, "", 0);
            fputs("WPE_PRINT_PDF_REJECTED\n", stderr);
        }
        return G_SOURCE_CONTINUE;
    }

    if (kind == BJ_CLIPBOARD_PASTE_PNG) {
        gboolean accepted = backend_clipboard_paste_png(state, payload, length, received_fd);
        if (received_fd >= 0) close(received_fd);
        const char result = accepted ? '1' : '0';
        bj_send_packet(state->control_fd, BJ_CLIPBOARD_PASTE_RESULT, request_id, &result, 1);
        if (!accepted) fputs("WPE_CLIPBOARD_PASTE_PNG_REJECTED\n", stderr);
        return G_SOURCE_CONTINUE;
    }

    if (kind == BJ_STOP || kind == BJ_TERMINATE) {
        if (received_fd >= 0) close(received_fd);
        state->stopping = TRUE;
        g_main_loop_quit(state->loop);
        return G_SOURCE_REMOVE;
    }

    if (kind == BJ_LOAD) {
        if (received_fd >= 0) close(received_fd);
        fputs("WPE_STAGE5A_FAIL raw-network-load-denied\n", stderr);
        return G_SOURCE_CONTINUE;
    }

    if (kind == BJ_SET_DRM) {
        if (received_fd >= 0) close(received_fd);
        if (length != 1U || (payload[0] != '0' && payload[0] != '1'))
            return G_SOURCE_CONTINUE;
        WebKitSettings *settings = webkit_web_view_get_settings(state->view);
        if (settings)
            webkit_settings_set_enable_encrypted_media(settings, payload[0] == '1');
        return G_SOURCE_CONTINUE;
    }

    /* The frontend owns document authority and history. These typed control
     * intents never authorize a native URL fetch or accept page script. */
    if (kind >= BJ_NAV_BACK && kind <= BJ_STATE_REQUEST) {
        if ((kind == BJ_NAVIGATE && (length == 0 || length > 8192 ||
             memchr(payload, '\0', length))) ||
            (kind != BJ_NAVIGATE && length != 0))
            return G_SOURCE_CONTINUE;
        if (kind == BJ_NAV_STOP)
            webkit_web_view_stop_loading(state->view);
        if (kind == BJ_STATE_REQUEST) {
            const char *uri = state->uri ? state->uri : "";
            bj_send_packet(fd, BJ_STATE_RESULT, request_id, uri, strlen(uri));
        }
        return G_SOURCE_CONTINUE;
    }

    if (kind == BJ_SITE_RULES) {
        g_clear_pointer(&state->site_rule_document, g_free);
        g_clear_pointer(&state->site_rule_uri, g_free);
        g_clear_pointer(&state->site_rule_css, g_free);
        char *fields[3];
        if (length <= 49152U && bj_split_fields(payload, length, fields, 3) == 3U &&
            strlen(fields[0]) <= 256U && strlen(fields[1]) <= 8192U &&
            strlen(fields[2]) <= 32768U && g_utf8_validate(fields[2], -1, NULL)) {
            state->site_rule_document = g_strdup(fields[0]);
            state->site_rule_uri = g_strdup(fields[1]);
            state->site_rule_css = g_strdup(fields[2]);
        }
        return G_SOURCE_CONTINUE;
    }

    if (kind == BJ_LOAD_DATA || kind == BJ_LOAD_DATA_HEADERS) {
        char *fields[136];
        size_t field_count = bj_split_fields(
            payload, length, fields, G_N_ELEMENTS(fields));
        if (received_fd < 0 ||
            (kind == BJ_LOAD_DATA && field_count != 5U) ||
            (kind == BJ_LOAD_DATA_HEADERS && field_count < 7U)) {
            if (received_fd >= 0) close(received_fd);
            fputs("WPE_STAGE5A_FAIL malformed-load-data\n", stderr);
            return G_SOURCE_CONTINUE;
        }
        char *end = NULL;
        errno = 0;
        unsigned long long body_length = strtoull(fields[4], &end, 10);
        struct stat body_stat;
        int required_seals = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;
        int actual_seals = fcntl(received_fd, F_GET_SEALS);
        if (errno || !end || *end || body_length > 8ULL * 1024ULL * 1024ULL ||
            actual_seals < 0 || (actual_seals & required_seals) != required_seals ||
            fstat(received_fd, &body_stat) != 0 || body_stat.st_size < 0 ||
            (unsigned long long)body_stat.st_size != body_length) {
            close(received_fd);
            fputs("WPE_STAGE5A_FAIL invalid-document-memfd\n", stderr);
            return G_SOURCE_CONTINUE;
        }
        guint8 *body = g_malloc((gsize)body_length ? (gsize)body_length : 1U);
        size_t offset = 0;
        while (offset < (size_t)body_length) {
            ssize_t got = pread(received_fd, body + offset, (size_t)body_length - offset, (off_t)offset);
            if (got <= 0) {
                g_free(body);
                close(received_fd);
                fputs("WPE_STAGE5A_FAIL document-memfd-read\n", stderr);
                return G_SOURCE_CONTINUE;
            }
            offset += (size_t)got;
        }
        close(received_fd);
        g_free(state->document_id);
        g_free(state->uri);
        g_clear_pointer(&state->pending_main_navigation_uri, g_free);
        state->last_operator_gesture_us = 0;
        state->operator_gesture_claimed = FALSE;
        state->automatic_same_origin_used = FALSE;
        state->automatic_cross_origin_used = FALSE;
        backend_clear_spelling_menu(state);
        g_clear_pointer(&state->image_resources, g_ptr_array_unref);
        state->document_id = g_strdup(fields[0]);
        state->uri = g_strdup(fields[1]);
        backend_send_uri_event(state, BJ_NAVIGATION_STARTED);
        const char *mime = fields[2][0] ? fields[2] : "application/octet-stream";
        state->trusted_document_load = TRUE;
        gboolean is_html = g_ascii_strncasecmp(mime, "text/html", 9) == 0 &&
                           (mime[9] == '\0' || mime[9] == ';' || g_ascii_isspace(mime[9]));
        GBytes *document_bytes = NULL;
        char *content_type = NULL;
        if (is_html) {
            char *html = bj_html_to_utf8(body, (gsize)body_length, fields[3]);
            if (!html) {
                g_free(body);
                fputs("WPE_STAGE5B_FAIL html-utf8\n", stderr);
                return G_SOURCE_CONTINUE;
            }
            g_free(body);
            document_bytes = g_bytes_new_take(html, strlen(html));
            content_type = g_strdup("text/html; charset=UTF-8");
        } else {
            document_bytes = g_bytes_new_take(body, (gsize)body_length);
            content_type = fields[3][0]
                ? g_strdup_printf("%s; charset=%s", mime, fields[3])
                : g_strdup(mime);
        }

        /* Present the trusted bytes as the response to one real HTTP(S)
         * navigation handled entirely inside BoJangles. This gives WebKit
         * normal URL/origin/history semantics while the registered BoJangles
         * HTTP handler remains the only path for every subsequent request. */
        bj_clear_pending_document(state);
        state->pending_document_bytes = document_bytes;
        state->pending_document_uri = g_strdup(state->uri);
        state->pending_document_content_type = content_type;
        state->pending_document_status = 200U;

        if (kind == BJ_LOAD_DATA_HEADERS) {
            char *status_end = NULL;
            char *count_end = NULL;
            errno = 0;
            unsigned long status = strtoul(fields[5], &status_end, 10);
            unsigned long header_count = strtoul(fields[6], &count_end, 10);
            if (errno || !status_end || *status_end || !count_end || *count_end ||
                status < 100U || status > 599U ||
                header_count > BJ_STAGE5D_MAX_HEADERS ||
                field_count != 7U + header_count * 2U) {
                bj_clear_pending_document(state);
                fputs("WPE_STAGE5B_FAIL invalid-document-metadata\n", stderr);
                return G_SOURCE_CONTINUE;
            }

            SoupMessageHeaders *headers =
                soup_message_headers_new(SOUP_MESSAGE_HEADERS_RESPONSE);
            size_t header_bytes = 0U;
            for (size_t i = 0; i < header_count; ++i) {
                const char *name = fields[7U + i * 2U];
                const char *value = fields[8U + i * 2U];
                if (!bj_header_field_safe(name, 128U) ||
                    !bj_header_field_safe(
                        value, BJ_STAGE5D_MAX_RESPONSE_HEADER_VALUE_BYTES)) {
                    soup_message_headers_unref(headers);
                    bj_clear_pending_document(state);
                    fputs("WPE_STAGE5B_FAIL invalid-document-header\n", stderr);
                    return G_SOURCE_CONTINUE;
                }
                header_bytes += strlen(name) + strlen(value) + 4U;
                if (header_bytes > BJ_STAGE5D_MAX_RESPONSE_HEADER_BYTES) {
                    soup_message_headers_unref(headers);
                    bj_clear_pending_document(state);
                    fputs("WPE_STAGE5B_FAIL document-header-budget\n", stderr);
                    return G_SOURCE_CONTINUE;
                }
                soup_message_headers_append(headers, name, value);
            }
            state->pending_document_status = (guint)status;
            state->pending_document_headers = headers;
        }

        /* Consume a trusted snapshot on the same ordered RESOURCE channel.
         * No file mounts, page callbacks, script execution or iframe rules. */
        WebKitUserContentManager *manager = webkit_web_view_get_user_content_manager(state->view);
        if (state->site_rule_sheet) {
            webkit_user_content_manager_remove_style_sheet(manager, state->site_rule_sheet);
            webkit_user_style_sheet_unref(state->site_rule_sheet);
            state->site_rule_sheet = NULL;
        }
        unsigned style_count = 0;
        if (state->site_rule_document && state->site_rule_uri && state->site_rule_css &&
            strcmp(state->site_rule_document, state->document_id) == 0 &&
            strcmp(state->site_rule_uri, state->uri) == 0 && state->site_rule_css[0]) {
            state->site_rule_sheet = webkit_user_style_sheet_new(
                state->site_rule_css, WEBKIT_USER_CONTENT_INJECT_TOP_FRAME,
                WEBKIT_USER_STYLE_LEVEL_USER, NULL, NULL);
            webkit_user_content_manager_add_style_sheet(manager, state->site_rule_sheet);
            style_count = 1;
            for (const char *cursor = state->site_rule_css; *cursor; ++cursor)
                if (*cursor == '\n') ++style_count;
        }
        char style_text[16];
        snprintf(style_text, sizeof(style_text), "%u", style_count <= 64 ? style_count : 0);
        const char *style_fields[] = {state->document_id, state->uri, style_text};
        GByteArray *style_ack = bj_pack_strings(style_fields, 3);
        bj_send_packet(state->control_fd, BJ_STYLE_APPLIED, 0, style_ack->data, style_ack->len);
        g_byte_array_unref(style_ack);
        g_clear_pointer(&state->site_rule_document, g_free);
        g_clear_pointer(&state->site_rule_uri, g_free);
        g_clear_pointer(&state->site_rule_css, g_free);
        webkit_web_view_load_uri(state->view, state->uri);
        return G_SOURCE_CONTINUE;
    }

    if (
        kind == BJ_RESOURCE_DATA ||
        kind == BJ_RESOURCE_DECISION || kind == BJ_RESOURCE_REDIRECT
    ) {
        bj_complete_resource_reply(
            state,
            kind,
            request_id,
            payload,
            length,
            received_fd);

        return G_SOURCE_CONTINUE;
    }

    if (kind == BJ_RESIZE) {
        if (received_fd >= 0) {
            if (length != 12U) {
                close(received_fd);
                return G_SOURCE_CONTINUE;
            }
            guint32 width = bj_get_u32((const guint8 *)payload);
            guint32 height = bj_get_u32((const guint8 *)payload + 4);
            guint32 stride = bj_get_u32((const guint8 *)payload + 8);
            guint64 size = (guint64)stride * height;
            struct stat info;
            if (!width || !height || width > 16384U || height > 16384U ||
                stride != (guint64)width * 4U || size > 512U * 1024U * 1024U ||
                fstat(received_fd, &info) || !S_ISREG(info.st_mode) ||
                (guint64)info.st_size != size) {
                close(received_fd);
                return G_SOURCE_CONTINUE;
            }
            guint8 *replacement = mmap(NULL, (size_t)size, PROT_READ | PROT_WRITE,
                                      MAP_SHARED, received_fd, 0);
            close(received_fd);
            if (replacement == MAP_FAILED)
                return G_SOURCE_CONTINUE;
            munmap(state->framebuffer, state->framebuffer_length);
            ++state->frame_serial;
            state->framebuffer = replacement;
            state->framebuffer_length = (size_t)size;
            state->width = width;
            state->height = height;
            state->stride = stride;
        } else if (length != 8U) {
            return G_SOURCE_CONTINUE;
        }
        guint32 width = bj_get_u32((const guint8 *)payload);
        guint32 height = bj_get_u32((const guint8 *)payload + 4);
        if (!width || !height || width > state->width || height > state->height)
            return G_SOURCE_CONTINUE;
        WPEView *wpe_view = webkit_web_view_get_wpe_view(state->view);
        if (wpe_view && wpe_view_get_toplevel(wpe_view))
            wpe_toplevel_resize(wpe_view_get_toplevel(wpe_view), width, height);
        return G_SOURCE_CONTINUE;
    }

    if (received_fd >= 0) {
        close(received_fd);
        fputs("WPE_STAGE5A_FAIL unexpected-ipc-fd\n", stderr);
        return G_SOURCE_CONTINUE;
    }

    if (kind == BJ_INPUT) {
        if (length > BJ_MAX_PACKET)
            return G_SOURCE_CONTINUE;
        bj_candidate_handle_input(state, payload, length);
        return G_SOURCE_CONTINUE;
    }

    if (kind == BJ_CLIPBOARD_COPY_REQUEST || kind == BJ_CLIPBOARD_COPY_RICH || kind == BJ_CLIPBOARD_CUT_RICH) {
        if (length != 0U)
            return G_SOURCE_CONTINUE;
        if (!backend_clipboard_begin_copy(state, request_id, kind != BJ_CLIPBOARD_COPY_REQUEST, kind == BJ_CLIPBOARD_CUT_RICH)) {
            const char *message = "WPE local clipboard unavailable";
            bj_send_packet(
                state->control_fd, BJ_ERROR, request_id,
                message, (guint32)strlen(message));
        }
        return G_SOURCE_CONTINUE;
    }

    if (kind == BJ_CLIPBOARD_PASTE_RICH) {
        char *fields[3];
        gboolean accepted = FALSE;
        if (bj_split_fields(payload, length, fields, 3) == 3U &&
            state->document_id && !strcmp(fields[0], state->document_id) &&
            strlen(fields[1]) <= BJ_CLIPBOARD_MAX_BYTES && strlen(fields[2]) <= 524288U &&
            g_utf8_validate(fields[1], -1, NULL) && g_utf8_validate(fields[2], -1, NULL)) {
            WPEClipboard *clipboard = backend_clipboard_for_view(state->view);
            if (clipboard) {
                WPEClipboardContent *content = wpe_clipboard_content_new();
                wpe_clipboard_content_set_text(content, fields[1]);
                GBytes *html = g_bytes_new(fields[2], strlen(fields[2]));
                wpe_clipboard_content_set_bytes(content, "text/html", html);
                g_bytes_unref(html);
                wpe_clipboard_set_content(clipboard, content);
                wpe_clipboard_content_unref(content);
                webkit_web_view_execute_editing_command(state->view, WEBKIT_EDITING_COMMAND_SELECT_ALL);
                webkit_web_view_execute_editing_command(state->view, WEBKIT_EDITING_COMMAND_PASTE);
                accepted = TRUE;
            }
        }
        const char answer = accepted ? '1' : '0';
        bj_send_packet(state->control_fd, BJ_CLIPBOARD_PASTE_RESULT, request_id, &answer, 1);
        return G_SOURCE_CONTINUE;
    }

    if (kind == BJ_CLIPBOARD_PASTE_TEXT) {
        if (!backend_clipboard_paste_text(state, payload, length))
            fputs("WPE_CLIPBOARD_PASTE_REJECTED\n", stderr);
        return G_SOURCE_CONTINUE;
    }

    if (kind == BJ_CREDENTIAL_FILL) {
        if (!backend_fill_credentials(state, request_id, payload, length)) {
            const char answer = '0';
            bj_send_packet(state->control_fd, BJ_CREDENTIAL_FILL_RESULT,
                           request_id, &answer, 1);
        }
        return G_SOURCE_CONTINUE;
    }

    if (kind == BJ_FILE_CHOOSER_RESULT) {
        if (!state->pending_file_chooser || request_id != state->pending_file_chooser_id)
            return G_SOURCE_CONTINUE;
        if (!length) {
            webkit_file_chooser_request_cancel(state->pending_file_chooser);
        } else {
            char *fields[65];
            size_t count = bj_split_fields(payload, length, fields, G_N_ELEMENTS(fields));
            if (!count) {
                webkit_file_chooser_request_cancel(state->pending_file_chooser);
            } else {
                const gchar **files = g_new0(const gchar *, count + 1U);
                for (size_t i = 0; i < count; ++i)
                    files[i] = fields[i];
                webkit_file_chooser_request_select_files(state->pending_file_chooser, files);
                g_free(files);
            }
        }
        g_clear_object(&state->pending_file_chooser);
        state->pending_file_chooser_id = 0;
        return G_SOURCE_CONTINUE;
    }

    if (kind == BJ_SPELLING_MENU_RESULT) {
        if (!state->spelling_actions || request_id != state->spelling_menu_id)
            return G_SOURCE_CONTINUE;
        gboolean valid = state->document_id && state->spelling_document_id &&
            g_str_equal(state->document_id, state->spelling_document_id) &&
            g_get_monotonic_time() - state->spelling_menu_us <= 20 * G_TIME_SPAN_SECOND;
        char *fields[1];
        size_t count = bj_split_fields(payload, length, fields, G_N_ELEMENTS(fields));
        GAction *action = NULL;
        GVariant *target = NULL;
        char *index_end = NULL;
        guint64 index_value = (count == 1 && fields[0][0])
            ? g_ascii_strtoull(fields[0], &index_end, 10) : 48;
        if (valid && count == 1 && fields[0][0] >= '0' && fields[0][0] <= '9' &&
            strlen(fields[0]) <= 2 && index_end && !*index_end && index_value < 48) {
            guint index = (guint)index_value;
            if (index < state->spelling_actions->len) {
                struct SpellingAction *choice = g_ptr_array_index(state->spelling_actions, index);
                action = g_object_ref(choice->action);
                target = choice->target ? g_variant_ref(choice->target) : NULL;
            }
        }
        backend_clear_spelling_menu(state);
        if (action) {
            if (g_action_get_enabled(action))
                g_action_activate(action, target);
            g_clear_object(&action);
            if (target) g_variant_unref(target);
        }
        return G_SOURCE_CONTINUE;
    }

    if (kind == BJ_SCRIPT_DIALOG_RESULT) {
        if (!state->pending_script_dialog || request_id != state->pending_script_dialog_id)
            return G_SOURCE_CONTINUE;
        char *fields[2];
        size_t count = bj_split_fields(payload, length, fields, G_N_ELEMENTS(fields));
        gboolean accepted = count == 2 && strcmp(fields[0], "1") == 0;
        WebKitScriptDialogType type = webkit_script_dialog_get_dialog_type(state->pending_script_dialog);
        if (type == WEBKIT_SCRIPT_DIALOG_CONFIRM || type == WEBKIT_SCRIPT_DIALOG_BEFORE_UNLOAD_CONFIRM)
            webkit_script_dialog_confirm_set_confirmed(state->pending_script_dialog, accepted);
        else if (type == WEBKIT_SCRIPT_DIALOG_PROMPT && accepted)
            webkit_script_dialog_prompt_set_text(state->pending_script_dialog, count == 2 ? fields[1] : "");
        webkit_script_dialog_close(state->pending_script_dialog);
        webkit_script_dialog_unref(state->pending_script_dialog);
        state->pending_script_dialog = NULL;
        state->pending_script_dialog_id = 0;
        return G_SOURCE_CONTINUE;
    }

    if (kind == BJ_SNAPSHOT) {
        /* Fixed isolated-world DOM access; the IPC never accepts executable code. */
        const char *script = "(()=>{const eligible=e=>e.name && !e.name.includes('\\0') && e.name.length<=256 && (e.tagName==='TEXTAREA' || (e.tagName==='INPUT' && ['text','search','url','email','tel','number'].includes(e.type)) || (e.tagName==='SELECT' && !e.multiple)); const elements=Array.from(document.querySelectorAll('input[name],textarea[name],select[name]')).filter(eligible);const fields=[]; const seen=new Set(); for(const e of elements){if(seen.has(e.name)||e.value.includes('\\0')||e.value.length>1024) continue; if(fields.length>=64) throw Error('form count bound'); seen.add(e.name); fields.push([e.name,e.value]);} return [String(Math.trunc(scrollX)),String(Math.trunc(scrollY)),String(fields.length),...fields.flat()].join('\\0')+'\\0';})()";
        webkit_web_view_evaluate_javascript(state->view, script, -1,
            "bojangles-bounded-state", NULL, state->operations, backend_state_ready,
            backend_state_request(state, request_id, FALSE));
        return G_SOURCE_CONTINUE;
    }

    if (kind == BJ_RESTORE) {
        char *fields[5 + 2 * BJ_STATE_MAX_FIELDS];
        size_t count = bj_split_fields(payload, length, fields, G_N_ELEMENTS(fields));
        if (length > BJ_STATE_MAX_BYTES || !bj_state_fields_valid(fields, count, 2) ||
            !state->document_id || !state->uri ||
            strcmp(fields[0], state->document_id) || strcmp(fields[1], state->uri)) {
            const char answer = '0';
            bj_send_packet(fd, BJ_RESTORE_RESULT, request_id, &answer, 1);
            return G_SOURCE_CONTINUE;
        }
        char *encoded = g_base64_encode((const guint8 *)payload, length);
        GVariantBuilder arguments;
        g_variant_builder_init(&arguments, G_VARIANT_TYPE_VARDICT);
        g_variant_builder_add(&arguments, "{sv}", "encoded", g_variant_new_string(encoded));
        GVariant *args = g_variant_ref_sink(g_variant_builder_end(&arguments));
        const char *script = "const raw=Uint8Array.from(atob(encoded),c=>c.charCodeAt(0)); const a=new TextDecoder('utf-8',{fatal:true}).decode(raw).split('\\0'); a.pop();const eligible=e=>e.name && !e.name.includes('\\0') && e.name.length<=256 && (e.tagName==='TEXTAREA' || (e.tagName==='INPUT' && ['text','search','url','email','tel','number'].includes(e.type)) || (e.tagName==='SELECT' && !e.multiple)); const elements=Array.from(document.querySelectorAll('input[name],textarea[name],select[name]')).filter(eligible);for(let i=0;i<Number(a[4]);i++){const matches=elements.filter(e=>e.name===a[5+2*i]);if(matches.length!==1)return false;} for(let i=0;i<Number(a[4]);i++)elements.find(e=>e.name===a[5+2*i]).value=a[6+2*i];scrollTo(Number(a[2]),Number(a[3]));return true;";
        webkit_web_view_call_async_javascript_function(state->view, script, -1, args,
            "bojangles-bounded-state", NULL, state->operations, backend_state_ready,
            backend_state_request(state, request_id, TRUE));
        g_variant_unref(args);
        g_free(encoded);
        return G_SOURCE_CONTINUE;
    }

    fputs("WPE_STAGE5A_FAIL unsupported-ipc-message\n", stderr);
    return G_SOURCE_CONTINUE;
}

/* Leaving the outer PID namespace kills every remaining WebKit child. Drain
 * public-object teardown and wait for child reaping before leaving it. This
 * bounded shutdown check creates no process, service, or background cleaner. */
static gboolean backend_finish_shutdown(gboolean keep_network_session)
{
    char path[128];
    snprintf(path, sizeof(path), "/proc/self/task/%ld/children", (long)getpid());
    gint64 deadline = g_get_monotonic_time() + 8 * G_TIME_SPAN_SECOND;
    do {
        while (g_get_monotonic_time() < deadline &&
               g_main_context_iteration(NULL, FALSE)) {}
        char *children = NULL;
        if (!g_file_get_contents(path, &children, NULL, NULL)) {
            fputs("WPE_SHUTDOWN_FAIL cannot observe child teardown\n", stderr);
            return FALSE;
        }
        gboolean finished = TRUE;
        char **pids = g_strsplit_set(children, " \t\n", -1);
        for (char **entry = pids; *entry; ++entry) {
            if (!**entry)
                continue;
            char *exe_path = g_strdup_printf("/proc/%s/exe", *entry);
            char *exe = g_file_read_link(exe_path, NULL);
            g_free(exe_path);
            if (!keep_network_session || !exe ||
                !g_str_has_suffix(exe, "/WPENetworkProcess"))
                finished = FALSE;
            g_free(exe);
        }
        g_strfreev(pids);
        g_free(children);
        if (finished)
            return TRUE;
        g_usleep(10000);
    } while (g_get_monotonic_time() < deadline);
    fprintf(stderr, "WPE_SHUTDOWN_FAIL phase=%s child teardown did not complete\n",
            keep_network_session ? "rendering" : "storage");
    return FALSE;
}

static int run_stage4b_backend(int argc, char **argv)
{
    struct BackendOptions options;
    if (!parse_backend_options(argc, argv, &options)) {
        fputs("WPE_STAGE4B_FAIL invalid-backend-arguments\n", stderr);
        return 5;
    }
    if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) {
        fputs("WPE_STAGE4B_FAIL no-new-privs-not-set\n", stderr);
        return 5;
    }

    const char *extension_dir = g_getenv("BOJANGLES_WPE_EXTENSION_DIR");
    if (!extension_dir || !*extension_dir) {
        fputs("WPE_STAGE4B_FAIL extension-dir-unset\n", stderr);
        return 5;
    }

    size_t framebuffer_length = (size_t)options.stride * (size_t)options.height;
    if (options.height && framebuffer_length / options.height != options.stride) {
        fputs("WPE_STAGE4B_FAIL framebuffer-overflow\n", stderr);
        return 5;
    }
    guint8 *framebuffer = mmap(NULL, framebuffer_length, PROT_READ | PROT_WRITE,
                               MAP_SHARED, options.fb_fd, 0);
    if (framebuffer == MAP_FAILED) {
        die_errno("mmap-framebuffer");
    }

    WebKitWebContext *context = WEBKIT_WEB_CONTEXT(g_object_new(WEBKIT_TYPE_WEB_CONTEXT, NULL));
    if (!context) {
        munmap(framebuffer, framebuffer_length);
        return 5;
    }
    webkit_web_context_set_web_process_extensions_directory(context, extension_dir);
    /* Local, advisory spelling for webpage editors. No autocorrection or
     * network dictionary service; browser chrome is outside WebKit editing. */
    const gchar *spell_languages[] = { "en_US", NULL };
    webkit_web_context_set_spell_checking_languages(context, spell_languages);
    webkit_web_context_set_spell_checking_enabled(context, TRUE);

    const char *profile_data = g_getenv("BOJANGLES_WPE_DATA_DIR");
    const char *profile_cache = g_getenv("BOJANGLES_WPE_CACHE_DIR");
    gboolean persistent_profile = profile_data && *profile_data && profile_cache && *profile_cache;
    WebKitNetworkSession *network_session = persistent_profile
        ? webkit_network_session_new(profile_data, profile_cache)
        : webkit_network_session_new_ephemeral();
    if (!network_session) {
        g_object_unref(context);
        munmap(framebuffer, framebuffer_length);
        return 5;
    }
    if (persistent_profile && webkit_network_session_is_ephemeral(network_session)) {
        fputs("WPE_STAGE7_FAIL persistent-session-is-ephemeral\n", stderr);
        g_object_unref(network_session);
        g_object_unref(context);
        munmap(framebuffer, framebuffer_length);
        return 5;
    }
    struct Stage6CookieHygiene hygiene;
    if (!stage6_configure_network_session(network_session, &hygiene)) {
        fputs("WPE_STAGE6_FAIL network-session-policy\n", stderr);
        g_object_unref(network_session);
        g_object_unref(context);
        munmap(framebuffer, framebuffer_length);
        return 5;
    }

    struct BackendState state = {
        .loop = g_main_loop_new(NULL, FALSE),
        .context = context,
        .network_session = network_session,
        .view = NULL,
        .control_fd = options.control_fd,
        .resource_fd = options.resource_fd,
        .framebuffer = framebuffer,
        .framebuffer_length = framebuffer_length,
        .width = options.width,
        .height = options.height,
        .stride = options.stride,
        .pixel_format = options.pixel_format,
        .document_id = NULL,
        .uri = NULL,
        .stopping = FALSE,
        .surface_focused = FALSE,
        .next_resource_request_id = 1U,
        .persistent_profile = persistent_profile,
        .retention = {0},
        .operations = NULL,
    };
    if (persistent_profile && !stage7_configure_persistent_profile(network_session, &state.retention)) {
        fputs("WPE_STAGE7_FAIL persistent-profile-policy\n", stderr);
        g_main_loop_unref(state.loop);
        g_object_unref(network_session);
        g_object_unref(context);
        munmap(framebuffer, framebuffer_length);
        return 5;
    }

    if (!webkit_web_context_register_bojangles_http_v1(context, backend_resource_scheme_request, &state)) {
        fputs("WPE_BROKER_FAIL http-handler-registration\n", stderr);
        return 5;
    }
    webkit_web_context_register_uri_scheme(
        context, "bojangles-resource", backend_resource_scheme_request, &state, NULL);
    WebKitSecurityManager *security_manager = webkit_web_context_get_security_manager(context);
    webkit_security_manager_register_uri_scheme_as_secure(security_manager, "bojangles-resource");
    webkit_security_manager_register_uri_scheme_as_cors_enabled(security_manager, "bojangles-resource");

    const char *upload_sandbox_dir = g_getenv("BOJANGLES_WPE_UPLOAD_DIR");
    if (upload_sandbox_dir && *upload_sandbox_dir)
        webkit_web_context_add_path_to_sandbox(context, upload_sandbox_dir, TRUE);

    WebKitSettings *settings = webkit_settings_new();
    if (!settings) {
        g_main_loop_unref(state.loop);
        g_object_unref(network_session);
        g_object_unref(context);
        munmap(framebuffer, framebuffer_length);
        return 5;
    }
    /* Keep the network and JavaScript-visible browser identity aligned while
     * avoiding a BoJangles-specific identifier. */
    webkit_settings_set_user_agent(settings, BOJANGLES_BROWSER_USER_AGENT);
    /* Keep EME invisible to ordinary pages. The trusted frontend may enable
     * Clear Key explicitly for this view after protected media is detected
     * and the operator accepts the DRM prompt. */
    webkit_settings_set_enable_encrypted_media(settings, FALSE);
    /* Use normal document focus navigation. Editable controls retain their
     * native caret; whole-document caret browsing would focus the first link
     * when the host surface activates, exposing focus-only skip links. */
    webkit_settings_set_enable_caret_browsing(settings, FALSE);
    /* The renderer never receives ambient system-clipboard authority. */
    webkit_settings_set_javascript_can_access_clipboard(settings, FALSE);

    /* Only explicit trusted per-site rules are installed on document load. */
    WebKitUserContentManager *site_rules_manager = webkit_user_content_manager_new();
    WebKitWebView *view = WEBKIT_WEB_VIEW(g_object_new(
        WEBKIT_TYPE_WEB_VIEW,
        "web-context", context,
        "network-session", network_session,
        "settings", settings,
        "user-content-manager", site_rules_manager,
        NULL));
    g_object_unref(settings);
    g_object_unref(site_rules_manager);
    if (!view) {
        g_main_loop_unref(state.loop);
        g_object_unref(network_session);
        g_object_unref(context);
        munmap(framebuffer, framebuffer_length);
        return 5;
    }
    state.view = view;

    WPEView *wpe_view = webkit_web_view_get_wpe_view(view);
    if (!wpe_view || !wpe_view_get_toplevel(wpe_view)) {
        g_object_unref(view);
        g_object_unref(network_session);
        g_object_unref(context);
        munmap(framebuffer, framebuffer_length);
        return 5;
    }
    wpe_toplevel_resize(wpe_view_get_toplevel(wpe_view), options.width, options.height);

    state.pending_resources = g_hash_table_new_full(
        g_direct_hash,
        g_direct_equal,
        NULL,
        bj_pending_resource_free);

    state.operations = g_cancellable_new();
    WebKitCookieManager *cookie_manager =
        webkit_network_session_get_cookie_manager(network_session);
    if (cookie_manager)
        g_signal_connect(cookie_manager, "changed",
                         G_CALLBACK(backend_cookie_changed), &state);
    g_signal_connect(wpe_view, "buffer-rendered", G_CALLBACK(backend_buffer_rendered), &state);
    g_signal_connect(network_session, "download-started",
                     G_CALLBACK(backend_download_started), &state);
    g_signal_connect(webkit_web_view_get_back_forward_list(view), "changed",
                     G_CALLBACK(backend_history_changed), &state);
    g_signal_connect(view, "permission-request", G_CALLBACK(bojangles_permission_request), &state);
    g_signal_connect(view, "run-file-chooser", G_CALLBACK(backend_run_file_chooser), &state);
    g_signal_connect(view, "script-dialog", G_CALLBACK(backend_script_dialog), &state);
    g_signal_connect(view, "resource-load-started", G_CALLBACK(backend_resource_started), &state);
    g_signal_connect(view, "context-menu", G_CALLBACK(backend_context_menu), &state);
    g_signal_connect(view, "notify::title", G_CALLBACK(backend_title_changed), &state);
    g_signal_connect(view, "notify::uri", G_CALLBACK(backend_uri_changed), &state);
    g_signal_connect(view, "decide-policy", G_CALLBACK(backend_navigation_policy), &state);
    g_signal_connect(view, "create", G_CALLBACK(backend_create_view), &state);
    g_signal_connect(view, "load-changed", G_CALLBACK(backend_load_changed), &state);
    g_signal_connect(view, "load-failed", G_CALLBACK(backend_load_failed), &state);
    g_signal_connect(view, "web-process-terminated", G_CALLBACK(backend_web_process_terminated), &state);
    guint ipc_source = g_unix_fd_add(options.control_fd, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
                  backend_ipc_ready, &state);

    guint resource_source = g_unix_fd_add(options.resource_fd, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
                  backend_ipc_ready, &state);

    if (!bj_send_packet(options.control_fd, BJ_READY, 0, NULL, 0)) {
        fputs("WPE_STAGE4B_FAIL ready-send\n", stderr);
        state.stopping = TRUE;
    } else {
        printf("WPE_STAGE4B_READY pid=%ld\n", (long)getpid());
        g_main_loop_run(state.loop);
    }

    GSource *ipc_watch = g_main_context_find_source_by_id(NULL, ipc_source);
    if (ipc_watch)
        g_source_destroy(ipc_watch);
    GSource *resource_watch = g_main_context_find_source_by_id(NULL, resource_source);
    if (resource_watch)
        g_source_destroy(resource_watch);
    g_cancellable_cancel(state.operations);
    if (state.pending_file_chooser) {
        webkit_file_chooser_request_cancel(state.pending_file_chooser);
        g_clear_object(&state.pending_file_chooser);
    }
    backend_clear_spelling_menu(&state);
    g_clear_pointer(&state.image_resources, g_ptr_array_unref);
    if (state.pending_script_dialog) {
        webkit_script_dialog_close(state.pending_script_dialog);
        webkit_script_dialog_unref(state.pending_script_dialog);
        state.pending_script_dialog = NULL;
    }

    if (state.pending_resources) {
        g_hash_table_destroy(state.pending_resources);
        state.pending_resources = NULL;
    }

    webkit_web_view_stop_loading(view);
    g_object_run_dispose(G_OBJECT(view));
    g_object_unref(view);
    g_object_unref(context);
    gboolean shutdown_ok = backend_finish_shutdown(TRUE);
    g_object_unref(network_session);
    shutdown_ok = backend_finish_shutdown(FALSE) && shutdown_ok;
    g_object_unref(state.operations);
    bj_clear_pending_document(&state);
    g_free(state.site_rule_document);
    g_free(state.site_rule_uri);
    g_free(state.site_rule_css);
    if (state.site_rule_sheet) webkit_user_style_sheet_unref(state.site_rule_sheet);
    g_free(state.document_id);
    g_free(state.uri);
    g_free(state.pending_main_navigation_uri);
    g_clear_pointer(&state.cookie_sync_snapshot, g_hash_table_unref);
    g_free(state.cookie_sync_document);
    g_clear_pointer(&state.subframe_origins, g_hash_table_unref);
    g_free(state.subframe_document);
    g_main_loop_unref(state.loop);
    munmap(state.framebuffer, state.framebuffer_length);
    close(options.control_fd);
    close(options.resource_fd);
    close(options.fb_fd);

    return state.stopping && shutdown_ok ? 0 : 5;
}


struct Stage6ProbeState {
    GMainLoop *loop;
    struct Stage6CookieHygiene hygiene;
    gboolean timed_out;
};

static void stage6_probe_verify_ready(GObject *source,
                                      GAsyncResult *result,
                                      gpointer user_data)
{
    struct Stage6ProbeState *probe = user_data;
    GError *error = NULL;
    GList *cookies = webkit_cookie_manager_get_all_cookies_finish(
        WEBKIT_COOKIE_MANAGER(source), result, &error);
    guint remaining = 0U;
    gboolean valid_present = FALSE;
    gboolean invalid_present = FALSE;

    if (!error) {
        for (GList *node = cookies; node; node = node->next) {
            SoupCookie *cookie = node->data;
            remaining++;
            const char *name = soup_cookie_get_name(cookie);
            if (name && strcmp(name, "stage6-valid") == 0)
                valid_present = TRUE;
            if (name && (strcmp(name, "__Secure-stage6-bad") == 0 ||
                         strcmp(name, "__Host-stage6-bad") == 0))
                invalid_present = TRUE;
        }
    }
    if (cookies)
        g_list_free_full(cookies, (GDestroyNotify)soup_cookie_free);
    if (error)
        g_error_free(error);

    printf("WPE_STAGE6_COOKIE_HYGIENE changed=%u audits=%u deleted=%u remaining=%u\n",
           probe->hygiene.changed_count,
           probe->hygiene.audit_count,
           probe->hygiene.delete_count,
           remaining);
    /* Invalid prefix cookies may be rejected by WebKit before they ever enter
     * CookieManager storage.  That is already a safe outcome.  Stage 6
     * therefore certifies the observable invariant: the change signal fired,
     * the event-driven audit ran, the valid cookie survived, and no invalid
     * probe cookie remains.  delete_count stays diagnostic for the case where
     * WebKit admits state that BoJangles must remove. */
    if (!probe->timed_out && !error && valid_present && !invalid_present &&
        remaining == 1U && probe->hygiene.changed_count > 0U &&
        probe->hygiene.audit_count > 0U) {
        fputs("WPE_STAGE6_COOKIE_HYGIENE=PASS\n", stdout);
    } else {
        fputs("WPE_STAGE6_COOKIE_HYGIENE=FAIL\n", stderr);
        probe->timed_out = TRUE;
    }
    g_main_loop_quit(probe->loop);
}

static gboolean stage6_probe_verify(gpointer user_data)
{
    struct Stage6ProbeState *probe = user_data;
    webkit_cookie_manager_get_all_cookies(
        probe->hygiene.manager, NULL, stage6_probe_verify_ready, probe);
    return G_SOURCE_REMOVE;
}

static gboolean stage6_probe_timeout(gpointer user_data)
{
    struct Stage6ProbeState *probe = user_data;
    probe->timed_out = TRUE;
    fputs("WPE_STAGE6_COOKIE_HYGIENE=TIMEOUT\n", stderr);
    g_main_loop_quit(probe->loop);
    return G_SOURCE_REMOVE;
}

static int run_stage6_cookie_probe(void)
{
    WebKitNetworkSession *network_session = webkit_network_session_new_ephemeral();
    if (!network_session)
        return 6;

    struct Stage6ProbeState probe = {
        .loop = g_main_loop_new(NULL, FALSE),
        .timed_out = FALSE,
    };
    if (!stage6_configure_network_session(network_session, &probe.hygiene)) {
        g_main_loop_unref(probe.loop);
        g_object_unref(network_session);
        return 6;
    }

    printf("WPE_STAGE6_ITP enabled=%d ephemeral=%d persistent_credentials=%d\n",
           webkit_network_session_get_itp_enabled(network_session) ? 1 : 0,
           webkit_network_session_is_ephemeral(network_session) ? 1 : 0,
           webkit_network_session_get_persistent_credential_storage_enabled(network_session) ? 1 : 0);

    SoupCookie *valid = soup_cookie_new(
        "stage6-valid", "ok", "stage6.invalid", "/", -1);
    soup_cookie_set_same_site_policy(valid, SOUP_SAME_SITE_POLICY_LAX);
    webkit_cookie_manager_add_cookie(probe.hygiene.manager, valid, NULL, NULL, NULL);
    soup_cookie_free(valid);

    SoupCookie *bad_secure = soup_cookie_new(
        "__Secure-stage6-bad", "x", "stage6.invalid", "/", -1);
    soup_cookie_set_same_site_policy(bad_secure, SOUP_SAME_SITE_POLICY_LAX);
    webkit_cookie_manager_add_cookie(probe.hygiene.manager, bad_secure, NULL, NULL, NULL);
    soup_cookie_free(bad_secure);

    SoupCookie *bad_host = soup_cookie_new(
        "__Host-stage6-bad", "x", ".stage6.invalid", "/wrong", -1);
    soup_cookie_set_secure(bad_host, TRUE);
    soup_cookie_set_same_site_policy(bad_host, SOUP_SAME_SITE_POLICY_LAX);
    webkit_cookie_manager_add_cookie(probe.hygiene.manager, bad_host, NULL, NULL, NULL);
    soup_cookie_free(bad_host);

    g_timeout_add(1500, stage6_probe_verify, &probe);
    g_timeout_add_seconds(6, stage6_probe_timeout, &probe);
    g_main_loop_run(probe.loop);

    gboolean ok = !probe.timed_out;
    g_main_loop_unref(probe.loop);
    g_object_unref(network_session);
    return ok ? 0 : 6;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    /* The outer sandbox is entered before WebKit initialization.  Stage 5B also
     * unshares the network namespace: WPE has no direct host/origin route.
     * Lifecycle IPC, framebuffer, and sealed document fds are the only admitted
     * host-created data-plane handles. */
    enter_outer_sandbox(argc, argv);

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--stage6-cookie-probe") == 0)
            return run_stage6_cookie_probe();
    }

    struct BackendOptions options;
    gboolean backend_requested = FALSE;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--control-fd") == 0 || strcmp(argv[i], "--resource-fd") == 0 || strcmp(argv[i], "--fb-fd") == 0) {
            backend_requested = TRUE;
            break;
        }
    }
    if (backend_requested) {
        if (!parse_backend_options(argc, argv, &options)) {
            fputs("WPE_STAGE4B_FAIL incomplete-backend-arguments\n", stderr);
            return 5;
        }
        return run_stage4b_backend(argc, argv);
    }
    return run_stage4a_probe(argc, argv);
}
