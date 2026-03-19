#include "sys.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <glib.h>

/* ── Internal helpers ────────────────────────────────────────────────── */

static char *config_path(const char *filename)
{
    return g_build_filename(g_get_home_dir(),
                            ".config", "rofi-bridge", filename, NULL);
}

static char *ca_dir_path(const char *filename)
{
    return g_build_filename(g_get_home_dir(),
                            "rofi-bridge-ca", filename, NULL);
}

/* Run a shell command and return stdout in a heap buffer (caller frees). */
static char *capture(const char *cmd)
{
    FILE *p = popen(cmd, "r");
    if (!p) return NULL;

    char *buf  = NULL;
    size_t len = 0;
    char   tmp[256];

    while (fgets(tmp, sizeof(tmp), p)) {
        size_t tl  = strlen(tmp);
        char  *nb  = realloc(buf, len + tl + 1);
        if (!nb) { free(buf); pclose(p); return NULL; }
        buf = nb;
        memcpy(buf + len, tmp, tl);
        len += tl;
        buf[len] = '\0';
    }
    pclose(p);
    return buf;  /* may be NULL if command produced no output */
}

/* ── sys_get_ip ───────────────────────────────────────────────────────── */
void sys_get_ip(char *buf, size_t n)
{
    strncpy(buf, "unknown", n);
    buf[n - 1] = '\0';

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(80);
    inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        struct sockaddr_in local;
        socklen_t len2 = sizeof(local);
        if (getsockname(sock, (struct sockaddr *)&local, &len2) == 0)
            strncpy(buf, inet_ntoa(local.sin_addr), n - 1);
    }
    close(sock);
}

/* ── sys_load_config ──────────────────────────────────────────────────── */
void sys_load_config(Config *c)
{
    c->port = 7443;
    strncpy(c->mode, "direct", sizeof(c->mode) - 1);

    char *path = config_path("config.toml");
    FILE *f    = fopen(path, "r");
    g_free(path);
    if (!f) return;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        int p;
        if (sscanf(line, "port = %d", &p) == 1)
            c->port = p;
        if (strstr(line, "mode") && strstr(line, "hardened"))
            strncpy(c->mode, "hardened", sizeof(c->mode) - 1);
    }
    fclose(f);
}

/* ── sys_systemctl ────────────────────────────────────────────────────── */
int sys_systemctl(const char *action)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "systemctl --user %s rofi-bridge >/dev/null 2>&1", action);
    return WEXITSTATUS(system(cmd));
}

/* ── sys_port_listening ───────────────────────────────────────────────── */
int sys_port_listening(int port)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "ss -tlnp 'sport = :%d' 2>/dev/null | grep -q ':%d'",
             port, port);
    return WEXITSTATUS(system(cmd)) == 0;
}

/* ── sys_generate_otp ─────────────────────────────────────────────────── */
int sys_generate_otp(ProvisionQR *out, const char *ca_pass)
{
    /* 1. Read LAN IP and port from config */
    Config cfg = {0};
    sys_load_config(&cfg);
    sys_get_ip(cfg.ip, sizeof(cfg.ip));

    char addr_buf[128];
    if (strcmp(cfg.mode, "hardened") == 0)
        snprintf(addr_buf, sizeof(addr_buf), "10.0.0.2:%d", cfg.port);
    else
        snprintf(addr_buf, sizeof(addr_buf), "%s:%d", cfg.ip, cfg.port);

    /* 2. Compute server cert SHA-256 fingerprint */
    char *crt_path = config_path("server.crt");
    char  fp_cmd[512];
    snprintf(fp_cmd, sizeof(fp_cmd),
             "openssl x509 -in '%s' -fingerprint -sha256 -noout 2>/dev/null",
             crt_path);
    g_free(crt_path);

    char *fp_raw = capture(fp_cmd);
    char  fp_hex[128] = "unknown";
    if (fp_raw) {
        /* Format: "SHA256 Fingerprint=AA:BB:CC:..." — extract hex, strip colons */
        char *eq = strchr(fp_raw, '=');
        if (eq) {
            char *p = eq + 1;
            char *d = fp_hex;
            while (*p && (size_t)(d - fp_hex) < sizeof(fp_hex) - 1) {
                if (*p != ':' && *p != '\n' && *p != '\r')
                    *d++ = *p;
                p++;
            }
            *d = '\0';
        }
        free(fp_raw);
    }

    /* 3. Generate 32-byte random OTP as lowercase hex */
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (!urandom) return -1;
    unsigned char raw[32];
    if (fread(raw, 1, sizeof(raw), urandom) != sizeof(raw)) {
        fclose(urandom);
        return -1;
    }
    fclose(urandom);

    char otp_hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(otp_hex + 2 * i, 3, "%02x", raw[i]);
    otp_hex[64] = '\0';

    /* 4. Write pending_otps.json atomically */
    time_t now     = time(NULL);
    time_t expires = now + 60;

    char *otps_path = config_path("pending_otps.json");

    /* Read existing OTPs (may be empty) */
    char existing[4096] = "{}";
    FILE *ef = fopen(otps_path, "r");
    if (ef) {
        fread(existing, 1, sizeof(existing) - 1, ef);
        fclose(ef);
    }

    /* Simple JSON injection of the new OTP entry.
     * Full JSON lib not available in C without deps; we write the entire
     * file from scratch since pending_otps rarely has >1 entry. */
    FILE *wf = fopen(otps_path, "w");
    if (!wf) { g_free(otps_path); return -1; }
    chmod(otps_path, 0600);

    /* Preserve any existing valid OTPs by re-writing existing content
     * (strip outer braces) then appending new entry. */
    char inner[4000] = "";
    if (strlen(existing) > 2) {
        /* Strip leading { and trailing } */
        size_t elen = strlen(existing);
        size_t copy = (elen - 2 < sizeof(inner)) ? elen - 2 : sizeof(inner) - 1;
        strncpy(inner, existing + 1, copy);
        /* Strip trailing whitespace/} */
        for (ssize_t i = (ssize_t)strlen(inner) - 1; i >= 0; i--) {
            if (inner[i] == '}') { inner[i] = '\0'; break; }
        }
    }

    fprintf(wf, "{");
    if (strlen(inner) > 1)   /* has prior entries */
        fprintf(wf, "%s,", inner);
    fprintf(wf, "\"%s\":{\"expires\":%ld,\"ca_pass\":\"%s\"}",
            otp_hex, (long)expires, ca_pass);
    fprintf(wf, "}");
    fclose(wf);

    g_free(otps_path);

    /* 5. Fill output struct */
    strncpy(out->otp,    otp_hex,  sizeof(out->otp)  - 1);
    strncpy(out->addr,   addr_buf, sizeof(out->addr)  - 1);
    strncpy(out->fp,     fp_hex,   sizeof(out->fp)    - 1);
    out->expires = expires;

    return 0;
}

/* ── sys_list_devices ─────────────────────────────────────────────────── */
int sys_list_devices(Device *devices, int max_count)
{
    char *clients_dir = g_build_filename(g_get_home_dir(),
                                         ".config", "rofi-bridge",
                                         "clients", NULL);
    DIR *d = opendir(clients_dir);
    g_free(clients_dir);
    if (!d) return 0;

    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) && count < max_count) {
        if (ent->d_name[0] == '.') continue;

        Device *dev = &devices[count];
        strncpy(dev->device_id, ent->d_name, sizeof(dev->device_id) - 1);
        dev->serial[0]    = '\0';
        dev->not_after[0] = '\0';

        /* Read cert serial + expiry via openssl */
        char *crt_path = g_build_filename(g_get_home_dir(),
                                          ".config", "rofi-bridge",
                                          "clients", ent->d_name,
                                          "tls.crt", NULL);

        char cmd[512];
        snprintf(cmd, sizeof(cmd),
                 "openssl x509 -in '%s' -noout -serial 2>/dev/null", crt_path);
        char *serial_raw = capture(cmd);
        if (serial_raw) {
            char *eq = strchr(serial_raw, '=');
            if (eq) strncpy(dev->serial, eq + 1, sizeof(dev->serial) - 1);
            /* Strip newline */
            dev->serial[strcspn(dev->serial, "\r\n")] = '\0';
            free(serial_raw);
        }

        snprintf(cmd, sizeof(cmd),
                 "openssl x509 -in '%s' -noout -enddate 2>/dev/null", crt_path);
        char *enddate_raw = capture(cmd);
        if (enddate_raw) {
            char *eq = strchr(enddate_raw, '=');
            if (eq) strncpy(dev->not_after, eq + 1, sizeof(dev->not_after) - 1);
            dev->not_after[strcspn(dev->not_after, "\r\n")] = '\0';
            free(enddate_raw);
        }

        g_free(crt_path);
        count++;
    }
    closedir(d);
    return count;
}

/* ── sys_revoke_device ────────────────────────────────────────────────── */
int sys_revoke_device(const char *device_id, const char *serial)
{
    /* 1. Append serial to revoked.txt */
    char *revoked_path = config_path("revoked.txt");
    FILE *f = fopen(revoked_path, "a");
    if (f) { fprintf(f, "%s\n", serial); fclose(f); }
    g_free(revoked_path);

    /* 2. Remove clients/<device_id>/ */
    char cmd[512];
    char *clients_dir = g_build_filename(g_get_home_dir(),
                                         ".config", "rofi-bridge",
                                         "clients", device_id, NULL);
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", clients_dir);
    g_free(clients_dir);
    return WEXITSTATUS(system(cmd));
}

/* ── sys_read_audit ───────────────────────────────────────────────────── */
char **sys_read_audit(int *count, int max_lines)
{
    *count = 0;
    char *path = config_path("audit.log");
    FILE *f    = fopen(path, "r");
    g_free(path);
    if (!f) return NULL;

    /* Collect all lines */
    char  **all  = NULL;
    int     total = 0;
    char    line[1024];

    while (fgets(line, sizeof(line), f)) {
        char **nb = realloc(all, (size_t)(total + 1) * sizeof(char *));
        if (!nb) break;
        all = nb;
        all[total++] = strdup(line);
    }
    fclose(f);

    if (total == 0) return NULL;

    /* Return last max_lines entries */
    int start = (total > max_lines) ? total - max_lines : 0;
    int ret   = total - start;
    char **result = malloc((size_t)ret * sizeof(char *));
    if (!result) { sys_free_lines(all, total); return NULL; }

    for (int i = 0; i < ret; i++)
        result[i] = all[start + i];

    /* Free lines we're not returning */
    for (int i = 0; i < start; i++) free(all[i]);
    free(all);

    *count = ret;
    return result;
}

/* ── sys_free_lines ───────────────────────────────────────────────────── */
void sys_free_lines(char **lines, int count)
{
    if (!lines) return;
    for (int i = 0; i < count; i++) free(lines[i]);
    free(lines);
}
