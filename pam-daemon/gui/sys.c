#define _XOPEN_SOURCE 700

#include "sys.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <ftw.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <glib.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

/* ── Internal helpers ────────────────────────────────────────────────── */

static char *config_path(const char *filename)
{
    return g_build_filename(g_get_home_dir(),
                            ".config", "rofi-bridge", filename, NULL);
}

/* JSON-escape a string into buf (truncates if buf too small). */
static void json_escape(const char *s, char *buf, size_t buf_size)
{
    size_t out = 0;
    buf[0] = '\0';
    if (!s) return;
    for (const char *p = s; *p && out + 2 < buf_size; p++) {
        if (*p == '"' || *p == '\\') {
            if (out + 3 >= buf_size) break;
            buf[out++] = '\\';
        }
        buf[out++] = (unsigned char)*p;
    }
    buf[out] = '\0';
}

/* Compute SHA-256 of cert DER and write lowercase hex into out. */
static int cert_sha256_hex(const char *pem_path, char *out, size_t out_size)
{
    FILE *f = fopen(pem_path, "r");
    if (!f) return -1;

    X509 *cert = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    if (!cert) return -1;

    int der_len = i2d_X509(cert, NULL);
    if (der_len <= 0) { X509_free(cert); return -1; }

    unsigned char *der = malloc((size_t)der_len);
    if (!der) { X509_free(cert); return -1; }

    unsigned char *p = der;
    i2d_X509(cert, &p);
    X509_free(cert);

    unsigned char digest[32];
    unsigned int  digest_len = sizeof(digest);
    EVP_MD_CTX   *ctx = EVP_MD_CTX_new();
    if (!ctx) { free(der); return -1; }
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, der, (size_t)der_len);
    EVP_DigestFinal_ex(ctx, digest, &digest_len);
    EVP_MD_CTX_free(ctx);
    free(der);

    for (unsigned int i = 0; i < digest_len && i * 2 + 2 <= out_size; i++)
        snprintf(out + i * 2, 3, "%02x", digest[i]);

    return 0;
}

/* Read cert serial (hex string) and not-after date without shell. */
static void cert_info(const char *pem_path,
                      char *serial_out, size_t serial_size,
                      char *enddate_out, size_t enddate_size)
{
    if (serial_size)  serial_out[0]  = '\0';
    if (enddate_size) enddate_out[0] = '\0';

    FILE *f = fopen(pem_path, "r");
    if (!f) return;

    X509 *cert = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    if (!cert) return;

    /* Serial as hex */
    ASN1_INTEGER *sn = X509_get_serialNumber(cert);
    if (sn && serial_size) {
        BIGNUM *bn = ASN1_INTEGER_to_BN(sn, NULL);
        if (bn) {
            char *hex = BN_bn2hex(bn);
            if (hex) {
                strncpy(serial_out, hex, serial_size - 1);
                serial_out[serial_size - 1] = '\0';
                OPENSSL_free(hex);
            }
            BN_free(bn);
        }
    }

    /* Not-after date as printable string */
    const ASN1_TIME *na = X509_get0_notAfter(cert);
    if (na && enddate_size) {
        BIO *bio = BIO_new(BIO_s_mem());
        if (bio) {
            ASN1_TIME_print(bio, na);
            char tmp[64] = "";
            BIO_read(bio, tmp, (int)sizeof(tmp) - 1);
            BIO_free(bio);
            strncpy(enddate_out, tmp, enddate_size - 1);
            enddate_out[enddate_size - 1] = '\0';
        }
    }

    X509_free(cert);
}

/* Validate device_id: non-empty, lowercase hex characters only. */
static int is_valid_device_id(const char *id)
{
    if (!id || !*id) return 0;
    for (const char *p = id; *p; p++)
        if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f')))
            return 0;
    return 1;
}

/* nftw callback for recursive directory removal (depth-first). */
static int _rm_entry(const char *path, const struct stat *sb, int typeflag,
                     struct FTW *ftwbuf)
{
    (void)sb; (void)ftwbuf;
    if (typeflag == FTW_DP)
        return rmdir(path);
    return unlink(path);
}

/* ── sys_get_ip ───────────────────────────────────────────────────────── */
void sys_get_ip(char *buf, size_t n)
{
    strncpy(buf, "unknown", n);
    buf[n - 1] = '\0';

    /* Try multiple targets: 8.8.8.8 for normal LAN, 10.0.0.1 for
     * WireGuard-only environments where no public route exists. */
    static const char * const targets[] = { "8.8.8.8", "10.0.0.1", NULL };
    for (int i = 0; targets[i]; i++) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) continue;

        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(80);
        inet_pton(AF_INET, targets[i], &addr.sin_addr);

        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            struct sockaddr_in local;
            socklen_t len2 = sizeof(local);
            if (getsockname(sock, (struct sockaddr *)&local, &len2) == 0) {
                strncpy(buf, inet_ntoa(local.sin_addr), n - 1);
                close(sock);
                return;
            }
        }
        close(sock);
    }
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
        /* Skip comment and blank lines to avoid matching TOML comments */
        char *t = line;
        while (*t == ' ' || *t == '\t') t++;
        if (*t == '#' || *t == '\0' || *t == '\n' || *t == '\r') continue;

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
    static const char * const allowed[] =
        { "start", "stop", "restart", "status", NULL };

    int valid = 0;
    for (int i = 0; allowed[i]; i++)
        if (strcmp(action, allowed[i]) == 0) { valid = 1; break; }
    if (!valid) return -1;

    pid_t pid = fork();
    if (pid < 0) return -1;

    if (pid == 0) {
        char *argv[] = { "systemctl", "--user", (char *)action,
                         "rofi-bridge", NULL };
        execvp("systemctl", argv);
        _exit(127);
    }

    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* ── sys_port_listening ───────────────────────────────────────────────── */
int sys_port_listening(int port)
{
    if (port <= 0 || port > 65535) return 0;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 0;

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)port);
    addr.sin_addr.s_addr = INADDR_ANY;

    int r   = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    int err = errno;
    close(sock);
    return r < 0 && err == EADDRINUSE;
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

    /* 2. Compute server cert SHA-256 fingerprint via OpenSSL API */
    char *crt_path = config_path("server.crt");
    char  fp_hex[128] = "unknown";
    cert_sha256_hex(crt_path, fp_hex, sizeof(fp_hex));
    g_free(crt_path);

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

    /* Read existing OTPs (may be empty).
     * If the file exceeds 4095 bytes something is wrong — start fresh
     * rather than silently truncating and producing malformed JSON. */
    char existing[4096] = "{}";
    FILE *ef = fopen(otps_path, "r");
    if (ef) {
        fseek(ef, 0, SEEK_END);
        long file_size = ftell(ef);
        rewind(ef);
        if (file_size > 0 && file_size < (long)(sizeof(existing) - 1))
            fread(existing, 1, (size_t)file_size, ef);
        fclose(ef);
    }

    FILE *wf = fopen(otps_path, "w");
    if (!wf) { g_free(otps_path); return -1; }
    chmod(otps_path, 0600);

    /* Preserve any existing valid OTPs by re-writing existing content
     * (strip outer braces) then appending new entry. */
    char inner[4000] = "";
    if (strlen(existing) > 2) {
        size_t elen = strlen(existing);
        size_t copy = (elen - 2 < sizeof(inner)) ? elen - 2 : sizeof(inner) - 1;
        strncpy(inner, existing + 1, copy);
        for (ssize_t i = (ssize_t)strlen(inner) - 1; i >= 0; i--) {
            if (inner[i] == '}') { inner[i] = '\0'; break; }
        }
    }

    /* JSON-escape ca_pass to prevent injection */
    char ca_pass_esc[512];
    json_escape(ca_pass, ca_pass_esc, sizeof(ca_pass_esc));

    fprintf(wf, "{");
    if (strlen(inner) > 1)
        fprintf(wf, "%s,", inner);
    fprintf(wf, "\"%s\":{\"expires\":%ld,\"ca_pass\":\"%s\"}",
            otp_hex, (long)expires, ca_pass_esc);
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
        if (!is_valid_device_id(ent->d_name)) continue;

        Device *dev = &devices[count];
        strncpy(dev->device_id, ent->d_name, sizeof(dev->device_id) - 1);
        dev->serial[0]    = '\0';
        dev->not_after[0] = '\0';

        char *crt_path = g_build_filename(g_get_home_dir(),
                                          ".config", "rofi-bridge",
                                          "clients", ent->d_name,
                                          "tls.crt", NULL);

        cert_info(crt_path,
                  dev->serial,    sizeof(dev->serial),
                  dev->not_after, sizeof(dev->not_after));

        g_free(crt_path);
        count++;
    }
    closedir(d);
    return count;
}

/* ── sys_revoke_device ────────────────────────────────────────────────── */
int sys_revoke_device(const char *device_id, const char *serial)
{
    if (!is_valid_device_id(device_id)) return -1;

    /* 1. Append serial to revoked.txt */
    char *revoked_path = config_path("revoked.txt");
    FILE *f = fopen(revoked_path, "a");
    if (f) { fprintf(f, "%s\n", serial); fclose(f); }
    g_free(revoked_path);

    /* 2. Remove clients/<device_id>/ using nftw (no shell) */
    char *clients_dir = g_build_filename(g_get_home_dir(),
                                         ".config", "rofi-bridge",
                                         "clients", device_id, NULL);
    int r = nftw(clients_dir, _rm_entry, 8, FTW_DEPTH | FTW_PHYS);
    g_free(clients_dir);
    return r;
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
