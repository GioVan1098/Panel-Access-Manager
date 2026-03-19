#pragma once

#include <stddef.h>
#include <time.h>

/* ── Config ─────────────────────────────────────────────────────────── */
typedef struct {
    char ip[64];
    int  port;
    char mode[16];   /* "direct" | "hardened" */
} Config;

void sys_get_ip(char *buf, size_t n);
void sys_load_config(Config *c);

/* ── Daemon control ──────────────────────────────────────────────────── */
int  sys_systemctl(const char *action);   /* returns 0 on success */
int  sys_port_listening(int port);        /* returns 1 if listening */

/* ── Provisioning ────────────────────────────────────────────────────── */
typedef struct {
    char otp[65];      /* 32-byte random, hex-encoded */
    char addr[128];    /* "ip:port" for QR payload */
    char fp[128];      /* server cert SHA-256 fingerprint, hex */
    time_t expires;    /* unix timestamp (now + 60) */
} ProvisionQR;

/*
 * Generate a new OTP, compute server cert fingerprint, write to
 * pending_otps.json with ca_pass embedded. Returns 0 on success.
 */
int sys_generate_otp(ProvisionQR *out, const char *ca_pass);

/* ── Device list ─────────────────────────────────────────────────────── */
typedef struct {
    char device_id[64];
    char serial[64];
    char not_after[32];   /* cert expiry date string */
} Device;

/* Returns count of devices found (max = max_count). */
int sys_list_devices(Device *devices, int max_count);

/* Revoke: append serial to revoked.txt, remove clients/<device_id>/. */
int sys_revoke_device(const char *device_id, const char *serial);

/* ── Audit log ───────────────────────────────────────────────────────── */
/* Returns a heap-allocated array of *count lines. Caller frees each line
 * and the array itself with sys_free_lines(). */
char **sys_read_audit(int *count, int max_lines);
void   sys_free_lines(char **lines, int count);
