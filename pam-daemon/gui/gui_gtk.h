#pragma once

#include <gtk/gtk.h>
#include "sys.h"

typedef struct _App App;

/* Passed as closure data to per-device revoke callbacks. */
typedef struct {
    char device_id[64];
    char serial[64];
    App *app;
} DeviceRevoke;

struct _App {
    GtkWidget *window;

    /* ── Status tab ─────────────────────────────────────────────────── */
    GtkWidget *lbl_ip;
    GtkWidget *lbl_port;
    GtkWidget *lbl_mode;
    GtkWidget *dot_daemon;
    GtkWidget *lbl_daemon;
    GtkWidget *dot_proc;
    GtkWidget *lbl_proc;

    /* ── Provision tab ──────────────────────────────────────────────── */
    GtkWidget   *entry_ca_pass;
    GtkWidget   *lbl_prov_addr;
    GtkWidget   *lbl_prov_otp;
    GtkWidget   *lbl_prov_fp;
    GtkWidget   *lbl_prov_ttl;
    GtkWidget   *da_qr;          /* GtkDrawingArea for QR code          */
    void        *qr_current;     /* QRcode* — void* avoids qrencode dep */
    ProvisionQR  prov;
    guint        prov_timer_id;

    /* ── Devices tab ────────────────────────────────────────────────── */
    GtkWidget *devices_box;      /* GtkBox filled by refresh_devices()  */

    /* ── Audit tab ──────────────────────────────────────────────────── */
    GtkWidget *audit_view;       /* GtkTextView (read-only)             */

    Config cfg;
};

void activate(GtkApplication *gapp, gpointer user_data);
