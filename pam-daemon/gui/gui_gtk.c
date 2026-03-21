#include "gui_gtk.h"
#include "qr.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/wait.h>

/* ── CSS (Catppuccin Mocha) ──────────────────────────────────────────── */

static const char *CSS =
    "window, dialog { background-color: #1e1e2e; }"
    "notebook { background-color: #1e1e2e; }"
    "notebook > header { background-color: #1e1e2e; }"
    "notebook > header > tabs > tab {"
    "    background-color: #313244; color: #cdd6f4;"
    "    padding: 4px 14px; }"
    "notebook > header > tabs > tab:checked {"
    "    background-color: #1e1e2e; color: #89b4fa; }"
    "label { color: #cdd6f4; font-size: 10pt; }"
    "label.title  { color: #89b4fa; font-size: 13pt; font-weight: bold; }"
    "label.accent { color: #89b4fa; }"
    "label.green  { color: #a6e3a1; font-size: 12pt; }"
    "label.red    { color: #f38ba8; font-size: 12pt; }"
    "label.yellow { color: #f9e2af; font-size: 12pt; }"
    "label.ttl         { color: #cba6f7; font-size: 11pt; font-weight: bold; }"
    "label.ttl-expired { color: #f38ba8; font-size: 11pt; font-weight: bold; }"
    "button { background: #313244; color: #cdd6f4; border: none;"
    "         border-radius: 4px; padding: 4px 10px; font-size: 10pt; }"
    "button:hover  { background: #585b70; }"
    "button.accent { color: #89b4fa; }"
    "button.green  { color: #a6e3a1; }"
    "button.red    { color: #f38ba8; }"
    "button.close  { background: transparent; color: #6c7086;"
    "                font-size: 14pt; padding: 0 4px; }"
    "button.close:hover { color: #f38ba8; background: transparent; }"
    "separator { background-color: #45475a; min-height: 1px; }"
    "entry { background: #313244; color: #cdd6f4;"
    "        border: 1px solid #45475a; border-radius: 4px;"
    "        caret-color: #cdd6f4; }"
    "textview { background-color: #181825; color: #cdd6f4;"
    "           font-family: monospace; font-size: 9pt; }"
    "textview text { background-color: #181825; color: #cdd6f4; }"
    ".dialog-vbox, .dialog-action-area { background-color: #1e1e2e; }";

/* ── Generic helpers ──────────────────────────────────────────────────── */

static void set_dot(GtkWidget *dot, const char *cls)
{
    GtkStyleContext *ctx = gtk_widget_get_style_context(dot);
    gtk_style_context_remove_class(ctx, "green");
    gtk_style_context_remove_class(ctx, "red");
    gtk_style_context_remove_class(ctx, "yellow");
    gtk_style_context_add_class(ctx, cls);
}

static void show_dialog(GtkWindow *parent, const char *title,
                        const char *msg, gboolean is_error)
{
    GtkWidget *dlg = gtk_dialog_new_with_buttons(title, parent,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "OK", GTK_RESPONSE_OK, NULL);

    GtkWidget *box = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_container_set_border_width(GTK_CONTAINER(box), 20);

    GtkWidget *tag = gtk_label_new(is_error ? "Error" : "Info");
    gtk_style_context_add_class(gtk_widget_get_style_context(tag),
                                is_error ? "red" : "accent");
    gtk_widget_set_margin_bottom(tag, 8);
    gtk_box_pack_start(GTK_BOX(box), tag, FALSE, FALSE, 0);

    GtkWidget *lbl = gtk_label_new(msg);
    gtk_label_set_line_wrap(GTK_LABEL(lbl), TRUE);
    gtk_label_set_max_width_chars(GTK_LABEL(lbl), 44);
    gtk_label_set_justify(GTK_LABEL(lbl), GTK_JUSTIFY_CENTER);
    gtk_box_pack_start(GTK_BOX(box), lbl, FALSE, FALSE, 0);

    gtk_widget_show_all(dlg);
    gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);
}

static GtkWidget *make_sep(void)
{
    GtkWidget *sep = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_widget_set_margin_top(sep, 6);
    gtk_widget_set_margin_bottom(sep, 6);
    return sep;
}

static GtkWidget *make_btn(const char *label, const char *css_class,
                           GCallback cb, gpointer data)
{
    GtkWidget *btn = gtk_button_new_with_label(label);
    if (css_class)
        gtk_style_context_add_class(gtk_widget_get_style_context(btn), css_class);
    if (cb)
        g_signal_connect(btn, "clicked", cb, data);
    return btn;
}

static GtkWidget *make_dot(const char *init_class)
{
    GtkWidget *lbl = gtk_label_new("●");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl), init_class);
    gtk_widget_set_halign(lbl, GTK_ALIGN_START);
    return lbl;
}

/* ── Status tab ───────────────────────────────────────────────────────── */

static void refresh_state(App *a)
{
    sys_get_ip(a->cfg.ip, sizeof(a->cfg.ip));
    sys_load_config(&a->cfg);

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", a->cfg.port);
    gtk_label_set_text(GTK_LABEL(a->lbl_ip),   a->cfg.ip);
    gtk_label_set_text(GTK_LABEL(a->lbl_port),  port_str);
    gtk_label_set_text(GTK_LABEL(a->lbl_mode),  a->cfg.mode);
}

static void update_daemon_status(App *a)
{
    if (sys_systemctl("is-active") == 0) {
        gtk_label_set_text(GTK_LABEL(a->lbl_daemon), "Active");
        set_dot(a->dot_daemon, "green");
    } else {
        gtk_label_set_text(GTK_LABEL(a->lbl_daemon), "Inactive");
        set_dot(a->dot_daemon, "red");
    }

    if (sys_port_listening(a->cfg.port)) {
        gtk_label_set_text(GTK_LABEL(a->lbl_proc), "Listening");
        set_dot(a->dot_proc, "green");
    } else {
        gtk_label_set_text(GTK_LABEL(a->lbl_proc), "Not listening");
        set_dot(a->dot_proc, "red");
    }
}

static void on_check(GtkButton *b, App *a)   { (void)b; update_daemon_status(a); }

static void on_start(GtkButton *b, App *a)
{
    (void)b;
    if (sys_systemctl("start") != 0)
        show_dialog(GTK_WINDOW(a->window), "Error",
                    "Failed to start daemon.\nCheck: journalctl --user -u rofi-bridge", TRUE);
    update_daemon_status(a);
}

static void on_stop(GtkButton *b, App *a)
{
    (void)b;
    if (sys_systemctl("stop") != 0)
        show_dialog(GTK_WINDOW(a->window), "Error", "Failed to stop daemon.", TRUE);
    update_daemon_status(a);
}

static void on_restart(GtkButton *b, App *a)
{
    (void)b;
    refresh_state(a);
    if (sys_systemctl("restart") != 0)
        show_dialog(GTK_WINDOW(a->window), "Error", "Failed to restart daemon.", TRUE);
    update_daemon_status(a);
}

static void on_open_port(GtkButton *b, App *a)
{
    (void)b;
    int r = WEXITSTATUS(system("/usr/lib/rofi-bridge/ipt-helper open 2>/dev/null"));
    if (r != 0)
        show_dialog(GTK_WINDOW(a->window), "Error",
                    "ipt-helper open failed.\n"
                    "Verify setup.sh was run and\n"
                    "ipt-helper has cap_net_admin.", TRUE);
    update_daemon_status(a);
}

static void on_close_port(GtkButton *b, App *a)
{
    (void)b;
    (void)WEXITSTATUS(system("/usr/lib/rofi-bridge/ipt-helper close 2>/dev/null"));
    update_daemon_status(a);
}

static GtkWidget *build_status_tab(App *a)
{
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 16);

    /* Header row */
    GtkWidget *hdr   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    GtkWidget *title = gtk_label_new("PAM Manager");
    gtk_style_context_add_class(gtk_widget_get_style_context(title), "title");
    gtk_widget_set_hexpand(title, TRUE);
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    GtkWidget *close_btn = gtk_button_new_with_label("×");
    gtk_style_context_add_class(gtk_widget_get_style_context(close_btn), "close");
    g_signal_connect_swapped(close_btn, "clicked",
                             G_CALLBACK(gtk_widget_destroy), a->window);
    gtk_box_pack_start(GTK_BOX(hdr), title,     TRUE,  TRUE,  0);
    gtk_box_pack_start(GTK_BOX(hdr), close_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), hdr, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), make_sep(), FALSE, FALSE, 0);

    /* IP / Port / Mode info */
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 4);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 8);

    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("IP:"),   0, 0, 1, 1);
    a->lbl_ip = gtk_label_new("…");
    gtk_style_context_add_class(gtk_widget_get_style_context(a->lbl_ip), "accent");
    gtk_widget_set_halign(a->lbl_ip, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), a->lbl_ip, 1, 0, 1, 1);

    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Port:"), 2, 0, 1, 1);
    a->lbl_port = gtk_label_new("…");
    gtk_style_context_add_class(gtk_widget_get_style_context(a->lbl_port), "accent");
    gtk_widget_set_halign(a->lbl_port, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), a->lbl_port, 3, 0, 1, 1);

    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Mode:"), 0, 1, 1, 1);
    a->lbl_mode = gtk_label_new("…");
    gtk_style_context_add_class(gtk_widget_get_style_context(a->lbl_mode), "accent");
    gtk_widget_set_halign(a->lbl_mode, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), a->lbl_mode, 1, 1, 3, 1);

    gtk_box_pack_start(GTK_BOX(vbox), grid, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), make_sep(), FALSE, FALSE, 0);

    /* Daemon status row */
    GtkWidget *d_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_pack_start(GTK_BOX(d_row), gtk_label_new("Daemon:"), FALSE, FALSE, 0);
    a->dot_daemon = make_dot("red");
    gtk_box_pack_start(GTK_BOX(d_row), a->dot_daemon, FALSE, FALSE, 0);
    a->lbl_daemon = gtk_label_new("Unknown");
    gtk_widget_set_hexpand(a->lbl_daemon, TRUE);
    gtk_widget_set_halign(a->lbl_daemon, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(d_row), a->lbl_daemon, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(d_row),
        make_btn("Check", NULL, G_CALLBACK(on_check), a), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), d_row, FALSE, FALSE, 0);

    /* Port listening row */
    GtkWidget *p_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_pack_start(GTK_BOX(p_row), gtk_label_new("Listen:"), FALSE, FALSE, 0);
    a->dot_proc = make_dot("red");
    gtk_box_pack_start(GTK_BOX(p_row), a->dot_proc, FALSE, FALSE, 0);
    a->lbl_proc = gtk_label_new("Unknown");
    gtk_widget_set_hexpand(a->lbl_proc, TRUE);
    gtk_widget_set_halign(a->lbl_proc, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(p_row), a->lbl_proc, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), p_row, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), make_sep(), FALSE, FALSE, 0);

    /* Daemon control buttons */
    GtkWidget *ctrl = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *sb   = make_btn("Start",   NULL, G_CALLBACK(on_start),   a);
    GtkWidget *tb   = make_btn("Stop",    NULL, G_CALLBACK(on_stop),    a);
    GtkWidget *rb   = make_btn("Restart", NULL, G_CALLBACK(on_restart), a);
    gtk_widget_set_hexpand(sb, TRUE);
    gtk_widget_set_hexpand(tb, TRUE);
    gtk_widget_set_hexpand(rb, TRUE);
    gtk_box_pack_start(GTK_BOX(ctrl), sb, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(ctrl), tb, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(ctrl), rb, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), ctrl, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), make_sep(), FALSE, FALSE, 0);

    /* Port control buttons */
    GtkWidget *port_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *ob = make_btn("Open Port",  "green", G_CALLBACK(on_open_port),  a);
    GtkWidget *cb = make_btn("Close Port", "red",   G_CALLBACK(on_close_port), a);
    gtk_widget_set_hexpand(ob, TRUE);
    gtk_widget_set_hexpand(cb, TRUE);
    gtk_box_pack_start(GTK_BOX(port_row), ob, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(port_row), cb, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), port_row, FALSE, FALSE, 0);

    return vbox;
}

/* ── Provision tab ────────────────────────────────────────────────────── */

static gboolean on_prov_tick(gpointer data);  /* forward declaration */

static gboolean on_qr_draw(GtkWidget *widget, cairo_t *cr, gpointer data)
{
    App *a = (App *)data;
    GtkAllocation alloc;
    gtk_widget_get_allocation(widget, &alloc);

    if (!a->qr_current) {
        /* Placeholder */
        cairo_set_source_rgb(cr, 0.19, 0.20, 0.24);   /* #313244 */
        cairo_paint(cr);
        cairo_set_source_rgb(cr, 0.42, 0.44, 0.51);   /* #6c7086 */
        cairo_select_font_face(cr, "Sans",
                               CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(cr, 10);
        const char *msg = qr_available()
            ? "Generate OTP to show QR"
            : "libqrencode not installed";
        cairo_text_extents_t te;
        cairo_text_extents(cr, msg, &te);
        cairo_move_to(cr,
            (alloc.width  - te.width)  / 2.0 - te.x_bearing,
            (alloc.height - te.height) / 2.0 - te.y_bearing);
        cairo_show_text(cr, msg);
        return FALSE;
    }

    qr_render(cr, a->qr_current, alloc.width, alloc.height);
    return FALSE;
}

static void on_gen_otp(GtkButton *b, App *a)
{
    (void)b;

    const char *ca_pass = gtk_entry_get_text(GTK_ENTRY(a->entry_ca_pass));
    if (!ca_pass || ca_pass[0] == '\0') {
        show_dialog(GTK_WINDOW(a->window), "Error",
                    "CA passphrase is required.", TRUE);
        return;
    }

    /* Cancel previous countdown */
    if (a->prov_timer_id) {
        g_source_remove(a->prov_timer_id);
        a->prov_timer_id = 0;
    }
    qr_free(a->qr_current);
    a->qr_current = NULL;

    if (sys_generate_otp(&a->prov, ca_pass) != 0) {
        show_dialog(GTK_WINDOW(a->window), "Error",
                    "Failed to generate OTP.\n"
                    "Ensure setup.sh was run (server.crt must exist).", TRUE);
        gtk_label_set_text(GTK_LABEL(a->lbl_prov_addr), "—");
        gtk_label_set_text(GTK_LABEL(a->lbl_prov_otp),  "—");
        gtk_label_set_text(GTK_LABEL(a->lbl_prov_fp),   "—");
        gtk_label_set_text(GTK_LABEL(a->lbl_prov_ttl),  "—");
        gtk_widget_queue_draw(a->da_qr);
        return;
    }

    a->qr_current = qr_generate(a->prov.addr, a->prov.otp, a->prov.fp);

    /* Update info labels (truncate long hex strings) */
    char otp_disp[24], fp_disp[24];
    snprintf(otp_disp, sizeof(otp_disp), "%.16s…", a->prov.otp);
    snprintf(fp_disp,  sizeof(fp_disp),  "%.16s…", a->prov.fp);

    gtk_label_set_text(GTK_LABEL(a->lbl_prov_addr), a->prov.addr);
    gtk_label_set_text(GTK_LABEL(a->lbl_prov_otp),  otp_disp);
    gtk_label_set_text(GTK_LABEL(a->lbl_prov_fp),   fp_disp);

    GtkStyleContext *ttl_ctx = gtk_widget_get_style_context(a->lbl_prov_ttl);
    gtk_style_context_remove_class(ttl_ctx, "ttl-expired");
    gtk_style_context_add_class(ttl_ctx, "ttl");

    a->prov_timer_id = g_timeout_add(1000, on_prov_tick, a);
    gtk_widget_queue_draw(a->da_qr);
}

static gboolean on_prov_tick(gpointer data)
{
    App *a = (App *)data;
    time_t remaining = a->prov.expires - time(NULL);

    if (remaining <= 0) {
        gtk_label_set_text(GTK_LABEL(a->lbl_prov_ttl), "EXPIRED");
        GtkStyleContext *ctx = gtk_widget_get_style_context(a->lbl_prov_ttl);
        gtk_style_context_remove_class(ctx, "ttl");
        gtk_style_context_add_class(ctx, "ttl-expired");
        qr_free(a->qr_current);
        a->qr_current = NULL;
        a->prov_timer_id = 0;
        gtk_widget_queue_draw(a->da_qr);
        return G_SOURCE_REMOVE;
    }

    char ttl_str[32];
    snprintf(ttl_str, sizeof(ttl_str), "Expires in: %lds", (long)remaining);
    gtk_label_set_text(GTK_LABEL(a->lbl_prov_ttl), ttl_str);
    return G_SOURCE_CONTINUE;
}

static GtkWidget *build_provision_tab(App *a)
{
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 16);

    /* CA passphrase row */
    GtkWidget *pass_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_pack_start(GTK_BOX(pass_row),
        gtk_label_new("CA Passphrase:"), FALSE, FALSE, 0);
    a->entry_ca_pass = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(a->entry_ca_pass), FALSE);
    gtk_entry_set_placeholder_text(GTK_ENTRY(a->entry_ca_pass),
                                   "Enter CA key passphrase…");
    gtk_widget_set_hexpand(a->entry_ca_pass, TRUE);
    gtk_box_pack_start(GTK_BOX(pass_row), a->entry_ca_pass, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), pass_row, FALSE, FALSE, 0);

    GtkWidget *gen_btn = make_btn("Generate OTP", "accent",
                                  G_CALLBACK(on_gen_otp), a);
    gtk_widget_set_margin_top(gen_btn, 2);
    gtk_box_pack_start(GTK_BOX(vbox), gen_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), make_sep(), FALSE, FALSE, 0);

    /* QR drawing area — centred */
    GtkWidget *qr_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    a->da_qr = gtk_drawing_area_new();
    gtk_widget_set_size_request(a->da_qr, 280, 280);
    g_signal_connect(a->da_qr, "draw", G_CALLBACK(on_qr_draw), a);
    gtk_widget_set_halign(a->da_qr, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(qr_box), a->da_qr, TRUE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), qr_box, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), make_sep(), FALSE, FALSE, 0);

    /* Info grid */
    GtkWidget *info = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(info), 4);
    gtk_grid_set_column_spacing(GTK_GRID(info), 8);

    struct { const char *label; GtkWidget **field; } rows[] = {
        { "Addr:",        &a->lbl_prov_addr },
        { "OTP:",         &a->lbl_prov_otp  },
        { "Fingerprint:", &a->lbl_prov_fp   },
    };
    for (int i = 0; i < 3; i++) {
        GtkWidget *k = gtk_label_new(rows[i].label);
        gtk_widget_set_halign(k, GTK_ALIGN_END);
        gtk_grid_attach(GTK_GRID(info), k, 0, i, 1, 1);
        *rows[i].field = gtk_label_new("—");
        gtk_style_context_add_class(
            gtk_widget_get_style_context(*rows[i].field), "accent");
        gtk_widget_set_halign(*rows[i].field, GTK_ALIGN_START);
        gtk_grid_attach(GTK_GRID(info), *rows[i].field, 1, i, 1, 1);
    }

    /* TTL label centred below the grid */
    a->lbl_prov_ttl = gtk_label_new("—");
    gtk_style_context_add_class(
        gtk_widget_get_style_context(a->lbl_prov_ttl), "ttl");
    gtk_widget_set_halign(a->lbl_prov_ttl, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_top(a->lbl_prov_ttl, 6);
    gtk_grid_attach(GTK_GRID(info), a->lbl_prov_ttl, 0, 3, 2, 1);

    gtk_box_pack_start(GTK_BOX(vbox), info, FALSE, FALSE, 0);
    return vbox;
}

/* ── Devices tab ──────────────────────────────────────────────────────── */

static void refresh_devices(App *a);  /* forward declaration */

static void on_revoke_device(GtkButton *b, DeviceRevoke *dr)
{
    (void)b;
    App *a = dr->app;

    char msg[128];
    snprintf(msg, sizeof(msg), "Revoke device:\n%.48s ?", dr->device_id);

    GtkWidget *dlg = gtk_dialog_new_with_buttons(
        "Confirm Revoke", GTK_WINDOW(a->window),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "Cancel", GTK_RESPONSE_CANCEL,
        "Revoke",  GTK_RESPONSE_OK, NULL);

    GtkWidget *box = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_container_set_border_width(GTK_CONTAINER(box), 20);
    GtkWidget *lbl = gtk_label_new(msg);
    gtk_label_set_justify(GTK_LABEL(lbl), GTK_JUSTIFY_CENTER);
    gtk_label_set_line_wrap(GTK_LABEL(lbl), TRUE);
    gtk_box_pack_start(GTK_BOX(box), lbl, FALSE, FALSE, 0);
    gtk_widget_show_all(dlg);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_OK) {
        sys_revoke_device(dr->device_id, dr->serial);
        /* Restart daemon so it drops the revoked mTLS connection */
        sys_systemctl("restart");
        refresh_devices(a);
    }
    gtk_widget_destroy(dlg);
}

static void refresh_devices(App *a)
{
    /* Remove all existing rows */
    GList *children = gtk_container_get_children(GTK_CONTAINER(a->devices_box));
    for (GList *c = children; c; c = c->next)
        gtk_widget_destroy(GTK_WIDGET(c->data));
    g_list_free(children);

    Device devs[64];
    int count = sys_list_devices(devs, 64);

    if (count == 0) {
        GtkWidget *lbl = gtk_label_new("No devices provisioned.");
        gtk_style_context_add_class(gtk_widget_get_style_context(lbl), "accent");
        gtk_widget_set_halign(lbl, GTK_ALIGN_CENTER);
        gtk_widget_set_margin_top(lbl, 16);
        gtk_box_pack_start(GTK_BOX(a->devices_box), lbl, FALSE, FALSE, 0);
        gtk_widget_show(lbl);
        return;
    }

    for (int i = 0; i < count; i++) {
        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        gtk_widget_set_margin_top(row, 2);
        gtk_widget_set_margin_bottom(row, 2);

        char info[256];
        snprintf(info, sizeof(info), "%.32s  |  sn: %.16s  |  exp: %.20s",
                 devs[i].device_id,
                 devs[i].serial[0]    ? devs[i].serial    : "n/a",
                 devs[i].not_after[0] ? devs[i].not_after : "n/a");
        GtkWidget *lbl = gtk_label_new(info);
        gtk_label_set_ellipsize(GTK_LABEL(lbl), PANGO_ELLIPSIZE_END);
        gtk_widget_set_hexpand(lbl, TRUE);
        gtk_widget_set_halign(lbl, GTK_ALIGN_START);

        DeviceRevoke *dr = g_new(DeviceRevoke, 1);
        strncpy(dr->device_id, devs[i].device_id, sizeof(dr->device_id) - 1);
        dr->device_id[sizeof(dr->device_id) - 1] = '\0';
        strncpy(dr->serial, devs[i].serial, sizeof(dr->serial) - 1);
        dr->serial[sizeof(dr->serial) - 1] = '\0';
        dr->app = a;

        GtkWidget *rev = gtk_button_new_with_label("Revoke");
        gtk_style_context_add_class(gtk_widget_get_style_context(rev), "red");
        g_signal_connect_data(rev, "clicked",
                              G_CALLBACK(on_revoke_device), dr,
                              (GClosureNotify)g_free, 0);

        gtk_box_pack_start(GTK_BOX(row), lbl, TRUE,  TRUE,  0);
        gtk_box_pack_start(GTK_BOX(row), rev, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(a->devices_box), row, FALSE, FALSE, 0);
        gtk_widget_show_all(row);
    }
}

static void on_refresh_devices(GtkButton *b, App *a) { (void)b; refresh_devices(a); }

static void on_revoke_all(GtkButton *b, App *a)
{
    (void)b;

    GtkWidget *dlg = gtk_dialog_new_with_buttons(
        "Confirm Revoke All", GTK_WINDOW(a->window),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "Cancel",     GTK_RESPONSE_CANCEL,
        "Revoke All", GTK_RESPONSE_OK, NULL);

    GtkWidget *box = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_container_set_border_width(GTK_CONTAINER(box), 20);
    GtkWidget *lbl = gtk_label_new(
        "Revoke ALL provisioned devices?\n"
        "They will need to be re-provisioned.");
    gtk_label_set_justify(GTK_LABEL(lbl), GTK_JUSTIFY_CENTER);
    gtk_box_pack_start(GTK_BOX(box), lbl, FALSE, FALSE, 0);
    gtk_widget_show_all(dlg);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_OK) {
        Device devs[64];
        int count = sys_list_devices(devs, 64);
        for (int i = 0; i < count; i++)
            sys_revoke_device(devs[i].device_id, devs[i].serial);
        sys_systemctl("restart");
        refresh_devices(a);
    }
    gtk_widget_destroy(dlg);
}

static GtkWidget *build_devices_tab(App *a)
{
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 16);

    GtkWidget *ref_btn = make_btn("Refresh", NULL,
                                  G_CALLBACK(on_refresh_devices), a);
    gtk_box_pack_start(GTK_BOX(vbox), ref_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), make_sep(), FALSE, FALSE, 0);

    /* Scrolled container for device rows */
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_size_request(scroll, -1, 240);
    gtk_widget_set_vexpand(scroll, TRUE);

    a->devices_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    gtk_container_add(GTK_CONTAINER(scroll), a->devices_box);
    gtk_box_pack_start(GTK_BOX(vbox), scroll, TRUE, TRUE, 0);

    gtk_box_pack_start(GTK_BOX(vbox), make_sep(), FALSE, FALSE, 0);

    GtkWidget *rall = make_btn("Revoke All", "red",
                               G_CALLBACK(on_revoke_all), a);
    gtk_box_pack_start(GTK_BOX(vbox), rall, FALSE, FALSE, 0);

    return vbox;
}

/* ── Audit tab ────────────────────────────────────────────────────────── */

static void refresh_audit(App *a)
{
    int count;
    char **lines = sys_read_audit(&count, 50);

    GtkTextBuffer *buf =
        gtk_text_view_get_buffer(GTK_TEXT_VIEW(a->audit_view));
    gtk_text_buffer_set_text(buf, "", 0);

    if (!lines || count == 0) {
        gtk_text_buffer_set_text(buf,
            "(audit.log is empty or not found)\n", -1);
        if (lines) sys_free_lines(lines, count);
        return;
    }

    GtkTextIter iter;
    gtk_text_buffer_get_end_iter(buf, &iter);
    for (int i = 0; i < count; i++)
        gtk_text_buffer_insert(buf, &iter, lines[i], -1);

    sys_free_lines(lines, count);

    /* Scroll to end */
    gtk_text_buffer_get_end_iter(buf, &iter);
    GtkTextMark *mark =
        gtk_text_buffer_create_mark(buf, NULL, &iter, FALSE);
    gtk_text_view_scroll_mark_onscreen(GTK_TEXT_VIEW(a->audit_view), mark);
    gtk_text_buffer_delete_mark(buf, mark);
}

static void on_refresh_audit(GtkButton *b, App *a) { (void)b; refresh_audit(a); }

static GtkWidget *build_audit_tab(App *a)
{
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 16);

    GtkWidget *ref_btn = make_btn("Refresh", NULL,
                                  G_CALLBACK(on_refresh_audit), a);
    gtk_box_pack_start(GTK_BOX(vbox), ref_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), make_sep(), FALSE, FALSE, 0);

    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(scroll, TRUE);

    a->audit_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(a->audit_view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(a->audit_view), FALSE);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(a->audit_view), 6);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(a->audit_view), 6);
    gtk_container_add(GTK_CONTAINER(scroll), a->audit_view);
    gtk_box_pack_start(GTK_BOX(vbox), scroll, TRUE, TRUE, 0);

    return vbox;
}

/* ── Window close handler ─────────────────────────────────────────────── */

static void on_window_destroy(App *a)
{
    if (a->prov_timer_id) {
        g_source_remove(a->prov_timer_id);
        a->prov_timer_id = 0;
    }
}

/* ── activate ─────────────────────────────────────────────────────────── */

void activate(GtkApplication *gapp, gpointer user_data)
{
    App *a = (App *)user_data;

    /* Apply CSS */
    GtkCssProvider *css = gtk_css_provider_new();
    gtk_css_provider_load_from_data(css, CSS, -1, NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(css), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(css);

    a->window = gtk_application_window_new(gapp);
    gtk_window_set_title(GTK_WINDOW(a->window), "PAM — Panel Access Manager");
    gtk_window_set_resizable(GTK_WINDOW(a->window), FALSE);
    gtk_window_set_default_size(GTK_WINDOW(a->window), 480, 520);

    GtkWidget *notebook = gtk_notebook_new();
    gtk_notebook_set_tab_pos(GTK_NOTEBOOK(notebook), GTK_POS_TOP);
    gtk_container_add(GTK_CONTAINER(a->window), notebook);

    gtk_notebook_append_page(GTK_NOTEBOOK(notebook),
        build_status_tab(a),    gtk_label_new("Status"));
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook),
        build_provision_tab(a), gtk_label_new("Provision"));
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook),
        build_devices_tab(a),   gtk_label_new("Devices"));
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook),
        build_audit_tab(a),     gtk_label_new("Audit Log"));

    /* Cancel OTP countdown timer on window close to prevent use-after-free */
    g_signal_connect_swapped(a->window, "destroy",
                             G_CALLBACK(on_window_destroy), a);

    gtk_widget_show_all(a->window);

    /* Initial state load */
    refresh_state(a);
    update_daemon_status(a);
    refresh_devices(a);
}
