#include <gtk/gtk.h>
#include <glib-unix.h>
#include "gui_gtk.h"

static gboolean on_signal(gpointer user_data)
{
    GApplication *app = G_APPLICATION(user_data);
    g_application_quit(app);
    return G_SOURCE_REMOVE;
}

int main(int argc, char *argv[])
{
    App a = {
        .cfg = { .ip = "unknown", .port = 7443, .mode = "direct" }
    };

    GtkApplication *gapp = gtk_application_new(
        "com.giovanni.pam-manager", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(gapp, "activate", G_CALLBACK(activate), &a);

    g_unix_signal_add(SIGTERM, on_signal, gapp);
    g_unix_signal_add(SIGINT,  on_signal, gapp);

    int status = g_application_run(G_APPLICATION(gapp), argc, argv);
    g_object_unref(gapp);
    return status;
}
