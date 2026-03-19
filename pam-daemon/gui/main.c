#include <gtk/gtk.h>
#include "gui_gtk.h"

int main(int argc, char *argv[])
{
    App a = {
        .cfg = { .ip = "unknown", .port = 7443, .mode = "direct" }
    };

    GtkApplication *gapp = gtk_application_new(
        "com.giovanni.pam-manager", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(gapp, "activate", G_CALLBACK(activate), &a);

    int status = g_application_run(G_APPLICATION(gapp), argc, argv);
    g_object_unref(gapp);
    return status;
}
