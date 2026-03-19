#include "qr.h"

#include <stdio.h>
#include <string.h>
#include <qrencode.h>

int qr_available(void) { return 1; }

void *qr_generate(const char *addr, const char *otp, const char *fp)
{
    char payload[768];
    snprintf(payload, sizeof(payload),
             "{\"addr\":\"%s\",\"otp\":\"%s\",\"fp\":\"%s\"}",
             addr, otp, fp);
    return QRcode_encodeString(payload, 0, QR_ECLEVEL_M, QR_MODE_8, 1);
}

void qr_free(void *qr)
{
    if (qr)
        QRcode_free((QRcode *)qr);
}

void qr_render(cairo_t *cr, void *data, int width, int height)
{
    QRcode *qr = (QRcode *)data;
    if (!qr) return;

    int    quiet = 4;
    int    total = qr->width + 2 * quiet;
    double side  = (double)(width < height ? width : height);
    double mod   = side / total;
    double off_x = (width  - total * mod) / 2.0;
    double off_y = (height - total * mod) / 2.0;

    cairo_set_source_rgb(cr, 1, 1, 1);
    cairo_paint(cr);
    cairo_set_source_rgb(cr, 0, 0, 0);

    for (int y = 0; y < qr->width; y++) {
        for (int x = 0; x < qr->width; x++) {
            if (qr->data[y * qr->width + x] & 1) {
                cairo_rectangle(cr,
                    off_x + (x + quiet) * mod,
                    off_y + (y + quiet) * mod,
                    mod, mod);
                cairo_fill(cr);
            }
        }
    }
}
