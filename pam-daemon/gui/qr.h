#pragma once

#include <cairo.h>

/*
 * QR code module for PAM provisioning.
 *
 * Uses void* for the QRcode handle so that callers do not need to include
 * qrencode.h directly.
 */

#ifdef HAVE_QRENCODE

int   qr_available(void);

/*
 * Generate a QRcode* for the PAM provisioning payload:
 *   {"addr":"<addr>","otp":"<otp>","fp":"<fp>"}
 *
 * Returns NULL on failure.  Caller must free with qr_free().
 */
void *qr_generate(const char *addr, const char *otp, const char *fp);

/* Free a handle returned by qr_generate(). */
void  qr_free(void *qr);

/*
 * Render the QR code onto an existing cairo context.
 * Centres the QR within the given width × height pixel area.
 */
void  qr_render(cairo_t *cr, void *qr, int width, int height);

#else

static inline int   qr_available(void)
    { return 0; }
static inline void *qr_generate(const char *a, const char *o, const char *f)
    { (void)a; (void)o; (void)f; return NULL; }
static inline void  qr_free(void *q)
    { (void)q; }
static inline void  qr_render(cairo_t *c, void *q, int w, int h)
    { (void)c; (void)q; (void)w; (void)h; }

#endif
