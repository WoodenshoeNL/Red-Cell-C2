/*
 * bof_printf.c — C variadic shim for BeaconPrintf.
 *
 * Rust stable does not support defining C-variadic functions.
 * This thin wrapper receives the variadic arguments, formats them
 * with vsnprintf, and calls into a Rust-side callback to append
 * the result to the BOF output buffer.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

/* Implemented in Rust (coffeeldr.rs) — appends to the TLS output buffer. */
extern void bof_printf_callback(const char *data, int len);

void bof_beacon_printf(int type __attribute__((unused)), const char *fmt, ...)
{
    if (!fmt)
        return;

    va_list ap;

    /* First pass: measure the required buffer length. */
    va_start(ap, fmt);
    int len = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);

    if (len < 0)
        return;

    /* Stack-allocate small buffers, heap-allocate large ones. */
    char stack_buf[512];
    char *buf = (len < (int)sizeof(stack_buf)) ? stack_buf : (char *)malloc((size_t)len + 1);
    if (!buf)
        return;

    /* Second pass: format into the buffer. */
    va_start(ap, fmt);
    vsnprintf(buf, (size_t)len + 1, fmt, ap);
    va_end(ap);

    bof_printf_callback(buf, len);

    if (buf != stack_buf)
        free(buf);
}
