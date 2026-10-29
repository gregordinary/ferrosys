/*
 * codec-reference — the reference decoders and encoders for LZVN, LZFSE and LZBITMAP, as one
 * command line the decoder differential drives.
 *
 * The crate's LZVN and LZFSE decoders are held to Apple's lzfse project, the reference
 * implementation of both, and its LZBITMAP decoder to libzbitmap. Neither project ships a
 * program that answers for one stream at a time with what it decoded and whether it reached the
 * stream's end, so this is that program. Every decision about a stream belongs to the library:
 * this file frames requests and answers and does nothing else.
 *
 * Licensing: the binary this builds links Apple's lzfse (BSD-3-Clause) and libzbitmap (MIT).
 * It is built locally by `ci/build-codec-reference.sh`, used only by the test suite, and is
 * not part of the crate, its dependency graph, or anything published from this repository.
 *
 * Usage:
 *   codec-reference --version
 *   codec-reference            requests on standard input, answers on standard output
 *
 * A request is one byte naming the algorithm (1 LZVN, 2 LZFSE, 3 LZBITMAP), one byte naming
 * the operation (0 decode, 1 encode), the output's capacity in bytes and the input's length,
 * each four bytes little-endian, and then the input. An answer is one status byte, the number
 * of bytes produced in four bytes little-endian, and then those bytes. A decode's status is 0
 * where the stream decoded to its end within the capacity, 2 where the output filled first,
 * and 1 otherwise; an encode's is 0 where the library wrote a stream within the capacity, and
 * 1 otherwise. Requests are answered in order until standard input ends.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lzfse.h"
#include "lzfse_internal.h"
#include "lzvn_decode_base.h"
#include "libzbitmap.h"

#ifndef CODEC_REFERENCE_LZFSE
#error "the build names the lzfse revision it links"
#endif
#ifndef CODEC_REFERENCE_LIBZBITMAP
#error "the build names the libzbitmap revision it links"
#endif

enum { LZVN = 1, LZFSE = 2, LZBITMAP = 3 };
enum { DECODE = 0, ENCODE = 1 };
enum { DONE = 0, REFUSED = 1, FULL = 2 };

/* Bytes of zeros past a stream's end, so a decoder that reads ahead of where it stops reads
 * bytes of this program's rather than past an allocation. They are not part of the stream:
 * every decoder is given the stream's own end. */
#define SLACK 64

static void die(const char *what) {
    fprintf(stderr, "codec-reference: %s\n", what);
    exit(2);
}

static int read_exact(void *buf, size_t n) {
    size_t got = fread(buf, 1, n, stdin);
    if (got == n) return 1;
    if (got == 0 && feof(stdin)) return 0;
    die("a request ends early");
    return 0;
}

static uint32_t le32(const uint8_t *b) {
    return (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
}

static void answer(int status, const uint8_t *out, size_t n) {
    uint8_t head[5] = {(uint8_t)status, (uint8_t)n, (uint8_t)(n >> 8), (uint8_t)(n >> 16),
                       (uint8_t)(n >> 24)};
    if (fwrite(head, 1, 5, stdout) != 5 || (n && fwrite(out, 1, n, stdout) != n))
        die("an answer could not be written");
}

static int lzfse_decode_one(const uint8_t *src, size_t sn, uint8_t *dst, size_t dn, size_t *out) {
    lzfse_decoder_state *s = calloc(1, sizeof *s);
    if (!s) die("out of memory");
    s->src = src;
    s->src_begin = src;
    s->src_end = src + sn;
    s->dst = dst;
    s->dst_begin = dst;
    s->dst_end = dst + dn;
    int status = lzfse_decode(s);
    *out = (size_t)(s->dst - dst);
    int r = status == LZFSE_STATUS_OK && s->end_of_stream ? DONE
          : status == LZFSE_STATUS_DST_FULL              ? FULL
                                                         : REFUSED;
    free(s);
    return r;
}

static int lzvn_decode_one(const uint8_t *src, size_t sn, uint8_t *dst, size_t dn, size_t *out) {
    lzvn_decoder_state d;
    memset(&d, 0, sizeof d);
    d.src = src;
    d.src_end = src + sn;
    d.dst = dst;
    d.dst_begin = dst;
    d.dst_end = dst + dn;
    lzvn_decode(&d);
    *out = (size_t)(d.dst - dst);
    if (d.end_of_stream) return DONE;
    return *out == dn ? FULL : REFUSED;
}

static int encode_one(int algorithm, const uint8_t *src, size_t sn, uint8_t *dst, size_t dn,
                      size_t *out) {
    void *scratch;
    switch (algorithm) {
    case LZFSE:
        scratch = malloc(lzfse_encode_scratch_size());
        if (!scratch) die("out of memory");
        *out = lzfse_encode_buffer(dst, dn, src, sn, scratch);
        free(scratch);
        return *out ? DONE : REFUSED;
    case LZVN:
        scratch = malloc(lzvn_encode_scratch_size());
        if (!scratch) die("out of memory");
        *out = lzvn_encode_buffer(dst, dn, src, sn, scratch);
        free(scratch);
        return *out ? DONE : REFUSED;
    default:
        return zbm_compress(dst, dn, src, sn, out) == 0 ? DONE : REFUSED;
    }
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("codec-reference (lzfse %s, libzbitmap %s)\n", CODEC_REFERENCE_LZFSE,
               CODEC_REFERENCE_LIBZBITMAP);
        return 0;
    }
    if (argc != 1) die("usage: codec-reference [--version]");
    uint8_t head[10];
    while (read_exact(head, sizeof head)) {
        int algorithm = head[0], operation = head[1];
        size_t capacity = le32(head + 2), length = le32(head + 6);
        if (algorithm < LZVN || algorithm > LZBITMAP || operation > ENCODE)
            die("a request names no algorithm or operation");
        uint8_t *in = calloc(length + SLACK, 1);
        uint8_t *out = malloc(capacity ? capacity : 1);
        if (!in || !out) die("out of memory");
        if (length && !read_exact(in, length)) die("a request ends early");
        size_t produced = 0;
        int status;
        if (operation == ENCODE) {
            status = encode_one(algorithm, in, length, out, capacity, &produced);
        } else if (algorithm == LZFSE) {
            status = lzfse_decode_one(in, length, out, capacity, &produced);
        } else if (algorithm == LZVN) {
            status = lzvn_decode_one(in, length, out, capacity, &produced);
        } else {
            int r = zbm_decompress(out, capacity, in, length, &produced);
            status = r == 0 ? DONE : r == ZBM_RANGE ? FULL : REFUSED;
            if (status != DONE) produced = 0;
        }
        answer(status, out, status == REFUSED && operation == ENCODE ? 0 : produced);
        free(in);
        free(out);
    }
    if (fflush(stdout) != 0) die("an answer could not be written");
    return 0;
}
