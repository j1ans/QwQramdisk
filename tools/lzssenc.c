/* Okumura LZSS encoder (4 KiB window, 18-byte lookahead).
 * The original algorithm was released with permission to use, distribute,
 * and modify freely. This file adds only a binary stdin/stdout-style CLI.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define N 4096
#define F 18
#define THRESHOLD 2
#define NIL N

static unsigned char text_buf[N + F - 1];
static int match_position, match_length;
static int lson[N + 1], rson[N + 257], dad[N + 1];

static void init_tree(void) {
    int i;
    for (i = N + 1; i <= N + 256; i++) rson[i] = NIL;
    for (i = 0; i < N; i++) dad[i] = NIL;
}

static void insert_node(int r) {
    int i, p, cmp = 1;
    unsigned char *key = &text_buf[r];
    p = N + 1 + key[0];
    rson[r] = lson[r] = NIL;
    match_length = 0;
    for (;;) {
        if (cmp >= 0) {
            if (rson[p] != NIL) p = rson[p];
            else { rson[p] = r; dad[r] = p; return; }
        } else {
            if (lson[p] != NIL) p = lson[p];
            else { lson[p] = r; dad[r] = p; return; }
        }
        for (i = 1; i < F; i++)
            if ((cmp = key[i] - text_buf[p + i]) != 0) break;
        if (i > match_length) {
            match_position = p;
            if ((match_length = i) >= F) break;
        }
    }
    dad[r] = dad[p]; lson[r] = lson[p]; rson[r] = rson[p];
    dad[lson[p]] = r; dad[rson[p]] = r;
    if (rson[dad[p]] == p) rson[dad[p]] = r;
    else lson[dad[p]] = r;
    dad[p] = NIL;
}

static void delete_node(int p) {
    int q;
    if (dad[p] == NIL) return;
    if (rson[p] == NIL) q = lson[p];
    else if (lson[p] == NIL) q = rson[p];
    else {
        q = lson[p];
        if (rson[q] != NIL) {
            do q = rson[q]; while (rson[q] != NIL);
            rson[dad[q]] = lson[q]; dad[lson[q]] = dad[q];
            lson[q] = lson[p]; dad[lson[p]] = q;
        }
        rson[q] = rson[p]; dad[rson[p]] = q;
    }
    dad[q] = dad[p];
    if (rson[dad[p]] == p) rson[dad[p]] = q;
    else lson[dad[p]] = q;
    dad[p] = NIL;
}

static int encode(FILE *in, FILE *out) {
    int i, c, len, r, s, last_match_length, code_buf_ptr;
    unsigned char code_buf[17], mask;
    init_tree();
    code_buf[0] = 0; code_buf_ptr = mask = 1;
    s = 0; r = N - F;
    for (i = s; i < r; i++) text_buf[i] = ' ';
    for (len = 0; len < F && (c = getc(in)) != EOF; len++) text_buf[r + len] = (unsigned char)c;
    if (!len) return 0;
    for (i = 1; i <= F; i++) insert_node(r - i);
    insert_node(r);
    do {
        if (match_length > len) match_length = len;
        if (match_length <= THRESHOLD) {
            match_length = 1; code_buf[0] |= mask;
            code_buf[code_buf_ptr++] = text_buf[r];
        } else {
            code_buf[code_buf_ptr++] = (unsigned char)match_position;
            code_buf[code_buf_ptr++] = (unsigned char)(((match_position >> 4) & 0xf0)
                                      | (match_length - (THRESHOLD + 1)));
        }
        if ((mask <<= 1) == 0) {
            if (fwrite(code_buf, 1, (size_t)code_buf_ptr, out) != (size_t)code_buf_ptr) return 2;
            code_buf[0] = 0; code_buf_ptr = mask = 1;
        }
        last_match_length = match_length;
        for (i = 0; i < last_match_length && (c = getc(in)) != EOF; i++) {
            delete_node(s); text_buf[s] = (unsigned char)c;
            if (s < F - 1) text_buf[s + N] = (unsigned char)c;
            s = (s + 1) & (N - 1); r = (r + 1) & (N - 1); insert_node(r);
        }
        while (i++ < last_match_length) {
            delete_node(s); s = (s + 1) & (N - 1); r = (r + 1) & (N - 1);
            if (--len) insert_node(r);
        }
    } while (len > 0);
    if (code_buf_ptr > 1 && fwrite(code_buf, 1, (size_t)code_buf_ptr, out) != (size_t)code_buf_ptr) return 2;
    return 0;
}

int main(int argc, char **argv) {
    FILE *in, *out;
    int rc;
    if (argc != 3) { fprintf(stderr, "usage: lzssenc input output\n"); return 64; }
    in = fopen(argv[1], "rb"); if (!in) return 66;
    out = fopen(argv[2], "wb"); if (!out) { fclose(in); return 73; }
    rc = encode(in, out);
    if (fclose(out) != 0 && rc == 0) rc = 74;
    fclose(in); return rc;
}
