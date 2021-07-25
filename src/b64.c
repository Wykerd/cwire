/**
 * This is a C port of NodeJS's base64 implementation.
 * Licensed under MIT and available here: https://github.com/nodejs/node/blob/master/src/base64-inl.h
 */

#include <cwire/common.h>
#include <cwire/b64.h>
#include <math.h>
#include <assert.h>
#include <cwire/no_malloc.h>

// supports regular and URL-safe base64
const int8_t unbase64_table[256] =
  { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -2, -1, -1, -2, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, 62, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
  };

inline static int8_t unbase64(uint8_t x) 
{
    return unbase64_table[x];
}

uint32_t ReadUint32BE(const unsigned char* p) 
{
    return (p[0] << 24U) | (p[1] << 16U) | (p[2] << 8U) | (p[3]);
}

int base64_decode_group_slow (char* const dst, const size_t dstlen,
                              const char* const src, const size_t srclen,
                              size_t* const i, size_t* const k) 
{
    uint8_t hi;
    uint8_t lo;
#define V(expr)                                                                 \
    for (;;) {                                                                  \
        const uint8_t c = src[*i];                                              \
        lo = unbase64(c);                                                       \
        *i += 1;                                                                \
        if (lo < 64)                                                            \
        break;  /* Legal character. */                                          \
        if (c == '=' || *i >= srclen)                                           \
        return 0;  /* Stop decoding. */                                         \
    }                                                                           \
    expr;                                                                       \
    if (*i >= srclen)                                                           \
        return 0;                                                               \
    if (*k >= dstlen)                                                           \
        return 0;                                                               \
    hi = lo;
    V(/* Nothing. */);
    V(dst[(*k)++] = ((hi & 0x3F) << 2) | ((lo & 0x30) >> 4));
    V(dst[(*k)++] = ((hi & 0x0F) << 4) | ((lo & 0x3C) >> 2));
    V(dst[(*k)++] = ((hi & 0x03) << 6) | ((lo & 0x3F) >> 0));
#undef V
    return 1;  // Continue decoding.
}

size_t base64_decode_fast (char* const dst, const size_t dstlen, 
                           const char* const src, const size_t srclen, const size_t decoded_size) 
{
    const size_t available = dstlen < decoded_size ? dstlen : decoded_size;
    const size_t max_k = available / 3 * 3;
    size_t max_i = srclen / 4 * 4;
    size_t i = 0;
    size_t k = 0;
    while (i < max_i && k < max_k) {
        const unsigned char txt[] = {
            (unbase64(src[i + 0])),
            (unbase64(src[i + 1])),
            (unbase64(src[i + 2])),
            (unbase64(src[i + 3])),
        };

        const uint32_t v = ReadUint32BE(txt);
        // If MSB is set, input contains whitespace or is not valid base64.
        if (v & 0x80808080) {
            if (!base64_decode_group_slow(dst, dstlen, src, srclen, &i, &k))
                return k;
            max_i = i + (srclen - i) / 4 * 4;  // Align max_i again.
        } else {
            dst[k + 0] = ((v >> 22) & 0xFC) | ((v >> 20) & 0x03);
            dst[k + 1] = ((v >> 12) & 0xF0) | ((v >> 10) & 0x0F);
            dst[k + 2] = ((v >>  2) & 0xC0) | ((v >>  0) & 0x3F);
            i += 4;
            k += 3;
        }
    }
    if (i < srclen && k < dstlen) {
        base64_decode_group_slow(dst, dstlen, src, srclen, &i, &k);
    }
    return k;
}

size_t base64_decoded_size(const char* src, size_t size) 
{
    // 1-byte input cannot be decoded
    if (size < 2)
        return 0;

    if (src[size - 1] == '=') {
        size--;
        if (src[size - 1] == '=')
        size--;
    }
    return base64_decoded_size_fast(size);
}

size_t base64_decode (char* const dst, const size_t dstlen,
                      const char* const src, const size_t srclen) 
{
    const size_t decoded_size = base64_decoded_size(src, srclen);
    return base64_decode_fast(dst, dstlen, src, srclen, decoded_size);
}


size_t base64_encode (const char* src, size_t slen,
                      char* dst, size_t dlen, cwr_b64_mode mode) 
{
    // We know how much we'll write, just make sure that there's space.
    assert(dlen >= base64_encoded_size(slen, mode) && "not enough space provided for base64 encode");

    dlen = base64_encoded_size(slen, mode);

    unsigned a;
    unsigned b;
    unsigned c;
    unsigned i;
    unsigned k;
    unsigned n;

    const char* table = base64_select_table(mode);

    i = 0;
    k = 0;
    n = slen / 3 * 3;

    while (i < n) {
        a = src[i + 0] & 0xff;
        b = src[i + 1] & 0xff;
        c = src[i + 2] & 0xff;

        dst[k + 0] = table[a >> 2];
        dst[k + 1] = table[((a & 3) << 4) | (b >> 4)];
        dst[k + 2] = table[((b & 0x0f) << 2) | (c >> 6)];
        dst[k + 3] = table[c & 0x3f];

        i += 3;
        k += 4;
    }

    switch (slen - n) {
        case 1:
        a = src[i + 0] & 0xff;
        dst[k + 0] = table[a >> 2];
        dst[k + 1] = table[(a & 3) << 4];
        if (mode == CWR_B64_MODE_NORMAL) {
            dst[k + 2] = '=';
            dst[k + 3] = '=';
        }
        break;
        case 2:
        a = src[i + 0] & 0xff;
        b = src[i + 1] & 0xff;
        dst[k + 0] = table[a >> 2];
        dst[k + 1] = table[((a & 3) << 4) | (b >> 4)];
        dst[k + 2] = table[(b & 0x0f) << 2];
        if (mode == CWR_B64_MODE_NORMAL)
            dst[k + 3] = '=';
        break;
    }

    return dlen;
}