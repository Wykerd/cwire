/**
 * This is a C port of NodeJS's base64 implementation.
 * Licensed under MIT and available here: https://github.com/nodejs/node/blob/master/src/base64.h
 */

#ifndef CWR_B64_H
#define CWR_B64_H
#include <cwire/common.h>

typedef enum cwr_b64_mode {
    CWR_B64_MODE_NORMAL,
    CWR_B64_MODE_URL
} cwr_b64_mode;

static const char base64_table[] =  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                    "abcdefghijklmnopqrstuvwxyz"
                                    "0123456789+/";

static const char base64_table_url[] =  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                        "abcdefghijklmnopqrstuvwxyz"
                                        "0123456789-_";

static inline const char* base64_select_table (cwr_b64_mode mode) {
    switch (mode) {
        case CWR_B64_MODE_NORMAL: return base64_table;
        case CWR_B64_MODE_URL: return base64_table_url;
        default: return base64_table;
    }
}

// Use CWR_B64_MODE_NORMAL as mode default
static inline const size_t base64_encoded_size (size_t size, cwr_b64_mode mode) {
    // return mode == CWR_B64_MODE_NORMAL ? ((size + 2) / 3 * 4) : ceil((size * 4.0) / 3.0);
    return ((size + 2) / 3 * 4);
}

// Doesn't check for padding at the end.  Can be 1-2 bytes over.
static inline const size_t base64_decoded_size_fast (size_t size) {
    // 1-byte input cannot be decoded
    return size > 1 ? (size / 4) * 3 + (size % 4 + 1) / 2 : 0;
}

inline uint32_t ReadUint32BE(const unsigned char* p);

size_t base64_decoded_size (const char* src, size_t size);

size_t base64_decode (char* const dst, const size_t dstlen,
                      const char* const src, const size_t srclen);

// Use CWR_B64_MODE_NORMAL as mode default
inline size_t base64_encode (const char* src, size_t slen,
                             char* dst, size_t dlen, cwr_b64_mode mode); 

#endif