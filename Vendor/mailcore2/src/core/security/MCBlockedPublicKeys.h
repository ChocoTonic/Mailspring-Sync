#ifndef MAILCORE_BLOCKED_PUBLIC_KEYS_H
#define MAILCORE_BLOCKED_PUBLIC_KEYS_H

#include <climits>
#include <cstddef>
#include <cstring>
#if __APPLE__
#include <CommonCrypto/CommonDigest.h>
#else
#include <openssl/sha.h>
#endif

namespace mailcore { namespace security {

enum CertificateKeyStatus { KeyAllowed, KeyBlocked, KeyInvalid };

// SHA-256 of DER SubjectPublicKeyInfo, shared with Node.js PR 66871 and
// Electron PR 55126. Key-based blocking also catches cross-signed certificates.
// https://bugzilla.mozilla.org/show_bug.cgi?id=2083449
static const char * const blockedPublicKeyHashes[] = {
    "49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f",
    "5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0",
    "63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8",
    "92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30",
    "ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105",
    "ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6",
    "43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b",
    "e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41"
};

// Walk only the outer, definite-length DER fields needed to locate SPKI.
// The platform verifier still validates the complete certificate. Invalid or
// truncated encodings fail closed instead of bypassing the key check.
static inline bool readDERElement(const unsigned char *&cursor,
                                  const unsigned char *end,
                                  unsigned char tag,
                                  const unsigned char *&value,
                                  std::size_t &length)
{
    if (cursor == end || *cursor++ != tag || cursor == end) return false;
    unsigned char first = *cursor++;
    length = first;
    if (first & 0x80) {
        std::size_t octets = first & 0x7f;
        if (octets == 0 || octets > sizeof(std::size_t) ||
            static_cast<std::size_t>(end - cursor) < octets || *cursor == 0) return false;
        length = 0;
        for (std::size_t i = 0; i < octets; ++i) length = (length << 8) | *cursor++;
        if (length < 128) return false;
    }
    if (length > static_cast<std::size_t>(end - cursor)) return false;
    value = cursor;
    cursor += length;
    return true;
}

static inline CertificateKeyStatus checkCertificatePublicKey(const unsigned char *der,
                                                             std::size_t length)
{
    if (der == NULL || length == 0 || length > UINT_MAX) return KeyInvalid;
    const unsigned char *cursor = der;
    const unsigned char *end = der + length;
    const unsigned char *value;
    std::size_t size;
    if (!readDERElement(cursor, end, 0x30, value, size) || cursor != end) return KeyInvalid;
    cursor = value;
    end = value + size;
    if (!readDERElement(cursor, end, 0x30, value, size)) return KeyInvalid;
    cursor = value;
    end = value + size;
    if (cursor != end && *cursor == 0xa0 &&
        !readDERElement(cursor, end, 0xa0, value, size)) return KeyInvalid;
    // serialNumber, signature, issuer, validity, subject.
    const unsigned char tags[] = { 0x02, 0x30, 0x30, 0x30, 0x30 };
    for (std::size_t i = 0; i < sizeof(tags); ++i) {
        if (!readDERElement(cursor, end, tags[i], value, size)) return KeyInvalid;
    }
    const unsigned char *spki = cursor;
    if (!readDERElement(cursor, end, 0x30, value, size)) return KeyInvalid;
    std::size_t spkiLength = static_cast<std::size_t>(cursor - spki);
    unsigned char digest[32];
#if __APPLE__
    if (CC_SHA256(spki, static_cast<CC_LONG>(spkiLength), digest) == NULL) return KeyInvalid;
#else
    if (SHA256(spki, spkiLength, digest) == NULL) return KeyInvalid;
#endif
    const char digits[] = "0123456789abcdef";
    char hex[64];
    for (std::size_t i = 0; i < sizeof(digest); ++i) {
        hex[i * 2] = digits[digest[i] >> 4];
        hex[i * 2 + 1] = digits[digest[i] & 15];
    }
    for (std::size_t i = 0; i < sizeof(blockedPublicKeyHashes) / sizeof(blockedPublicKeyHashes[0]); ++i) {
        if (std::memcmp(hex, blockedPublicKeyHashes[i], sizeof(hex)) == 0) return KeyBlocked;
    }
    return KeyAllowed;
}

} }
#endif
