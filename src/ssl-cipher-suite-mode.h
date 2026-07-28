/* Copyright (C) 2026 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 */

#ifndef SURICATA_TLS_CIPHER_SUITE_MODE_H
#define SURICATA_TLS_CIPHER_SUITE_MODE_H

/**
 * \brief Cipher-mode classification used to determine whether a cipher
 *        suite is a standard block cipher with distinct encrypt/MAC
 *        operations (RFC 7366 Section 3), or a stream/AEAD/NULL cipher
 *        for which the encrypt_then_mac extension has no meaning.
 */
typedef enum {
    TLS_CIPHER_MODE_UNKNOWN = 0, /**< not found in the classification table;
                                   *   treat as unreliable */
    TLS_CIPHER_MODE_BLOCK,       /**< CBC-mode block cipher; encrypt_then_mac
                                   *   (RFC 7366) applies */
    TLS_CIPHER_MODE_STREAM,      /**< e.g. RC4; encrypt_then_mac does not
                                   *   apply */
    TLS_CIPHER_MODE_AEAD,        /**< GCM/CCM/ChaCha20-Poly1305/etc; already
                                   *   authenticated, encrypt_then_mac does
                                   *   not apply */
    TLS_CIPHER_MODE_NULL,        /**< no encryption (or integrity-only);
                                   *   encrypt_then_mac does not apply */
} TlsCipherMode;

/**
 * \brief Look up the cipher-mode classification for a given cipher suite
 *        value, per the IANA TLS Cipher Suites registry.
 *
 * \param cipher_suite the 2-byte cipher suite value
 *
 * \return the classification, or TLS_CIPHER_MODE_UNKNOWN if the value is
 *         not present in the table
 */
TlsCipherMode TLSCipherSuiteGetMode(uint16_t cipher_suite);
const char *TLSCipherSuiteGetName(uint16_t cipher_suite);

static inline bool TLSCipherSuiteIsRC4(uint16_t cipher_suite)
{
    return TLSCipherSuiteGetMode(cipher_suite) == TLS_CIPHER_MODE_STREAM;
}
#endif /* SURICATA_TLS_CIPHER_SUITE_MODE_H */