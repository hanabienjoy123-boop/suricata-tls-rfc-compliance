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
 * \brief Classification of the ClientKeyExchange wire-format structure a
 *        cipher suite implies. This is orthogonal to TlsCipherMode (which
 *        classifies bulk encryption): a cipher suite's KeyExchangeAlgorithm
 *        determines what ClientKeyExchange.exchange_keys actually contains,
 *        independent of whether the record cipher itself is BLOCK/STREAM/AEAD.
 */
typedef enum {
    TLS_KEX_STRUCT_UNKNOWN = 0,   /**< not classifiable from the name alone
                                    *   (GOST suites, legacy pseudo-suites
                                    *   like TLS_SHA256_SHA256); treat as
                                    *   unreliable, do not parse */
    TLS_KEX_STRUCT_NONE,          /**< TLS 1.3 AEAD suites: no legacy
                                    *   ClientKeyExchange message exists at
                                    *   all; key exchange is negotiated via
                                    *   the key_share extension instead */
    TLS_KEX_STRUCT_RSA,           /**< EncryptedPreMasterSecret (opaque
                                    *   RSA-encrypted blob) */
    TLS_KEX_STRUCT_DH,            /**< ClientDiffieHellmanPublic (dh_Yc);
                                    *   covers both static (dh_dss/dh_rsa)
                                    *   and ephemeral (dhe_dss/dhe_rsa/
                                    *   dh_anon) -- same wire structure */
    TLS_KEX_STRUCT_ECDH,          /**< ClientECDiffieHellmanPublic
                                    *   (ecdh_Yc); covers both static
                                    *   (ecdh_ecdsa/ecdh_rsa) and ephemeral
                                    *   (ecdhe_ecdsa/ecdhe_rsa/ecdh_anon) */
    TLS_KEX_STRUCT_PSK,           /**< psk_identity only, no DH/ECDH/RSA
                                    *   component */
    TLS_KEX_STRUCT_DHE_PSK,       /**< psk_identity + ClientDiffieHellmanPublic */
    TLS_KEX_STRUCT_RSA_PSK,       /**< psk_identity + EncryptedPreMasterSecret */
    TLS_KEX_STRUCT_ECDHE_PSK,     /**< psk_identity + ClientECDiffieHellmanPublic */
    TLS_KEX_STRUCT_SRP,           /**< srp_A (RFC 5054); structurally
                                    *   resembles DH but is a distinct
                                    *   mechanism */
    TLS_KEX_STRUCT_KRB5,          /**< Kerberos ticket-based exchange
                                    *   (RFC 2712); entirely different
                                    *   structure, not DH/RSA-derived */
    TLS_KEX_STRUCT_PWD,           /**< RFC 8492 (ECCPWD/TLS-PWD); PAKE
                                    *   scalar+element structure, distinct
                                    *   from plain ECDH despite the "EC"
                                    *   in the name */
} TlsKeyExchangeStruct;

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
TlsKeyExchangeStruct TLSCipherSuiteGetKexStruct(uint16_t cipher_suite);

static inline bool TLSCipherSuiteIsRC4(uint16_t cipher_suite)
{
    return TLSCipherSuiteGetMode(cipher_suite) == TLS_CIPHER_MODE_STREAM;
}
#endif /* SURICATA_TLS_CIPHER_SUITE_MODE_H */