/* Copyright (C) 2026 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 */

#ifndef SURICATA_TLS_CIPHER_SUITE_MODE_H
#define SURICATA_TLS_CIPHER_SUITE_MODE_H

typedef enum {
    TLS_CIPHER_MODE_NULL,     /* no encryption (WITH_NULL_*) */
    TLS_CIPHER_MODE_STREAM,   /* stream cipher (e.g. RC4) */
    TLS_CIPHER_MODE_BLOCK,    /* block cipher, CBC mode (e.g. AES-CBC, 3DES, DES) */
    TLS_CIPHER_MODE_AEAD,     /* AEAD mode (e.g. GCM, CCM, ChaCha20-Poly1305) */
    TLS_CIPHER_MODE_UNKNOWN,  /* could not be determined from the name */
} TlsCipherMode;

typedef enum {
    TLS_KEX_STRUCT_NONE,       /* no key exchange struct (NULL suite, or
                                 * TLS1.3 suite where kex is via key_share) */
    TLS_KEX_STRUCT_RSA,        /* static RSA / RSA_EXPORT */
    TLS_KEX_STRUCT_DH,         /* DH_DSS / DH_RSA / DHE_DSS / DHE_RSA / DH_anon */
    TLS_KEX_STRUCT_ECDH,       /* ECDH_ECDSA / ECDH_RSA / ECDHE_ECDSA / ECDHE_RSA / ECDH_anon */
    TLS_KEX_STRUCT_PSK,        /* plain PSK */
    TLS_KEX_STRUCT_DHE_PSK,
    TLS_KEX_STRUCT_ECDHE_PSK,
    TLS_KEX_STRUCT_RSA_PSK,
    TLS_KEX_STRUCT_SRP,        /* SRP_SHA / SRP_SHA_RSA / SRP_SHA_DSS */
    TLS_KEX_STRUCT_PWD,        /* TLS-PWD / ECCPWD (Dragonfly) */
    TLS_KEX_STRUCT_KRB5,       /* Kerberos */
    TLS_KEX_STRUCT_UNKNOWN,    /* GOST / non-standard, structure not verified */
} TlsKexStruct;

typedef enum {
    SKE_ABSENT,           /* cipher suite does not send ServerKeyExchange
                            * (key material is in the certificate, or this
                            * is a TLS1.3 suite where key exchange happens
                            * via the key_share extension instead) */
    SKE_DH_SIGNED,         /* ServerDHParams + digitally-signed block
                            * (DHE_DSS / DHE_RSA) */
    SKE_DH_UNSIGNED,       /* ServerDHParams, no signature (DH_anon) */
    SKE_ECDH_SIGNED,       /* ServerECDHParams + digitally-signed block
                            * (ECDHE_RSA / ECDHE_ECDSA) */
    SKE_ECDH_UNSIGNED,     /* ServerECDHParams, no signature (ECDH_anon) */
    SKE_RSA_EXPORT,        /* legacy weak RSA export key + signature
                            * (RSA_EXPORT family, relevant to FREAK) */
    SKE_PSK_HINT_ONLY,     /* only psk_identity_hint, no DH/EC params
                            * (PSK / RSA_PSK) */
    SKE_PSK_DH,            /* psk_identity_hint + ServerDHParams, no
                            * signature (DHE_PSK) */
    SKE_PSK_ECDH,          /* psk_identity_hint + ServerECDHParams, no
                            * signature (ECDHE_PSK) */
    SKE_SRP_SIGNED,        /* ServerSRPParams + signature
                            * (SRP_SHA_RSA / SRP_SHA_DSS) */
    SKE_SRP_UNSIGNED,      /* ServerSRPParams, no signature (SRP_SHA anon) */
    SKE_UNKNOWN,           /* GOST / non-standard suite, structure not
                            * verified - do not attempt to parse, report
                            * an event instead if encountered */
} SkePresence;

typedef enum {
    TLS_DTLS_OK_UNSPEC,
    TLS_DTLS_OK_YES,
    TLS_DTLS_OK_NO,
} TlsDtlsOk;

typedef enum {
    TLS_RECOMMENDED_UNSPEC,
    TLS_RECOMMENDED_YES,
    TLS_RECOMMENDED_NO,
    TLS_RECOMMENDED_DISCOURAGED,   /* IANA "D" - weaker than N, but flagged */
} TlsRecommended;

typedef struct TlsCipherModeEntry_ {
    uint16_t         id;
    TlsCipherMode     mode;
    TlsKexStruct      kex_struct;
    SkePresence       ske_presence;
    TlsDtlsOk         dtls_ok;
    TlsRecommended    recommended;
    const char       *reference;
    const char       *name;
} TlsCipherModeEntry;

TlsCipherMode  TlsCipherModeGet(uint16_t cipher_id);
TlsKexStruct   TlsCipherModeGetKexStruct(uint16_t cipher_id);
SkePresence    TlsCipherModeGetSkePresence(uint16_t cipher_id);
TlsDtlsOk      TlsCipherModeGetDtlsOk(uint16_t cipher_id);
TlsRecommended TlsCipherModeGetRecommended(uint16_t cipher_id);
const char    *TlsCipherModeGetReference(uint16_t cipher_id);
const char    *TlsCipherModeGetName(uint16_t cipher_id);
bool TlsCipherModeIsStream(uint16_t cipher_id);

#endif /* SURICATA_TLS_CIPHER_SUITE_MODE_H */