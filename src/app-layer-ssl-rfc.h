/* Copyright (C) 2017 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Hu Jingbin <hanabienjoy123@gmail.com>
 */

#ifndef SURICATA_APP_LAYER_TLS_RFC_H
#define SURICATA_APP_LAYER_TLS_RFC_H

#include "ssl-cipher-suite-mode.h"

/* GREASE values reserved by RFC 8701: 0x?A?A pattern */
#define TLS_EXT_IS_GREASE(x) (((x) & 0x0F0F) == 0x0A0A)

/* signature_algorithms is a client-only extension per RFC 8446 4.2.3;
 * it MUST NOT appear in ServerHello / EncryptedExtensions. */
#define SSL_EXT_SIGNATURE_ALGORITHMS 0x000d

/* pre_shared_key extension type, RFC 8446 Section 4.2.11 */
#define SSL_EXT_PRE_SHARED_KEY 0x0029
/* status_request extension type, RFC 8446 Section 4.2.10 */
#define SSL_EXTENSION_STATUS_REQUEST 0x0005

/* max_fragment_length extension type, RFC 6066 Section 4 */
#define SSL_EXTENSION_MAX_FRAGMENT_LENGTH       0x0001
// encrypt_then_mac extension type, RFC 7366 Section 3
#define SSL_EXTENSION_ENCRYPT_THEN_MAC          0x0016
/**
 * \brief Structure to audit and store extracted TLS Hello Extension types.
 */

typedef enum {
    TLS_HS_DIRECTION_CLIENT = 0,
    TLS_HS_DIRECTION_SERVER = 1,
} TlsHandshakeDirection;

typedef struct SslExtAudit_ {
    uint16_t *types; /**< Dynamically allocated; NULL if no extensions or audit not yet run. Owned by this struct. */
    uint16_t count;                    /**< Number of entries actually stored */
    uint8_t ready;        /**< This side's Hello extensions have been parsed */
    uint8_t framing_ok;   /**< Frame consumed exactly to the boundary (trust premise) */
    uint8_t alloc_failed; /**< SCMalloc() for types[] failed (OOM);*   types is NULL and count is 0. Treated as*   unreliable, same as a framing failure. */
    uint8_t max_fragment_length; /**< If the max_fragment_length extension was present, this is the value. Otherwise 0. */
} SslExtAudit;

typedef struct SslCipherAudit_ {
    uint8_t *ciphers;   /**< Dynamically allocated. NULL if none or audit
                          *   not yet run. Owned by this struct. Raw
                          *   network-byte-order bytes, 2 bytes per cipher
                          *   suite entry, NOT converted to host uint16_t.
                          *   For ServerHello this will contain at most
                          *   one entry (the selected cipher suite). */
    uint16_t count;      /**< number of cipher suite entries (NOT byte count) */

    uint8_t ready;
    uint8_t framing_ok;
    uint8_t alloc_failed;
} SslCipherAudit;

typedef struct SslDhPublicAudit_ {
    uint8_t *share;        /**< Dynamically allocated raw dh_Yc bytes,
                             *   big-endian. NULL if not yet parsed or
                             *   parse failed. Owned by this struct. */
    uint16_t share_len;    /**< Length of share in bytes. 0 if absent. */

    uint8_t ready;
    uint8_t framing_ok;
    uint8_t alloc_failed;
} SslDhPublicAudit;

typedef struct SslSupportedGroups_ {
    uint8_t *groups;    /**< Dynamically allocated. NULL if none or audit
                          *   not yet run. Owned by this struct. Raw
                          *   network-byte-order bytes, 2 bytes per group
                          *   entry. GREASE entries are filtered out and not
                          *   stored. */
    uint16_t count;      /**< number of group entries (NOT byte count) */

    uint8_t ready;
    uint8_t framing_ok;
    uint8_t alloc_failed;
} SslSupportedGroups;

void TLSExtractHSHelloExtTypes(const uint8_t *buf, uint32_t len, SslExtAudit *out);
void TLSExtAuditFree(SslExtAudit *audit);
int TLSExtAuditNoDuplicateExtTypes(const SslExtAudit *audit);
int TLSExtAuditServerExtsSubsetOfClient(const SslExtAudit *client_audit, const SslExtAudit *server_audit);
int TLSExtAuditServerNoGreaseNegotiated(const SslExtAudit *server_audit);
int TLSExtAuditServerNoSignatureAlgorithms(const SslExtAudit *server_audit);
int TLSExtAuditPreSharedKeyIsLast(const SslExtAudit *client_audit);
int TLSExtAuditMaxFragmentLengthValid(const SslExtAudit *audit);
int TLSExtAuditMaxFragmentLengthMatchesRequest(const SslExtAudit *client_audit, const SslExtAudit *server_audit);
int TLSExtAuditServerStatusRequestOfferedByClient(
        const SslExtAudit *client_audit, const SslExtAudit *server_audit);
//section for cipher suites audition
void TLSExtractHSHelloCipherSuites(const uint8_t *buf, uint32_t len, TlsHandshakeDirection direction, SslCipherAudit *out);
void TLSCipherAuditFree(SslCipherAudit *audit);
int TLSCipherAuditServerSelectedInClientList(const SslCipherAudit *client_audit, const SslCipherAudit *server_audit);
int TLSCipherAuditServerNoGreaseSelected(const SslCipherAudit *server_audit);
int TLSCipherAuditServerIsRC4(const SslCipherAudit *server_audit);
int TLSCipherAuditClientOnlyRC4(const SslCipherAudit *client_audit);
int TLSCipherAuditClientProposedRC4(const SslCipherAudit *client_audit);
int TLSExtAuditServerEncryptThenMacRequiresBlockCipher(
        const SslExtAudit *server_ext_audit, const SslCipherAudit *server_cipher_audit);
int TLSCipherAuditServerIsDeprecated(const SslCipherAudit *server_audit);

//section for supported groups audition
void TLSExtractHSHelloSupportedGroups(
        const uint8_t *buf, uint32_t len, SslSupportedGroups *out);
void TLSSupportedGroupsAuditFree(SslSupportedGroups *audit);
#endif /* SURICATA_APP_LAYER_TLS_RFC_H */
