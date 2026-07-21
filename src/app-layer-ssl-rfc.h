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

/* GREASE values reserved by RFC 8701: 0x?A?A pattern */
#define TLS_EXT_IS_GREASE(x) (((x) & 0x0F0F) == 0x0A0A)

/* signature_algorithms is a client-only extension per RFC 8446 4.2.3;
 * it MUST NOT appear in ServerHello / EncryptedExtensions. */
#define SSL_EXT_SIGNATURE_ALGORITHMS 0x000d

/* pre_shared_key extension type, RFC 8446 Section 4.2.11 */
#define SSL_EXT_PRE_SHARED_KEY 0x0029

/* Maximum number of extension types recorded from a single Hello.
 * Beyond this the list is truncated and the `truncated` flag is set. */
#define SSL_EXT_AUDIT_MAX 64


/**
 * \brief Structure to audit and store extracted TLS Hello Extension types.
 */
typedef struct SslExtAudit_ {
    uint16_t types[SSL_EXT_AUDIT_MAX]; /**< Extension types in order (including GREASE) */
    uint16_t count;                    /**< Number of entries actually stored */

    uint8_t ready;        /**< This side's Hello extensions have been parsed */
    uint8_t framing_ok;   /**< Frame consumed exactly to the boundary (trust premise) */
    uint8_t truncated;    /**< More than MAX extensions seen; types[] is incomplete */
} SslExtAudit;

void TLSExtractHSHelloExtTypes(const uint8_t *buf, uint32_t len, SslExtAudit *out);
int TLSExtAuditNoDuplicateExtTypes(const SslExtAudit *audit);
int TLSExtAuditServerExtsSubsetOfClient(const SslExtAudit *client_audit, const SslExtAudit *server_audit);
int TLSExtAuditServerNoGreaseNegotiated(const SslExtAudit *server_audit);
int TLSExtAuditServerNoSignatureAlgorithms(const SslExtAudit *server_audit);
int TLSExtAuditPreSharedKeyIsLast(const SslExtAudit *client_audit);

#endif /* SURICATA_APP_LAYER_TLS_RFC_H */
