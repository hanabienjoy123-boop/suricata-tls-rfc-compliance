/* Copyright (C) 2007-2024 Open Information Security Foundation
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
 * Lookup tables for translating TLS numeric identifiers into their
 * human-readable IANA names. Two independent namespaces are covered:
 *
 *   - TLS Supported Groups (NamedGroup values used in the
 *     elliptic_curves / supported_groups extension and in key_share)
 *   - TLS ExtensionType values (the extension type field seen in
 *     ClientHello / ServerHello extensions)
 *
 * These tables are for debug/logging readability only - they play no
 * role in parsing correctness. Entries were compiled from general
 * knowledge of the IANA registries and have NOT been cross-checked
 * against the registry CSVs entry-by-entry the way tls_cipher_mode_table
 * was. Treat lookups here as "best effort naming", not as an
 * authoritative source - if you need to depend on this data for
 * anything beyond log output, verify against the current IANA registry
 * first:
 *   - https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8  (Supported Groups)
 *   - https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-extensiontype-values  (ExtensionType)
 */

#ifndef SURICATA_APP_LAYER_SSL_NAMES_H
#define SURICATA_APP_LAYER_SSL_NAMES_H

#include <stdint.h>
#include <stddef.h>

typedef struct TlsNamedGroupEntry_ {
    uint16_t     id;
    const char  *name;
} TlsNamedGroupEntry;

typedef struct TlsExtensionEntry_ {
    uint16_t     id;
    const char  *name;
} TlsExtensionEntry;

extern const TlsNamedGroupEntry tls_named_group_table[];
extern const size_t tls_named_group_table_size;

extern const TlsExtensionEntry tls_extension_table[];
extern const size_t tls_extension_table_size;

/**
 * \brief Look up the human-readable name of a TLS NamedGroup value.
 * \param group_id NamedGroup value (e.g. from supported_groups or key_share)
 * \retval Name string (e.g. "x25519") on success, NULL if not found in
 *         the table (includes GREASE values, which are intentionally
 *         not listed here).
 */
const char *TlsNamedGroupGetName(uint16_t group_id);

/**
 * \brief Look up the human-readable name of a TLS extension type.
 * \param ext_type Extension type value from a Hello extension list
 * \retval Name string (e.g. "server_name") on success, NULL if not
 *         found in the table.
 */
const char *TlsExtensionGetName(uint16_t ext_type);

#endif /* SURICATA_APP_LAYER_SSL_NAMES_H */