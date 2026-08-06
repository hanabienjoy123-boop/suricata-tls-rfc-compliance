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
 * See app-layer-ssl-names.h for scope and caveats. This file only
 * contains lookup tables and their binary-search accessors - no parsing
 * logic lives here.
 */

#include "app-layer-ssl-names.h"

/* Sorted by id ascending - required for binary search in
 * TlsNamedGroupGetName(). */
const TlsNamedGroupEntry tls_named_group_table[] = {
    { 0x0001, "sect163k1" },
    { 0x0002, "sect163r1" },
    { 0x0003, "sect163r2" },
    { 0x0004, "sect193r1" },
    { 0x0005, "sect193r2" },
    { 0x0006, "sect233k1" },
    { 0x0007, "sect233r1" },
    { 0x0008, "sect239k1" },
    { 0x0009, "sect283k1" },
    { 0x000a, "sect283r1" },
    { 0x000b, "sect409k1" },
    { 0x000c, "sect409r1" },
    { 0x000d, "sect571k1" },
    { 0x000e, "sect571r1" },
    { 0x000f, "secp160k1" },
    { 0x0010, "secp160r1" },
    { 0x0011, "secp160r2" },
    { 0x0012, "secp192k1" },
    { 0x0013, "secp192r1" },
    { 0x0014, "secp224k1" },
    { 0x0015, "secp224r1" },
    { 0x0016, "secp256k1" },
    { 0x0017, "secp256r1" },
    { 0x0018, "secp384r1" },
    { 0x0019, "secp521r1" },
    { 0x001a, "brainpoolP256r1" },
    { 0x001b, "brainpoolP384r1" },
    { 0x001c, "brainpoolP512r1" },
    { 0x001d, "x25519" },
    { 0x001e, "x448" },
    { 0x001f, "brainpoolP256r1tls13" },
    { 0x0020, "brainpoolP384r1tls13" },
    { 0x0021, "brainpoolP512r1tls13" },
    { 0x0022, "GC256A" },
    { 0x0023, "GC256B" },
    { 0x0024, "GC256C" },
    { 0x0025, "GC256D" },
    { 0x0026, "GC512A" },
    { 0x0027, "GC512B" },
    { 0x0028, "GC512C" },
    { 0x0029, "curveSM2" },
    { 0x0100, "ffdhe2048" },
    { 0x0101, "ffdhe3072" },
    { 0x0102, "ffdhe4096" },
    { 0x0103, "ffdhe6144" },
    { 0x0104, "ffdhe8192" },
    { 0x11eb, "SecP256r1MLKEM768" },
    { 0x11ec, "X25519MLKEM768" },
    { 0x11ed, "SecP384r1MLKEM1024" },
    /* Deprecated pre-standard draft codepoint, superseded by 0x11ec. */
    { 0x6399, "X25519Kyber768Draft00" },
};

const size_t tls_named_group_table_size =
        sizeof(tls_named_group_table) / sizeof(tls_named_group_table[0]);

/* Sorted by id ascending - required for binary search in
 * TlsExtensionGetName(). */
const TlsExtensionEntry tls_extension_table[] = {
    { 0x0000, "server_name" },
    { 0x0001, "max_fragment_length" },
    { 0x0002, "client_certificate_url" },
    { 0x0003, "trusted_ca_keys" },
    { 0x0004, "truncated_hmac" },
    { 0x0005, "status_request" },
    { 0x0006, "user_mapping" },
    { 0x0007, "client_authz" },
    { 0x0008, "server_authz" },
    { 0x0009, "cert_type" },
    /* pre-TLS1.3 name was elliptic_curves */
    { 0x000a, "supported_groups" },
    { 0x000b, "ec_point_formats" },
    { 0x000c, "srp" },
    { 0x000d, "signature_algorithms" },
    { 0x000e, "use_srtp" },
    { 0x000f, "heartbeat" },
    { 0x0010, "application_layer_protocol_negotiation" },
    { 0x0011, "status_request_v2" },
    { 0x0012, "signed_certificate_timestamp" },
    { 0x0013, "client_certificate_type" },
    { 0x0014, "server_certificate_type" },
    { 0x0015, "padding" },
    { 0x0016, "encrypt_then_mac" },
    { 0x0017, "extended_master_secret" },
    { 0x0018, "token_binding" },
    { 0x0019, "cached_info" },
    { 0x001b, "compress_certificate" },
    { 0x001c, "record_size_limit" },
    { 0x0023, "session_ticket" },
    { 0x0029, "pre_shared_key" },
    { 0x002a, "early_data" },
    { 0x002b, "supported_versions" },
    { 0x002c, "cookie" },
    { 0x002d, "psk_key_exchange_modes" },
    { 0x002f, "certificate_authorities" },
    { 0x0030, "oid_filters" },
    { 0x0031, "post_handshake_auth" },
    { 0x0032, "signature_algorithms_cert" },
    { 0x0033, "key_share" },
    { 0xff01, "renegotiation_info" },
};

const size_t tls_extension_table_size =
        sizeof(tls_extension_table) / sizeof(tls_extension_table[0]);

const char *TlsNamedGroupGetName(uint16_t group_id)
{
    int lo = 0;
    int hi = (int)tls_named_group_table_size - 1;

    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        uint16_t mid_id = tls_named_group_table[mid].id;

        if (mid_id == group_id) {
            return tls_named_group_table[mid].name;
        } else if (mid_id < group_id) {
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }

    return NULL;
}

const char *TlsExtensionGetName(uint16_t ext_type)
{
    int lo = 0;
    int hi = (int)tls_extension_table_size - 1;

    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        uint16_t mid_id = tls_extension_table[mid].id;

        if (mid_id == ext_type) {
            return tls_extension_table[mid].name;
        } else if (mid_id < ext_type) {
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }

    return NULL;
}