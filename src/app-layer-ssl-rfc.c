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

#include "suricata-common.h"
#include "app-layer-events.h"
#include "app-layer-ssl-rfc.h"
#include "ssl-cipher-suite-mode.h"

/* Side-channel audit of Hello extensions. Walks only the [type][len]
 * framing to collect extension types and to judge whether the framing is
 * self-consistent. Does not parse any extension body and does not affect
 * the normal parsing path. Result is written to `out`. */
void TLSExtractHSHelloExtTypes(const uint8_t *buf, uint32_t len, SslExtAudit *out)
{
    memset(out, 0, sizeof(*out));

    uint32_t offset = 0;

    if (len == 0) {
        out->framing_ok = true;
        out->ready = true;
        return;
    }

    if (len - offset < 2) {
        out->framing_ok = false;
        out->ready = true;
        return;
    }

    uint16_t ext_total = (uint16_t)((buf[offset] << 8) | buf[offset + 1]);
    offset += 2;

    if (len - offset < ext_total) {
        out->framing_ok = false;
        out->ready = true;
        return;
    }

    const uint32_t block_end = offset + ext_total;

    /* Pass 1: validate framing and count extensions. No writes yet. */
    uint32_t scan_offset = offset;
    uint16_t ext_count = 0;
    while (scan_offset < block_end) {
        if (block_end - scan_offset < 4) {
            out->framing_ok = false;
            out->ready = true;
            return;
        }
        uint16_t elen = (uint16_t)((buf[scan_offset + 2] << 8) | buf[scan_offset + 3]);
        scan_offset += 4;

        if (block_end - scan_offset < elen) {
            out->framing_ok = false;
            out->ready = true;
            return;
        }
        scan_offset += elen;
        ext_count++;
    }

    if (scan_offset != block_end) {
        out->framing_ok = false;
        out->ready = true;
        return;
    }

    /* Framing is fully validated. Allocate exact-size storage. */
    if (ext_count > 0) {
        out->types = SCMalloc(ext_count * sizeof(uint16_t));
        if (out->types == NULL) {
            out->alloc_failed = true; /* OOM: treat as unreliable, same as before */
            out->framing_ok = true;
            out->ready = true;
            return;
        }
    }

    /* Pass 2: fill in the type values. Framing already validated above,
     * so no bounds re-checking needed here. */
    uint32_t fill_offset = offset;
    for (uint16_t i = 0; i < ext_count; i++) {
        uint16_t etype = (uint16_t)((buf[fill_offset] << 8) | buf[fill_offset + 1]);
        uint16_t elen = (uint16_t)((buf[fill_offset + 2] << 8) | buf[fill_offset + 3]);
        out->types[i] = etype;

        if (etype == SSL_EXTENSION_MAX_FRAGMENT_LENGTH && elen == 1) {
            out->max_fragment_length = buf[fill_offset + 4];
        }

        fill_offset += 4 + elen;
    }

    out->count = ext_count;
    out->framing_ok = true;
    out->ready = true;
}

void TLSExtAuditFree(SslExtAudit *audit)
{
    if (audit == NULL) {
        return;
    }
    if (audit->types != NULL) {
        SCFree(audit->types);
        audit->types = NULL;
    }
    audit->count = 0;
}

/**
 * \brief Check a parsed TLS Hello extension list for duplicate extension
 *        types.
 *
 * The check is only meaningful when the audit result is trustworthy: the
 * buffer must have been fully parsed (\a ready) and framing must have
 * landed exactly on the extensions block boundary (\a framing_ok). If
 * either condition is not met, the parse itself is unreliable and no
 * sound duplicate verdict can be made -- return 1 (no violation) to avoid
 * raising a false event off of an unrelated parse failure.
 *
 * \param audit Pointer to a TlsExtAudit filled by TLSExtractHSHelloExtTypes()
 *
 * \retval 1 no duplicate found, or audit data is unreliable
 * \retval 0 a duplicate extension type was found in a trustworthy parse
 */
int TLSExtAuditNoDuplicateExtTypes(const SslExtAudit *audit)
{
    if (audit == NULL) {
        return 1;
    }

    if (!audit->ready || !audit->framing_ok || audit->alloc_failed) {
        SCLogDebug("unreliable TLS ext audit (ready=%u framing_ok=%u "
                   "alloc_failed=%u), skipping duplicate check",
                   audit->ready, audit->framing_ok, audit->alloc_failed);
        return 1;
    }

    for (uint16_t i = 0; i < audit->count; i++) {
        for (uint16_t j = i + 1; j < audit->count; j++) {
            if (audit->types[i] == audit->types[j]) {
                SCLogDebug("duplicate TLS extension type 0x%04x at "
                           "indices %u and %u", audit->types[i], i, j);
                return 0;
            }
        }
    }

    return 1;
}

/**
 * \brief Check whether every server-offered extension was also offered
 *        by the client (RFC 8446 4.2: a server MUST NOT send an
 *        extension the client did not first offer).
 *
 * \param client_audit Client Hello extension audit
 * \param server_audit Server Hello extension audit
 *
 * \retval 1 all server extensions are a subset of client's, or audit
 *           data is unreliable
 * \retval 0 the server sent an extension type not offered by the client
 */
int TLSExtAuditServerExtsSubsetOfClient(
        const SslExtAudit *client_audit, const SslExtAudit *server_audit)
{
    if (client_audit == NULL || server_audit == NULL) {
        return 1;
    }
    
    if (!client_audit->ready || !client_audit->framing_ok || client_audit->alloc_failed ||
            !server_audit->ready || !server_audit->framing_ok || server_audit->alloc_failed) {
        SCLogDebug("unreliable client/server ext audit, skipping subset check");
        return 1;
    }

    for (uint16_t i = 0; i < server_audit->count; i++) {
        uint16_t stype = server_audit->types[i];
        int offered = 0;

        for (uint16_t j = 0; j < client_audit->count; j++) {
            if (client_audit->types[j] == stype) {
                offered = 1;
                break;
            }
        }

        if (!offered) {
            SCLogDebug("server extension type 0x%04x not offered by client", stype);
            return 0;
        }
    }

    return 1;
}

/**
 * \brief Check that the server did not negotiate/echo a GREASE extension
 *        type (RFC 8701: a client MUST reject a GREASE value appearing
 *        in any ServerHello extension).
 *
 * \param server_audit Server Hello extension audit
 *
 * \retval 1 no GREASE value present, or audit data is unreliable
 * \retval 0 a GREASE extension type was found among server extensions
 */
int TLSExtAuditServerNoGreaseNegotiated(const SslExtAudit *server_audit)
{
    if (server_audit == NULL) {
        return 1;
    }

    if (!server_audit->ready || !server_audit->framing_ok || server_audit->alloc_failed) {
        SCLogDebug("unreliable server ext audit, skipping GREASE check");
        return 1;
    }

    for (uint16_t i = 0; i < server_audit->count; i++) {
        if (TLS_EXT_IS_GREASE(server_audit->types[i])) {
            SCLogDebug("server negotiated GREASE extension type 0x%04x",
                       server_audit->types[i]);
            return 0;
        }
    }

    return 1;
}

/**
 * \brief Check that the server did not send a signature_algorithms
 *        extension. Per RFC 8446 4.2.3, signature_algorithms is a
 *        client-only extension (sent in ClientHello / CertificateRequest)
 *        and MUST NOT appear in ServerHello or EncryptedExtensions --
 *        even if the client happened to offer it, so this is not covered
 *        by the subset check.
 *
 * \param server_audit Server Hello extension audit
 *
 * \retval 1 no signature_algorithms extension present, or audit data is
 *           unreliable
 * \retval 0 the server sent a signature_algorithms extension
 */
int TLSExtAuditServerNoSignatureAlgorithms(const SslExtAudit *server_audit)
{
    if (server_audit == NULL) {
        return 1;
    }

    if (!server_audit->ready || !server_audit->framing_ok || server_audit->alloc_failed) {
        SCLogDebug("unreliable server ext audit, skipping signature_algorithms check");
        return 1;
    }

    for (uint16_t i = 0; i < server_audit->count; i++) {
        if (server_audit->types[i] == SSL_EXT_SIGNATURE_ALGORITHMS) {
            SCLogDebug("server sent disallowed signature_algorithms extension");
            return 0;
        }
    }

    return 1;
}

/**
 * \brief Check that, if present, the "pre_shared_key" extension is the
 *        last extension in the ClientHello.
 *
 * RFC 8446 Section 4.2.11: "The 'pre_shared_key' extension MUST be the
 * last extension in the ClientHello (this facilitates implementation as
 * described below). Servers MUST check that it is the last extension
 * and otherwise fail the handshake with an 'illegal_parameter' alert."
 *
 * This rule applies to the ClientHello only -- pre_shared_key may appear
 * anywhere in the ServerHello extensions block, so this check must not
 * be applied to server-side audits.
 *
 * Duplicate occurrences of pre_shared_key are not this function's
 * concern; that is covered by TLSExtAuditNoDuplicateExtTypes(). If the
 * type does appear more than once, only its first occurrence's position
 * is evaluated here.
 *
 * \param client_audit ClientHello extension audit
 *
 * \retval 1 pre_shared_key is absent, or present and last, or audit
 *           data is unreliable (caller should not raise an event)
 * \retval 0 pre_shared_key is present but not the last extension
 */
int TLSExtAuditPreSharedKeyIsLast(const SslExtAudit *client_audit)
{
    if (client_audit == NULL) {
        return 1;
    }

    if (!client_audit->ready || !client_audit->framing_ok || client_audit->alloc_failed) {
        SCLogDebug("unreliable client ext audit (ready=%u framing_ok=%u "
                   "alloc_failed=%u), skipping pre_shared_key position check",
                   client_audit->ready, client_audit->framing_ok, client_audit->alloc_failed);
        return 1;
    }

    if (client_audit->count == 0) {
        return 1;
    }

    for (uint16_t i = 0; i < client_audit->count; i++) {
        if (client_audit->types[i] == SSL_EXT_PRE_SHARED_KEY) {
            if (i != (uint16_t)(client_audit->count - 1)) {
                SCLogDebug("pre_shared_key extension not last "
                           "(index %u of %u total extensions)",
                           i, client_audit->count);
                return 0;
            }
            /* found at the last position: valid, nothing more to check */
            break;
        }
    }

    return 1;
}

/**
 * \brief Check that, if a max_fragment_length extension was seen, its
 *        value falls within the range defined by RFC 6066 Section 4
 *        (1..4, corresponding to 512/1024/2048/4096 bytes).
 *
 * A value of 0 is treated as "extension not present" (see
 * TLSExtractHSHelloExtTypes()), not as a violation -- there is no way to
 * distinguish an absent extension from a genuinely malformed extension
 * whose single payload byte happens to be 0x00, since that byte is never
 * stored in that case. In practice a peer sending 0x00 as the value is
 * itself non-conformant, but this function cannot detect that specific
 * case; it can only catch values 5-255, which are unambiguously invalid
 * whenever the extension is otherwise well-formed.
 *
 * \param audit Extension audit for either side of the handshake
 *
 * \retval 1 no max_fragment_length extension present, its value is
 *           within 1..4, or the audit data is unreliable
 * \retval 0 a max_fragment_length extension was present with a value
 *           outside 1..4
 */
int TLSExtAuditMaxFragmentLengthValid(const SslExtAudit *audit)
{
    if (audit == NULL) {
        return 1;
    }

    if (!audit->ready || !audit->framing_ok || audit->alloc_failed) {
        SCLogDebug("unreliable ext audit, skipping max_fragment_length check");
        return 1;
    }

    if (audit->max_fragment_length == 0) {
        /* not present (or, ambiguously, a malformed 0x00 payload -- see
         * function-level comment) */
        return 1;
    }

    if (audit->max_fragment_length > 4) {
        SCLogDebug("max_fragment_length value %u out of RFC 6066 range (1-4)",
                   audit->max_fragment_length);
        return 0;
    }

    return 1;
}

/**
 * \brief Check that, if the server responded with a max_fragment_length
 *        extension, its value matches the one the client requested.
 *
 * RFC 6066 Section 4: "if a client receives a maximum fragment length
 * negotiation response that differs from the length it requested, it
 * MUST also abort the handshake with an 'illegal_parameter' alert."
 *
 * This is distinct from TLSExtAuditMaxFragmentLengthValid(), which only
 * checks that a value is within the legal 1-4 range; a server can send a
 * perfectly legal value that simply isn't the one the client asked for.
 * It is also distinct from TLSExtAuditServerExtsSubsetOfClient(), which
 * catches the server sending an extension type the client never offered
 * at all -- here both sides did offer/negotiate the extension, only the
 * negotiated value itself is wrong.
 *
 * If the client did not request this extension, or the server chose not
 * to respond with it, there is nothing to compare and no violation.
 *
 * \param client_audit ClientHello extension audit
 * \param server_audit ServerHello extension audit
 *
 * \retval 1 no mismatch (including: extension absent on either side), or
 *           audit data is unreliable
 * \retval 0 both sides negotiated max_fragment_length but the server's
 *           value does not match the client's requested value
 */
int TLSExtAuditMaxFragmentLengthMatchesRequest(
        const SslExtAudit *client_audit, const SslExtAudit *server_audit)
{
    if (client_audit == NULL || server_audit == NULL) {
        return 1;
    }

    if (!client_audit->ready || !client_audit->framing_ok || client_audit->alloc_failed ||
            !server_audit->ready || !server_audit->framing_ok || server_audit->alloc_failed) {
        SCLogDebug("unreliable client/server ext audit, skipping "
                   "max_fragment_length match check");
        return 1;
    }

    if (client_audit->max_fragment_length == 0 || server_audit->max_fragment_length == 0) {
        /* not negotiated on one (or both) sides: nothing to compare */
        return 1;
    }

    if (client_audit->max_fragment_length != server_audit->max_fragment_length) {
        SCLogDebug("max_fragment_length mismatch: client requested %u, "
                   "server responded %u",
                   client_audit->max_fragment_length, server_audit->max_fragment_length);
        return 0;
    }

    return 1;
}

/**
 * \brief Side-channel audit of the cipher_suites field. Mirrors the
 * branching in TLSDecodeHSHelloCipherSuites(): ClientHello carries a
 * 2-byte cipher_suites_length prefix followed by the list; ServerHello
 * has no length prefix and is always exactly one 2-byte selected cipher
 * suite. Called at the top of TLSDecodeHSHelloCipherSuites() with the
 * same initial_input/input_len as the main parse; does not affect it.
 */
void TLSExtractHSHelloCipherSuites(const uint8_t *buf, uint32_t len, TlsHandshakeDirection direction, SslCipherAudit *out)
{
    memset(out, 0, sizeof(*out));

    uint32_t offset = 0;
    uint16_t list_len;

    if (direction == TLS_HS_DIRECTION_SERVER) {
        if (len < 2) {
            out->framing_ok = false;
            out->ready = true;
            return;
        }
        list_len = 2;
    } else if (direction == TLS_HS_DIRECTION_CLIENT) {
        if (len < 2) {
            out->framing_ok = false;
            out->ready = true;
            return;
        }
        list_len = (uint16_t)((buf[0] << 8) | buf[1]);
        offset = 2;

        if (len - offset < list_len) {
            out->framing_ok = false;
            out->ready = true;
            return;
        }
    } else {
        SCLogDebug("invalid direction %d for TLS cipher_suites audit", direction);
        out->framing_ok = false;
        out->ready = true;
        return;
    }

    if (list_len == 0) {
        out->framing_ok = false;
        out->ready = true;
        return;
    }

    if ((list_len % 2) != 0) {
        out->framing_ok = false;
        out->ready = true;
        return;
    }

    uint16_t count = (uint16_t)(list_len / 2);

    out->ciphers = SCMalloc((size_t)count * 2);
    if (out->ciphers == NULL) {
        out->alloc_failed = true;
        out->framing_ok = true;
        out->ready = true;
        return;
    }

    memcpy(out->ciphers, buf + offset, (size_t)count * 2);

    out->count = count;
    out->framing_ok = true;
    out->ready = true;
}
/**
 * \brief Free the dynamically allocated cipher list inside a
 *        SslCipherAudit and reset it to an empty state.
 *
 * Idempotent: safe to call multiple times, or on an audit that was
 * never populated (ciphers == NULL).
 *
 * \param audit Pointer to the audit to free. NULL is a safe no-op.
 */
void TLSCipherAuditFree(SslCipherAudit *audit)
{
    if (audit == NULL) {
        return;
    }
    if (audit->ciphers != NULL) {
        SCFree(audit->ciphers);
        audit->ciphers = NULL;
    }
    audit->count = 0;
}
/**
 * \retval 1 server's selected cipher is in client's offered list, or
 *           audit data is unreliable
 * \retval 0 server selected a cipher the client never offered
 */
int TLSCipherAuditServerSelectedInClientList(
        const SslCipherAudit *client_audit, const SslCipherAudit *server_audit)
{
    if (client_audit == NULL || server_audit == NULL) {
        return 1;
    }
    if (!client_audit->ready || !client_audit->framing_ok || client_audit->alloc_failed ||
            !server_audit->ready || !server_audit->framing_ok || server_audit->alloc_failed) {
        return 1;
    }
    if (server_audit->count == 0) {
        return 1; /* server hasn't selected yet / nothing to check */
    }

    const uint8_t *selected = server_audit->ciphers;
    for (uint16_t i = 0; i < client_audit->count; i++) {
        const uint8_t *entry = client_audit->ciphers + (size_t)i * 2;
        if (entry[0] == selected[0] && entry[1] == selected[1]) {
            return 1;
        }
    }
    return 0;
}

/**
 * \retval 1 server's selected cipher is not a GREASE value, or audit
 *           data is unreliable / not yet negotiated
 * \retval 0 server selected a GREASE cipher suite value
 */
int TLSCipherAuditServerNoGreaseSelected(const SslCipherAudit *server_audit)
{
    if (server_audit == NULL) {
        return 1;
    }
    if (!server_audit->ready || !server_audit->framing_ok || server_audit->alloc_failed) {
        return 1;
    }
    if (server_audit->count == 0) {
        return 1;
    }

    uint16_t selected = (uint16_t)((server_audit->ciphers[0] << 8) | server_audit->ciphers[1]);

    if (TLS_EXT_IS_GREASE(selected)) {
        return 0;
    }
    return 1;
}

/**
 * \brief Check whether the server selected an RC4 cipher suite.
 *        Corresponds to RFC 7465 rule #2 (server MUST NOT select RC4).
 *
 * \retval 1 server did not select RC4, or audit data is unreliable /
 *           not yet negotiated
 * \retval 0 server selected an RC4 cipher suite (RFC 7465 violation)
 */
int TLSCipherAuditServerIsRC4(const SslCipherAudit *server_audit)
{
    if (server_audit == NULL) {
        return 1;
    }
    if (!server_audit->ready || !server_audit->framing_ok || server_audit->alloc_failed) {
        return 1;
    }
    if (server_audit->count == 0) {
        return 1;
    }

    uint16_t selected = (uint16_t)((server_audit->ciphers[0] << 8) | server_audit->ciphers[1]);

    if (TLSCipherSuiteIsRC4(selected)) {
        return 0;
    }
    return 1;
}

/**
 * \brief Check whether the client proposed at least one RC4 cipher suite.
 *        Corresponds to RFC 7465 rule #1 (client MUST NOT include RC4
 *        cipher suites in ClientHello).
 *
 * \retval 1 client did not propose RC4, or audit data is unreliable /
 *           not yet parsed
 * \retval 0 client proposed at least one RC4 cipher suite (RFC 7465 violation)
 */
int TLSCipherAuditClientProposedRC4(const SslCipherAudit *client_audit)
{
    if (client_audit == NULL) {
        return 1;
    }
    if (!client_audit->ready || !client_audit->framing_ok || client_audit->alloc_failed) {
        return 1;
    }
    if (client_audit->count == 0) {
        return 1;
    }

    for (uint16_t i = 0; i < client_audit->count; i++) {
        uint16_t c = (uint16_t)((client_audit->ciphers[i * 2] << 8) |
                                 client_audit->ciphers[i * 2 + 1]);
        if (TLSCipherSuiteIsRC4(c)) {
            return 0;
        }
    }
    return 1;
}

/**
 * \brief Check whether the client's cipher suite list consisted
 *        exclusively of RC4 cipher suites.
 *        Corresponds to RFC 7465 rule #3 (if the client only offers
 *        RC4, the server MUST terminate the handshake). This function
 *        only reports the client-side condition; it does not verify
 *        the server actually terminated the handshake.
 *
 * \retval 1 client offered at least one non-RC4 cipher suite, or audit
 *           data is unreliable / not yet parsed
 * \retval 0 client's entire cipher suite list was RC4-only
 *           (RFC 7465 rule #3 condition met)
 */
int TLSCipherAuditClientOnlyRC4(const SslCipherAudit *client_audit)
{
    if (client_audit == NULL) {
        return 1;
    }
    if (!client_audit->ready || !client_audit->framing_ok || client_audit->alloc_failed) {
        return 1;
    }
    if (client_audit->count == 0) {
        return 1;
    }

    for (uint16_t i = 0; i < client_audit->count; i++) {
        uint16_t c = (uint16_t)((client_audit->ciphers[i * 2] << 8) |
                                 client_audit->ciphers[i * 2 + 1]);
        if (!TLSCipherSuiteIsRC4(c)) {
            return 1;
        }
    }
    return 0;
}