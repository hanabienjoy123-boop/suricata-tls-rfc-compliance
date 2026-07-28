/* Copyright (C) 2022 Open Information Security Foundation
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

#include "suricata-common.h"
#include "threads.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-buffer.h"
#include "detect-engine-mpm.h"
#include "detect-content.h"

#include "flow.h"
#include "stream-tcp.h"

#include "app-layer.h"
#include "app-layer-ssl.h"
#include "detect-engine-prefilter.h"
#include "detect-tls-cipher-suite.h"

static int DetectTlsClientCipherSuitesSetup(DetectEngineCtx *, Signature *, const char *);
static int DetectTlsServerCipherSuitesSetup(DetectEngineCtx *, Signature *, const char *);

static InspectionBuffer *GetClientCipherSuitesData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id);
static InspectionBuffer *GetServerCipherSuitesData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id);

static int g_tls_client_cipher_suites_buffer_id = 0;
static int g_tls_server_cipher_suites_buffer_id = 0;

void DetectTlsClientCipherSuitesRegister(void)
{
    sigmatch_table[DETECT_TLS_CLIENT_CIPHER_SUITES].name = "tls.ciphers.client";
    sigmatch_table[DETECT_TLS_CLIENT_CIPHER_SUITES].desc =
            "sticky buffer to match on the TLS client cipher suites list";
    sigmatch_table[DETECT_TLS_CLIENT_CIPHER_SUITES].url =
            "/rules/tls-keywords.html#tls-client-cipher-suites";
    sigmatch_table[DETECT_TLS_CLIENT_CIPHER_SUITES].Setup = DetectTlsClientCipherSuitesSetup;
    sigmatch_table[DETECT_TLS_CLIENT_CIPHER_SUITES].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;

    /* ClientHello -> TOSERVER */
    DetectAppLayerInspectEngineRegister("tls.ciphers.client", ALPROTO_TLS, SIG_FLAG_TOSERVER,
            TLS_STATE_CLIENT_HELLO_DONE, DetectEngineInspectBufferGeneric, GetClientCipherSuitesData);
    DetectAppLayerMpmRegister("tls.ciphers.client", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetClientCipherSuitesData, ALPROTO_TLS, TLS_STATE_CLIENT_HELLO_DONE);

    DetectBufferTypeSetDescriptionByName("tls.ciphers.client", "TLS Client Cipher Suites");

    g_tls_client_cipher_suites_buffer_id = DetectBufferTypeGetByName("tls.ciphers.client");
}

void DetectTlsServerCipherSuitesRegister(void)
{
    sigmatch_table[DETECT_TLS_SERVER_CIPHER_SUITES].name = "tls.ciphers.server";
    sigmatch_table[DETECT_TLS_SERVER_CIPHER_SUITES].desc =
            "sticky buffer to match on the TLS server selected cipher suite";
    sigmatch_table[DETECT_TLS_SERVER_CIPHER_SUITES].url =
            "/rules/tls-keywords.html#tls-server-cipher-suites";
    sigmatch_table[DETECT_TLS_SERVER_CIPHER_SUITES].Setup = DetectTlsServerCipherSuitesSetup;
    sigmatch_table[DETECT_TLS_SERVER_CIPHER_SUITES].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;

    /* ServerHello -> TOCLIENT */
    DetectAppLayerInspectEngineRegister("tls.ciphers.server", ALPROTO_TLS, SIG_FLAG_TOCLIENT,
            TLS_STATE_SERVER_HELLO, DetectEngineInspectBufferGeneric, GetServerCipherSuitesData);
    DetectAppLayerMpmRegister("tls.ciphers.server", SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister,
            GetServerCipherSuitesData, ALPROTO_TLS, TLS_STATE_SERVER_HELLO);

    DetectBufferTypeSetDescriptionByName("tls.ciphers.server", "TLS Server Cipher Suites");

    g_tls_server_cipher_suites_buffer_id = DetectBufferTypeGetByName("tls.ciphers.server");
}

/**
 * \brief this function setup the tls.random_time sticky buffer keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0  On success
 * \retval -1 On failure
 */
static int DetectTlsClientCipherSuitesSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, g_tls_client_cipher_suites_buffer_id) < 0)
        return -1;

    if (SCDetectSignatureSetAppProto(s, ALPROTO_TLS) < 0)
        return -1;

    return 0;
}

/**
 * \brief this function setup the tls.random_bytes sticky buffer keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0  On success
 * \retval -1 On failure
 */
static int DetectTlsServerCipherSuitesSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, g_tls_server_cipher_suites_buffer_id) < 0)
        return -1;

    if (SCDetectSignatureSetAppProto(s, ALPROTO_TLS) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetClientCipherSuitesData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const SSLState *ssl_state = (SSLState *)f->alstate;
        const SslCipherAudit *audit = &ssl_state->client_connp.cipher_audit;

        if (!audit->ready || !audit->framing_ok || audit->alloc_failed || audit->count == 0)
            return NULL;

        const uint32_t data_len = (uint32_t)audit->count * 2;

        InspectionBufferSetupAndApplyTransforms(
                det_ctx, list_id, buffer, audit->ciphers, data_len, transforms);
    }
    return buffer;
}

static InspectionBuffer *GetServerCipherSuitesData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const SSLState *ssl_state = (SSLState *)f->alstate;
        const SslCipherAudit *audit = &ssl_state->server_connp.cipher_audit;

        if (!audit->ready || !audit->framing_ok || audit->alloc_failed || audit->count == 0)
            return NULL;

        const uint32_t data_len = (uint32_t)audit->count * 2;

        InspectionBufferSetupAndApplyTransforms(
                det_ctx, list_id, buffer, audit->ciphers, data_len, transforms);
    }
    return buffer;
}