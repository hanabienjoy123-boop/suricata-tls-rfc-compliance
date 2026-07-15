/* Copyright (C) 2026 Open Information Security Foundation
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
 * Implements support for tls.random_reused keyword.
 *
 * Matches when the TLS client random and server random are identical,
 * which should never happen in a legitimate handshake.
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"

#include "flow.h"

#include "app-layer.h"
#include "app-layer-ssl.h"

#include "detect-tls-random-reused.h"

static int DetectTlsRandomReusedSetup(DetectEngineCtx *, Signature *, const char *);
static int DetectTlsRandomReusedMatch(DetectEngineThreadCtx *, Flow *,
        uint8_t, void *, void *, const Signature *, const SigMatchCtx *);

/**
 * \brief Registration function for keyword: tls.random_reused
 */
void DetectTlsRandomReusedRegister(void)
{
    sigmatch_table[DETECT_TLS_RANDOM_REUSED].name = "tls.random_reused";
    sigmatch_table[DETECT_TLS_RANDOM_REUSED].desc =
            "match when the TLS client and server random values are identical";
    sigmatch_table[DETECT_TLS_RANDOM_REUSED].url =
            "/rules/tls-keywords.html#tls-random-reused";
    sigmatch_table[DETECT_TLS_RANDOM_REUSED].AppLayerTxMatch = DetectTlsRandomReusedMatch;
    sigmatch_table[DETECT_TLS_RANDOM_REUSED].Setup = DetectTlsRandomReusedSetup;
    sigmatch_table[DETECT_TLS_RANDOM_REUSED].flags |= SIGMATCH_NOOPT;

    /* Both randoms are only available once the ServerHello has been seen,
     * so we only inspect in the toclient direction. */
    DetectAppLayerInspectEngineRegister("tls.random_reused", ALPROTO_TLS,
            SIG_FLAG_TOCLIENT, TLS_STATE_SERVER_HELLO,
            DetectEngineInspectGenericList, NULL);
}

/**
 * \brief setup function for the tls.random_reused keyword
 *
 * \param de_ctx  detection engine context
 * \param s       signature the keyword belongs to
 * \param str     should be empty (SIGMATCH_NOOPT)
 *
 * \retval 0  on success
 * \retval -1 on failure
 */
static int DetectTlsRandomReusedSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (SCDetectSignatureSetAppProto(s, ALPROTO_TLS) < 0)
        return -1;

    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_TLS_RANDOM_REUSED,
                NULL, DETECT_SM_LIST_MATCH) == NULL) {
        return -1;
    }

    return 0;
}

/**
 * \brief match function: returns 1 when client and server random are equal
 */
static int DetectTlsRandomReusedMatch(DetectEngineThreadCtx *det_ctx, Flow *f,
        uint8_t flags, void *state, void *txv,
        const Signature *s, const SigMatchCtx *m)
{
    const SSLState *ssl_state = (const SSLState *)state;
    if (ssl_state == NULL)
        return 0;

    /* Only compare once both randoms have actually been parsed. */
    if ((ssl_state->flags & (TLS_TS_RANDOM_SET | TLS_TC_RANDOM_SET)) !=
            (TLS_TS_RANDOM_SET | TLS_TC_RANDOM_SET)) {
        return 0;
    }

    if (memcmp(ssl_state->client_connp.random,
                ssl_state->server_connp.random, TLS_RANDOM_LEN) == 0) {
        return 1;
    }

    return 0;
}