/*
 * Copyright (c) 2026 European Commission
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the European
 * Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work
 * except in compliance with the Licence.
 *
 * You may obtain a copy of the Licence at:
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF
 * ANY KIND, either express or implied. See the Licence for the specific language
 * governing permissions and limitations under the Licence.
 */

package eu.europa.ec.zkplogic

import com.kss.euid.zk.sdk.IdentityStatement
import com.kss.euid.zk.sdk.IssuerKey
import com.kss.euid.zk.sdk.NatMode
import com.kss.euid.zk.sdk.PredicateMode
import com.kss.euid.zk.sdk.ProductPublicStatementV1
import com.kss.euid.zk.sdk.ZkPublicStatement
import com.kss.euid.zk.sdk.ZkSystemKind
import com.kss.euid.zk.sdk.demoIssuerPublicKey
import com.kss.euid.zk.sdk.demoRevocationEpoch
import com.kss.euid.zk.sdk.demoRevocationPublicKey
import com.kss.euid.zk.sdk.predicateModeFromToken
import com.kss.euid.zk.sdk.predicateModeUsesAge
import com.kss.euid.zk.sdk.predicateModeUsesNat
import com.kss.euid.zk.sdk.resultAgeOver
import com.kss.euid.zk.sdk.ts13DemoCircuitHash
import com.kss.euid.zk.sdk.zkSystem
import kotlinx.io.bytestring.ByteString
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.toDataItem
import org.multipaz.crypto.EcPublicKey
import org.multipaz.crypto.EcPublicKeyDoubleCoordinate
import org.multipaz.mdoc.response.MdocDocument
import org.multipaz.mdoc.zkp.ZkDocument
import org.multipaz.mdoc.zkp.ZkDocumentData
import org.multipaz.mdoc.zkp.ZkSystemSpec
import java.security.MessageDigest
import kotlin.time.Instant

/**
 * Public statement at proving time. The issuer trust anchor depends on the linked ZK system
 * ([zkSystem]): ML-DSA pins the **demo** issuer's `pkEncode` hash (the in-memory re-signed doc
 * re-issues the PID under it), while P-256 reads the real issuer key from the presented document's
 * x5chain. `today` derives from the proof [timestamp].
 */
fun ZkPublicStatement.Companion.forProver(
    spec: ZkSystemSpec,
    document: MdocDocument,
    sessionTranscript: DataItem,
    timestamp: Instant
): ZkPublicStatement {
    val mode = PredicateMode.from(spec)
    val minAge = spec.getParam<Long>(ZK_CONTRACT.paramMinAge)
    val accepted = spec.getParam<String>(ZK_CONTRACT.paramAcceptedCountries)
        ?.split(",")
        ?.mapNotNull { it.trim().toUIntOrNull() }

    val issuerKey = when (zkSystem()) {
        // Demo ML-DSA issuer: the in-memory re-signed doc re-issues the PID under it.
        ZkSystemKind.ML_DSA -> IssuerKey.MlDsa(sha256(demoIssuerPublicKey()))
        // P-256: the real issuer key from the presented document's x5chain.
        ZkSystemKind.P256 -> {
            val (keyX, keyY) = document.issuerCertChain.certificates.first().ecPublicKey.toXY()
            IssuerKey.P256(keyX, keyY)
        }
    }

    // ponytail: Ts13DemoV1 path — a single equality proof of the verifier-requested age-over element.
    // The threshold flows from the request (min_age on the matched spec), NOT hardcoded. NOTE: the
    // circuit on this branch is fixed to age_over_18 (MdocPidRequest carries no threshold), so only a
    // min_age of 18 actually verifies until the circuit is parameterized. ML-DSA-only (issuerKey above
    // is unused here). Flip back to ProductV1(ProductPublicStatementV1(...)) for the flat P-256 SDK.
    return ZkPublicStatement.Ts13DemoV1(
        IdentityStatement(
            circuitHash = ts13DemoCircuitHash(),
            zkSystemId = spec.id,
            documentType = ZK_CONTRACT.doctypePid,
            namespace = ZK_CONTRACT.pidNamespace,
            elementIdentifier = resultAgeOver(
                requireNotNull(minAge) { "ZK age-over proof requires a min_age param" }.toUInt()
            ),
            expectedValueCbor = byteArrayOf(0xF5.toByte()), // CBOR true
            timestampEpochSeconds = timestamp.epochSeconds,
            sessionTranscript = Cbor.encode(sessionTranscript),
            trustedIssuerPublicKey = demoIssuerPublicKey(),
            revocationPublicKey = demoRevocationPublicKey(),
            revocationEpoch = demoRevocationEpoch(),
        ),
    )
}

/**
 * Public statement at verify time. Unsupported wallet-side for the ML-DSA (post-quantum) flow: the PQ
 * mdoc carries no `x5chain`, so there is no issuer key to recover from the [ZkDocument]. The verifier
 * app pins the trusted issuer key hash from its own trust store and builds the statement there. This
 * path has no non-test caller in the wallet (real verification happens in the verifier app); wire it
 * only if the wallet ever needs to self-verify PQ proofs.
 */
@Suppress("UNUSED_PARAMETER")
fun ZkPublicStatement.Companion.forVerifier(
    spec: ZkSystemSpec,
    zkDocument: ZkDocument,
    sessionTranscript: DataItem,
): ZkPublicStatement = throw NotImplementedError(
    "ML-DSA verify-side issuer-key sourcing is not wired wallet-side (no x5chain in the PQ mdoc; " +
        "the verifier app pins the trusted issuer key hash)."
)

/** Wraps the proof + asserted boolean results into a Multipaz [ZkDocument]. */
fun ZkDocument.Companion.from(
    spec: ZkSystemSpec,
    document: MdocDocument,
    proof: ByteArray,
    timestamp: Instant,
): ZkDocument {
    val mode = PredicateMode.from(spec)
    val minAge = spec.getParam<Long>(ZK_CONTRACT.paramMinAge)

    val resultClaims = buildMap<String, DataItem> {
        if (predicateModeUsesAge(mode) && minAge != null) {
            put(resultAgeOver(minAge.toUInt()), true.toDataItem())
        }
        if (predicateModeUsesNat(mode)) {
            put(ZK_CONTRACT.resultNatInSet, true.toDataItem())
        }
    }

    val data = ZkDocumentData(
        zkSystemSpecId = spec.id,
        docType = document.docType,
        timestamp = timestamp,
        issuerSigned = mapOf(ZK_CONTRACT.pidNamespace to resultClaims),
        deviceSigned = emptyMap(),
        // P-256 surfaces the issuer chain so the verifier can recover the key; the ML-DSA PID
        // carries no x5chain (issuer trust is by pinned pkEncode hash).
        msoX5chain = when (zkSystem()) {
            ZkSystemKind.ML_DSA -> null
            ZkSystemKind.P256 -> document.issuerCertChain
        },
    )
    return ZkDocument(documentData = data, proof = ByteString(proof))
}

private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

/** The (x, y) coordinates of a P-256 issuer key, for the P-256 ZK system's issuer pin. */
private fun EcPublicKey.toXY(): Pair<ByteArray, ByteArray> = when (this) {
    is EcPublicKeyDoubleCoordinate -> this.x to this.y
    else -> throw IllegalArgumentException("Expected a P-256 double-coordinate issuer key")
}

/** Days since 1970-01-01 (UTC) from an [Instant]. */
private fun Instant.epochDay(): Int = (this.epochSeconds / 86_400L).toInt()

private fun PredicateMode.Companion.from(spec: ZkSystemSpec) =
    spec.getParam<String>(ZK_CONTRACT.paramPredicateMode)
        ?.let { predicateModeFromToken(it) }
        ?: PredicateMode.AND