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

import com.kss.euid.zk.sdk.NatMode
import com.kss.euid.zk.sdk.PredicateMode
import com.kss.euid.zk.sdk.ZkMdocWitness
import com.kss.euid.zk.sdk.ZkPublicStatement
import com.kss.euid.zk.sdk.predicateModeFromToken
import com.kss.euid.zk.sdk.predicateModeUsesAge
import com.kss.euid.zk.sdk.predicateModeUsesNat
import com.kss.euid.zk.sdk.resultAgeOver
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
import kotlin.time.Instant

/** Public statement at proving time — `today` derives from the proof [timestamp] (device clock) TODO. */
fun ZkPublicStatement.Companion.forProver(
    spec: ZkSystemSpec,
    document: MdocDocument,
    sessionTranscript: DataItem,
    timestamp: Instant
): ZkPublicStatement {
    val (keyX, keyY) = document.issuerCertChain.certificates.first().ecPublicKey.toXY()

    val mode = PredicateMode.from(spec)
    val minAge = spec.getParam<Long>(ZK_CONTRACT.paramMinAge)
    val accepted = spec.getParam<String>(ZK_CONTRACT.paramAcceptedCountries)
        ?.split(",")
        ?.mapNotNull { it.trim().toUIntOrNull() }

    return ZkPublicStatement(
        specId = spec.id,
        version = (spec.getParam<Long>(ZK_CONTRACT.paramVersion) ?: 1L).toUInt(),
        doctype = ZK_CONTRACT.doctypePid,
        namespace = ZK_CONTRACT.pidNamespace,
        issuerKeyX = keyX,
        issuerKeyY = keyY,
        todayEpochDay = timestamp.epochDay(), // TODO maybe not use system clock
        nonce = Cbor.encode(sessionTranscript),
        predicateMode = mode,
        ageThresholdYears = if (predicateModeUsesAge(mode)) minAge?.toUInt() else null,
        acceptedNumericCountries = if (predicateModeUsesNat(mode)) accepted else null,
        natMode = NatMode.ANY, // only "any" supported this iteration
    )
}

/** Public statement at verify time — issuer key + `today` come from the proof's [ZkDocument]. */
fun ZkPublicStatement.Companion.forVerifier(
    spec: ZkSystemSpec,
    zkDocument: ZkDocument,
    sessionTranscript: DataItem,
): ZkPublicStatement {
    val chain = zkDocument.documentData.msoX5chain
        ?: throw IllegalArgumentException("ZkDocument is missing msoX5chain (issuer key)")
    val (keyX, keyY) = chain.certificates.first().ecPublicKey.toXY()
    val mode = PredicateMode.from(spec)
    val minAge = spec.getParam<Long>(ZK_CONTRACT.paramMinAge)
    val accepted = spec.getParam<String>(ZK_CONTRACT.paramAcceptedCountries)
        ?.split(",")
        ?.mapNotNull { it.trim().toUIntOrNull() }

    return ZkPublicStatement(
        specId = spec.id,
        version = (spec.getParam<Long>(ZK_CONTRACT.paramVersion) ?: 1L).toUInt(),
        doctype = ZK_CONTRACT.doctypePid,
        namespace = ZK_CONTRACT.pidNamespace,
        issuerKeyX = keyX,
        issuerKeyY = keyY,
        todayEpochDay = zkDocument.documentData.timestamp.epochDay(), // TODO
        nonce = Cbor.encode(sessionTranscript),
        predicateMode = mode,
        ageThresholdYears = if (predicateModeUsesAge(mode)) minAge?.toUInt() else null,
        acceptedNumericCountries = if (predicateModeUsesNat(mode)) accepted else null,
        natMode = NatMode.ANY, // only "any" supported this iteration
    )
}

/**
 * Witness (prove side only). The new SDK parses the whole mdoc itself — issuer signature, MSO,
 * disclosed items, AND the device signature (holder binding is now proven in-circuit) — so we hand
 * it the full ISO 18013-5 `Document` CBOR instead of pre-extracting fields.
 *
 * The device signature inside [document] is real: Multipaz signs `DeviceAuthentication` via the
 * credential's SecureArea in `MdocDocument.fromPresentment`, before `generateProof` is ever called.
 */
fun ZkMdocWitness.Companion.from(
    document: MdocDocument,
): ZkMdocWitness = ZkMdocWitness(
    document = Cbor.encode(document.toDataItem()),
    // ponytail: trust the credential's own issuer chain. The prover only needs a root that
    // validates the credential it already holds; the VERIFIER independently re-checks the issuer
    // key against its own trust anchors. Swap for the app's bundled issuer roots if the prover
    // must reject out-of-trust-store credentials at proof time.
    trustedIssuerCertificates = document.issuerCertChain.certificates.map { it.encoded.toByteArray() },
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
        msoX5chain = document.issuerCertChain,
    )
    return ZkDocument(documentData = data, proof = ByteString(proof))
}

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