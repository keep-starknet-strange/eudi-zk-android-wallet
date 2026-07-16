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
import org.multipaz.cose.CoseTextLabel
import org.multipaz.mdoc.response.MdocDocument
import org.multipaz.mdoc.zkp.ZkDocument
import org.multipaz.mdoc.zkp.ZkDocumentData
import org.multipaz.mdoc.zkp.ZkSystemSpec
import java.security.MessageDigest
import kotlin.time.Instant

/** Public statement at proving time — `today` derives from the proof [timestamp] (device clock) TODO. */
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

    return ZkPublicStatement(
        specId = spec.id,
        version = (spec.getParam<Long>(ZK_CONTRACT.paramVersion) ?: 1L).toUInt(),
        doctype = ZK_CONTRACT.doctypePid,
        namespace = ZK_CONTRACT.pidNamespace,
        issuerPublicKeyHash = sha256(document.mldsaIssuerPublicKey()),
        todayEpochDay = timestamp.epochDay(), // TODO maybe not use system clock
        nonce = Cbor.encode(sessionTranscript),
        predicateMode = mode,
        ageThresholdYears = if (predicateModeUsesAge(mode)) minAge?.toUInt() else null,
        acceptedNumericCountries = if (predicateModeUsesNat(mode)) accepted else null,
        natMode = NatMode.ANY, // only "any" supported this iteration
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
    // ponytail: trust the credential's own issuer key. The prover only needs a key that validates
    // the credential it already holds; the VERIFIER independently re-checks the issuer key hash
    // against its own trust anchors. Swap for the app's bundled issuer keys if the prover must
    // reject out-of-trust-store credentials at proof time.
    trustedIssuerPublicKeys = listOf(document.mldsaIssuerPublicKey()),
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
        msoX5chain = null, // ML-DSA PID carries no x5chain; issuer trust is by pinned pkEncode hash.
    )
    return ZkDocument(documentData = data, proof = ByteString(proof))
}

private const val COSE_KTY_AKP = 7L

/**
 * The issuer's raw ML-DSA-65 public key (FIPS 204 `pkEncode`, 1952 bytes) from the `issuerAuth`
 * unprotected `issuerKey` COSE_Key (`{1: AKP, 3: -49, -1: pk}`). The PQ mdoc has no `x5chain`; the
 * key rides in the unprotected header (see the eu-id `mldsa_fixture` format).
 */
private fun MdocDocument.mldsaIssuerPublicKey(): ByteArray {
    val coseKey = issuerAuth.unprotectedHeaders[CoseTextLabel("issuerKey")]
        ?: throw IllegalArgumentException("issuerAuth is missing the ML-DSA issuerKey (unprotected COSE_Key)")
    require(coseKey[1L].asNumber == COSE_KTY_AKP) { "issuerKey is not an AKP (ML-DSA) COSE_Key" }
    return coseKey[-1L].asBstr
}

private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

/** Days since 1970-01-01 (UTC) from an [Instant]. */
private fun Instant.epochDay(): Int = (this.epochSeconds / 86_400L).toInt()

private fun PredicateMode.Companion.from(spec: ZkSystemSpec) =
    spec.getParam<String>(ZK_CONTRACT.paramPredicateMode)
        ?.let { predicateModeFromToken(it) }
        ?: PredicateMode.AND