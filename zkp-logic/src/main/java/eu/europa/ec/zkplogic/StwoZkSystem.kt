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

import com.kss.euid.zk.sdk.IdentityWitness
import com.kss.euid.zk.sdk.ProductMdocWitnessV1
import com.kss.euid.zk.sdk.TrustedIssuers
import com.kss.euid.zk.sdk.ZkMdocWitness
import com.kss.euid.zk.sdk.ZkPublicStatement
import com.kss.euid.zk.sdk.ZkSystemKind
import com.kss.euid.zk.sdk.demoBuildMlDsaWitness
import com.kss.euid.zk.sdk.demoDeviceAuthSigStructure
import com.kss.euid.zk.sdk.demoIssuerPublicKey
import com.kss.euid.zk.sdk.demoMintMlDsaSignedPidMdoc
import com.kss.euid.zk.sdk.demoRevocationWitness
import com.kss.euid.zk.sdk.proveIdentity
import com.kss.euid.zk.sdk.verifyIdentity
import com.kss.euid.zk.sdk.zkContractV1
import com.kss.euid.zk.sdk.zkSystem
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.buildCborMap
import org.multipaz.cbor.toDataItem
import org.multipaz.mdoc.response.MdocDocument
import org.multipaz.mdoc.zkp.ProofVerificationFailureException
import org.multipaz.mdoc.zkp.ZkDocument
import org.multipaz.mdoc.zkp.ZkSystem
import org.multipaz.mdoc.zkp.ZkSystemSpec
import org.multipaz.request.MdocRequestedClaim
import org.multipaz.request.RequestedClaim
import kotlin.system.measureTimeMillis
import kotlin.time.Instant

/**
 * The shared prover↔verifier contract — system/spec names, the `ZkSystemSpec.params` keys, the EUDI
 * identifiers, and result-claim ids — fetched once from the SDK (the single source of truth). Both the
 * wallet and the verifier read the same values, so neither hardcodes a string the other might change.
 */
internal val ZK_CONTRACT = zkContractV1()

/**
 * STWO-backed [ZkSystem] for the EUDI PID: proves an issuer-signed PID satisfies an age-over-threshold
 * and/or nationality-in-set predicate in zero knowledge, revealing only the boolean outcome.
 *
 * All circuit work is delegated to the Rust SDK (`com.kss.euid.zk.sdk`).
 */
class StwoZkSystem : ZkSystem {

    override val name: String = ZK_CONTRACT.systemName

    /**
     * The ZK system specs this wallet can produce. Advertised via [StwoZkSystem.systemSpecs]; the concrete
     * predicate parameters (`min_age`, `accepted_countries`, …) are supplied per-request by the verifier
     * and read off the matched [ZkSystemSpec] at proving time. Identifiers come from the SDK contract.
     */
    override val systemSpecs: List<ZkSystemSpec> = listOf(
        ZkSystemSpec(
            id = ZK_CONTRACT.specIdPid,
            system = ZK_CONTRACT.systemName,
        ).apply {
            // Circuit identity (mirrors Longfellow's version/num_attributes/circuit_hash convention).
            addParam(ZK_CONTRACT.paramVersion, 1L)
            addParam(ZK_CONTRACT.paramNumAttributes, 2L)
        }
    )

    override fun getMatchingSystemSpec(
        zkSystemSpecs: List<ZkSystemSpec>,
        requestedClaims: List<RequestedClaim>,
    ): ZkSystemSpec? = zkSystemSpecs.firstOrNull { spec ->
        spec.system == name && requestedClaimsSupported(requestedClaims)
    }

    override fun generateProof(
        zkSystemSpec: ZkSystemSpec,
        document: MdocDocument, // P256 compatible
        sessionTranscript: DataItem,
        timestamp: Instant,
    ): ZkDocument = try {
        android.util.Log.i("StwoZkSystem", "generateProof entered: zkSystem=${zkSystem()} spec=${zkSystemSpec.id}")
        // Build the prover witness for the linked ZK system. ML-DSA re-signs the presented P-256
        // PID in-memory (demo issuer + real device key); P-256 uses the document as-is with its
        // x5chain as the trust anchor.
        lateinit var witnessDoc: ByteArray
        lateinit var trustedIssuers: TrustedIssuers
        // Only ML-DSA re-signs/re-issues in memory, so only it has a reissue timing; P-256 uses the
        // presented document as-is (reissueMs stays null and the metric isn't rendered).
        var reissueMs: Long? = null
        when (zkSystem()) {
            ZkSystemKind.ML_DSA -> {
                reissueMs = measureTimeMillis {
                    witnessDoc = buildMlDsaWitnessDocument(document, sessionTranscript)
                }
                trustedIssuers = TrustedIssuers.PublicKeys(listOf(demoIssuerPublicKey()))
            }
            ZkSystemKind.P256 -> {
                witnessDoc = Cbor.encode(document.toDataItem())
                trustedIssuers = TrustedIssuers.Certificates(
                    document.issuerCertChain.certificates.map { it.encoded.toByteArray() }
                )
            }
        }

        val statement = ZkPublicStatement.forProver(
            spec = zkSystemSpec,
            document = document,
            sessionTranscript = sessionTranscript,
            timestamp = timestamp
        )
        // ponytail: Ts13DemoV1 path — non-revocation witness minted by the demo revocation authority
        // (id derived from the minted MSO). Flip back to ProductV1(ProductMdocWitnessV1(...)) + the
        // `trustedIssuers` above forFwifi the flat P-256 SDK.
        val rev = demoRevocationWitness(witnessDoc)
        val witness = ZkMdocWitness.Ts13DemoV1(
            IdentityWitness(
                document = witnessDoc,
                revocationIdLo = rev.idLo,
                revocationIdHi = rev.idHi,
                revocationSignature = rev.signature,
            ),
        )

        // ponytail: temporary diagnostics — dump the witness mdoc (base64, chunked) so we can replay
        // the prover's extract_pid_mdoc offline and see the exact MdocError (ElementMissing / digest /
        // deviceAuth). Remove once the InvalidPrivateCredential cause is fixed.
        android.util.Base64.encodeToString(witnessDoc, android.util.Base64.NO_WRAP)
            .chunked(3000)
            .forEachIndexed { i, c -> android.util.Log.i("StwoZkWitness", "wd[$i]=$c") }

        lateinit var proof: ByteArray
        val proveMs = measureTimeMillis { proof = proveIdentity(statement, witness) }

        ZkProofMetrics.record(
            ZkProofMetrics.Snapshot(reissueMs = reissueMs, proveMs = proveMs, proofSizeBytes = proof.size)
        )

        ZkDocument.from(zkSystemSpec, document, proof, timestamp)
    } catch (t: Throwable) {
        android.util.Log.e("StwoZkSystem", "generateProof failed", t)
        throw t
    }

    override fun verifyProof(
        zkDocument: ZkDocument,
        zkSystemSpec: ZkSystemSpec,
        sessionTranscript: DataItem,
    ) {
        val statement = ZkPublicStatement.forVerifier(
            spec = zkSystemSpec,
            zkDocument = zkDocument,
            sessionTranscript = sessionTranscript
        );
        val result = verifyIdentity(statement = statement, proof = zkDocument.proof.toByteArray())
        if (!result.ok) {
            throw ProofVerificationFailureException("STWO ZK proof verification failed")
        }
    }

    private fun requestedClaimsSupported(requestedClaims: List<RequestedClaim>): Boolean {
        val mdocClaims = requestedClaims.filterIsInstance<MdocRequestedClaim>()
        if (mdocClaims.isEmpty()) return false
        val supported = setOf(ZK_CONTRACT.elementBirthDate, ZK_CONTRACT.elementNationality)
        return mdocClaims.all {
            it.namespaceName == ZK_CONTRACT.pidNamespace && it.dataElementName in supported
        }
    }

    /**
     * Build the full ISO 18013-5 `Document` CBOR the prover consumes as its witness, re-signed in memory
     * as ML-DSA over the presented P-256 [document]:
     * - issuer arm: demo ML-DSA issuer, MSO `deviceKey` = the real Keystore device key;
     * - device arm: `deviceSignature` over `DeviceAuthentication(sessionTranscript, docType)`, produced by
     *   the real Keystore key ([MlDsaDeviceKey.sign]).
     *
     * The presented document's own P-256 issuer + device signatures are discarded — only its namespaces,
     * MSO digests, and docType are carried through.
     */
    private fun buildMlDsaWitnessDocument(document: MdocDocument, sessionTranscript: DataItem): ByteArray {
        // Lift the real P-256 IssuerSigned (nameSpaces + issuerAuth) from the presented document.
        val p256IssuerSigned = Cbor.encode(
            buildCborMap {
                put("nameSpaces", document.issuerNamespaces.toDataItem())
                put("issuerAuth", document.issuerAuth.toDataItem())
            }
        )

        // Offload to SDK to mint the doc with ML-DSA issuer key
        val mlDsaIssuerSigned = demoMintMlDsaSignedPidMdoc(
            p256IssuerSigned = p256IssuerSigned,
            devicePublicKey = MlDsaDeviceKey.publicKey()
        )

        // Device arm: sign DeviceAuthentication with the real hardware-backed device key.
        val transcript = Cbor.encode(sessionTranscript)
        val sigStructure = demoDeviceAuthSigStructure(transcript, document.docType)
        val deviceSignature = MlDsaDeviceKey.sign(sigStructure)

        return demoBuildMlDsaWitness(mlDsaIssuerSigned, transcript, document.docType, deviceSignature)
    }

}
