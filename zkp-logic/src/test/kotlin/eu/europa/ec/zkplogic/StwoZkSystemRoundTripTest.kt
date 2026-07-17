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
import com.kss.euid.zk.sdk.ZkPublicStatement
import com.kss.euid.zk.sdk.demoIssuerPublicKey
import com.kss.euid.zk.sdk.zkContractV1
import kotlinx.datetime.LocalDate
import kotlinx.io.bytestring.ByteString
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Ignore
import org.junit.Test
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.buildCborArray
import org.multipaz.cbor.buildCborMap
import org.multipaz.cbor.toDataItem
import org.multipaz.cbor.toDataItemFullDate
import org.multipaz.cose.Cose
import org.multipaz.cose.CoseLabel
import org.multipaz.cose.CoseNumberLabel
import org.multipaz.cose.CoseSign1
import org.multipaz.cose.CoseTextLabel
import org.multipaz.mdoc.devicesigned.DeviceAuth
import org.multipaz.mdoc.devicesigned.DeviceNamespaces
import org.multipaz.mdoc.issuersigned.IssuerNamespaces
import org.multipaz.mdoc.issuersigned.IssuerSignedItem
import org.multipaz.mdoc.response.MdocDocument
import org.multipaz.mdoc.zkp.ZkSystemSpec
import java.security.MessageDigest
import kotlin.time.Instant

/**
 * Mapping + witness construction for [StwoZkSystem] against a synthetic ML-DSA-issuer PID
 * [MdocDocument] fixture.
 *
 * The full prove→verify round trip ([generate_then_verify_round_trips]) is [Ignore]d: the STWO SDK
 * runs the *real* prover, so it requires a genuinely ML-DSA-issuer- and device-signed mdoc `Document`
 * — the dummy fixture below is not circuit-valid. Re-enable it once a real fixture exists; the most
 * reliable source is a golden capture from an on-device ZK presentation (dump the exact
 * `Cbor.encode(document.toDataItem())` + sessionTranscript that feed `proveMdocPid`, commit as a test
 * resource, and drive prove→verify off those bytes).
 */
class StwoZkSystemRoundTripTest {

    private val contract = zkContractV1()
    private val transcript = "session-transcript".toDataItem()
    private val timestamp = Instant.fromEpochSeconds(EPOCH_DAY * 86_400L)

    private fun pidSpec() = ZkSystemSpec(id = contract.specIdPid, system = contract.systemName).apply {
        addParam(contract.paramPredicateMode, "and")
        addParam(contract.paramMinAge, 18L)
        addParam(contract.paramAcceptedCountries, "300,196") // GR, CY
        addParam(contract.paramVersion, 1L)
        addParam(contract.paramNumAttributes, 2L)
    }

    private fun fixtureDocument(): MdocDocument {
        // ML-DSA-65 issuerAuth: protected {1:-49}, unprotected {issuerKey: AKP COSE_Key{1:7,3:-49,-1:pk}},
        // NO x5chain — matching the eu-id `mldsa_fixture` format. Payload/signature are dummy (this
        // fixture never reaches the real prover; the round trip is @Ignore'd).
        val issuerAuth = CoseSign1(
            protectedHeaders = mapOf<CoseLabel, DataItem>(
                CoseNumberLabel(Cose.COSE_LABEL_ALG) to COSE_ALG_ML_DSA_65.toDataItem(),
            ),
            unprotectedHeaders = mapOf<CoseLabel, DataItem>(
                CoseTextLabel("issuerKey") to buildCborMap {
                    put(1.toDataItem(), COSE_KTY_AKP.toDataItem())
                    put(3.toDataItem(), COSE_ALG_ML_DSA_65.toDataItem())
                    put((-1).toDataItem(), Bstr(ISSUER_PK))
                },
            ),
            signature = ByteArray(3309) { it.toByte() }, // dummy ML-DSA sig; not circuit-valid
            payload = byteArrayOf(0xA1.toByte(), 0x00), // dummy MSO bytes (never decoded on our path)
        )
        val birthItem = IssuerSignedItem.fromValues(
            digestId = 0L,
            random = ByteString(ByteArray(16)),
            dataElementIdentifier = contract.elementBirthDate,
            dataElementValue = LocalDate.parse("1990-01-01").toDataItemFullDate(),
        )
        val natItem = IssuerSignedItem.fromValues(
            digestId = 1L,
            random = ByteString(ByteArray(16)),
            dataElementIdentifier = contract.elementNationality,
            dataElementValue = buildCborArray { add("GR"); add("CY") },
        )
        return MdocDocument(
            docType = contract.doctypePid,
            issuerAuth = issuerAuth,
            issuerNamespaces = IssuerNamespaces(
                data = mapOf(
                    contract.pidNamespace to mapOf(
                        contract.elementBirthDate to birthItem,
                        contract.elementNationality to natItem,
                    ),
                ),
            ),
            deviceAuth = DeviceAuth.Ecdsa(CoseSign1(emptyMap(), emptyMap(), ByteArray(64), null)),
            deviceNamespaces = DeviceNamespaces(emptyMap()),
            errors = emptyMap(),
        )
    }

    @Test
    fun forProver_uses_demo_issuer_and_predicate_params() {
        val statement = ZkPublicStatement.forProver(pidSpec(), transcript, timestamp)

        // In-memory re-sign proves under the demo ML-DSA issuer, so the statement pins its hash
        // (not the presented document's issuer key).
        assertArrayEquals(
            MessageDigest.getInstance("SHA-256").digest(demoIssuerPublicKey()),
            statement.issuerPublicKeyHash,
        )
        assertEquals(contract.doctypePid, statement.doctype)
        assertEquals(PredicateMode.AND, statement.predicateMode)
        assertEquals(18u, statement.ageThresholdYears)
        assertEquals(listOf(300u, 196u), statement.acceptedNumericCountries)
        assertEquals(NatMode.ANY, statement.natMode)
        assertEquals(EPOCH_DAY.toInt(), statement.todayEpochDay)
    }

    @Test
    @Ignore("Real STWO prover needs a circuit-valid ML-DSA issuer+device-signed mdoc; capture a golden device fixture first (see class KDoc).")
    fun generate_then_verify_round_trips() {
        val system = StwoZkSystem()
        val spec = pidSpec()
        val zkDocument = system.generateProof(spec, fixtureDocument(), transcript, timestamp)

        val results = zkDocument.documentData.issuerSigned[contract.pidNamespace]!!
        assertTrue("age_over_18 asserted", results.containsKey("age_over_18"))
        assertTrue("nationality_in_set asserted", results.containsKey(contract.resultNatInSet))

        system.verifyProof(zkDocument, spec, transcript)
    }

    private companion object {
        const val EPOCH_DAY = 19_000L
        const val COSE_ALG_ML_DSA_65 = -49L
        const val COSE_KTY_AKP = 7L

        // A deterministic stand-in for the issuer's ML-DSA-65 `pkEncode` (1952 bytes).
        val ISSUER_PK = ByteArray(1_952) { (it and 0xFF).toByte() }
    }
}
