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

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.buildCborArray
import org.multipaz.cbor.buildCborMap
import org.multipaz.cbor.toDataItem
import org.multipaz.cose.Cose
import org.multipaz.cose.CoseNumberLabel
import org.multipaz.cose.CoseSign1
import org.multipaz.cose.CoseTextLabel

/**
 * STEP-1 IMPORT PROBE — does Multipaz preserve an ML-DSA-signed `issuerAuth`?
 *
 * The quantum-safe eu-id prover (`feat/quantum-safe`) is ML-DSA-65 only. Its `issuerAuth` is a
 * COSE_Sign1 unlike anything today's ES256/P-256 flow produces:
 *   - protected header `{1: -49}` (COSE alg ML-DSA-65)  -> canonical CBOR `A1 01 38 30`
 *   - unprotected header `{"issuerKey": AKP COSE_Key{1:7, 3:-49, -1: pk(1952B)}}`
 *   - NO `x5chain` (no PQ PKI profile exists) — trust is by pinning SHA-256(pkEncode)
 * (reference: eu-id `crates/eu-id-prover/tests/mldsa_fixture.rs`.)
 *
 * The wallet feeds the prover `Cbor.encode(document.toDataItem())`, and both `MdocDocument.fromDataItem`
 * and `.toDataItem()` route `issuerAuth` through [CoseSign1] verbatim (no signature check, no x5chain
 * requirement — those live only in the verifier-side `MdocDocument.verify()`). This probe pins that
 * the ML-DSA `issuerAuth` survives that parse+re-encode byte-for-byte on the actual mavenLocal Multipaz.
 *
 * NOT covered here (needs an AKP device key + SecureArea, i.e. step 2): the full store path
 * (`storeIssuedDocument`) and `MdocDocument` round-trip with an ML-DSA `deviceSignature`.
 */
class MldsaIssuerAuthRoundTripTest {

    private companion object {
        const val COSE_ALG_ML_DSA_65 = -49L
        const val COSE_KTY_AKP = 7L
        const val ML_DSA_65_PK_BYTES = 1_952
        const val ML_DSA_65_SIG_BYTES = 3_309
    }

    @Test
    fun `ML-DSA issuerAuth survives Multipaz CoseSign1 round-trip`() {
        val issuerPk = ByteArray(ML_DSA_65_PK_BYTES) { (it and 0xFF).toByte() }
        val signature = ByteArray(ML_DSA_65_SIG_BYTES) { ((it * 7) and 0xFF).toByte() }
        val msoPayload = Cbor.encode(buildCborMap { put("docType", "eu.europa.ec.eudi.pid.1") })

        // protected = {1: -49}
        val protectedHeaderBytes = Cbor.encode(
            buildCborMap { put(Cose.COSE_LABEL_ALG.toDataItem(), COSE_ALG_ML_DSA_65.toDataItem()) }
        )
        assertArrayEquals(
            "protected header must be the canonical ML-DSA-65 encoding A1 01 38 30",
            byteArrayOf(0xA1.toByte(), 0x01, 0x38, 0x30),
            protectedHeaderBytes,
        )

        // issuerAuth = [ protected, unprotected{issuerKey: AKP COSE_Key}, payload(MSO), signature ]
        val issuerAuthDi = buildCborArray {
            add(protectedHeaderBytes)
            add(
                buildCborMap {
                    put(
                        "issuerKey".toDataItem(),
                        buildCborMap {
                            put(1.toDataItem(), COSE_KTY_AKP.toDataItem())
                            put(3.toDataItem(), COSE_ALG_ML_DSA_65.toDataItem())
                            put((-1).toDataItem(), Bstr(issuerPk))
                        },
                    )
                },
            )
            add(Bstr(msoPayload))
            add(Bstr(signature))
        }

        // Parse + re-encode exactly as the witness path does.
        val roundTripped = CoseSign1.fromDataItem(CoseSign1.fromDataItem(issuerAuthDi).toDataItem())

        // Strongest check: full byte preservation.
        assertArrayEquals(
            "ML-DSA issuerAuth was altered by the CoseSign1 round-trip",
            Cbor.encode(issuerAuthDi),
            Cbor.encode(roundTripped.toDataItem()),
        )

        // Readable structural pins (document intent; also survive if canonical ordering ever changes).
        assertEquals(
            COSE_ALG_ML_DSA_65,
            roundTripped.protectedHeaders[CoseNumberLabel(Cose.COSE_LABEL_ALG)]!!.asNumber,
        )
        assertNull(
            "an ML-DSA issuerAuth must carry no x5chain",
            roundTripped.unprotectedHeaders[CoseNumberLabel(Cose.COSE_LABEL_X5CHAIN)],
        )
        val coseKey = roundTripped.unprotectedHeaders[CoseTextLabel("issuerKey")]!!
        assertEquals(COSE_KTY_AKP, coseKey[1L].asNumber)
        assertArrayEquals(issuerPk, coseKey[-1L].asBstr)
        assertArrayEquals(signature, roundTripped.signature)
        assertArrayEquals(msoPayload, roundTripped.payload)
    }
}
