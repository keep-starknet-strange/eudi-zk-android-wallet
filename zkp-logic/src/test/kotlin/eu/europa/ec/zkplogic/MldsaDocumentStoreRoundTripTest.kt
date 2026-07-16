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

import eu.europa.ec.eudi.wallet.document.CreateDocumentSettings
import eu.europa.ec.eudi.wallet.document.DocumentManagerImpl
import eu.europa.ec.eudi.wallet.document.credential.IssuerProvidedCredential
import eu.europa.ec.eudi.wallet.document.format.MsoMdocFormat
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.Tagged
import org.multipaz.cbor.buildCborArray
import org.multipaz.cbor.buildCborMap
import org.multipaz.cbor.toDataItem
import org.multipaz.cose.Cose
import org.multipaz.cose.CoseLabel
import org.multipaz.cose.CoseNumberLabel
import org.multipaz.cose.CoseSign1
import org.multipaz.cose.CoseTextLabel
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.EcPublicKey
import org.multipaz.mdoc.mso.MobileSecurityObjectGenerator
import org.multipaz.securearea.SecureAreaRepository
import org.multipaz.securearea.software.SoftwareCreateKeySettings
import org.multipaz.securearea.software.SoftwareSecureArea
import org.multipaz.storage.ephemeral.EphemeralStorage
import java.security.MessageDigest
import kotlin.time.Instant

/**
 * STEP-1 IMPORT PROBE (full store path) — does the wallet's real issuance store accept an
 * ML-DSA-65-issuer PID mdoc, and hand it back with the `issuerAuth` intact?
 *
 * This drives the actual `DocumentManagerImpl.storeIssuedDocument` (the method the OpenID4VCI flow
 * calls) over an in-memory `EphemeralStorage` + `SoftwareSecureArea`. The only wallet-issued piece
 * is the device key: we create a document (P-256 device key in the SecureArea — an AKP ML-DSA device
 * key is step 2), then mint an ML-DSA-*issuer* mdoc that binds that device key and store it.
 *
 * The store gate (`MsoMdocCredentialCertifier`, read from the 0.17.0 sources) does NOT verify the
 * issuer signature and does NOT require an `x5chain`; its only hard check is
 * `mso.deviceKey == credential's SecureArea key`, and it persists the issuer bytes verbatim. This
 * probe confirms that path end-to-end for the ML-DSA shape: `{1:-49}` alg, AKP `issuerKey` in the
 * unprotected header, no `x5chain` — including that the certifier's COSE library (augustcellars,
 * NOT Multipaz) tolerates alg `-49` and a text-labelled unprotected header.
 *
 * NOT covered (step 2): an AKP ML-DSA *device* key in the MSO — Multipaz's `MobileSecurityObjectParser`
 * decodes `deviceKey` as an `EcPublicKey`, so that needs separate work.
 */
class MldsaDocumentStoreRoundTripTest {

    private companion object {
        const val COSE_ALG_ML_DSA_65 = -49L
        const val COSE_KTY_AKP = 7L
        const val ML_DSA_65_PK_BYTES = 1_952
        const val ML_DSA_65_SIG_BYTES = 3_309
        const val PID_DOCTYPE = "eu.europa.ec.eudi.pid.1"
        const val PID_NAMESPACE = "eu.europa.ec.eudi.pid.1"
        const val CBOR_TAG_ENCODED = 24L
    }

    @Test
    fun `wallet store accepts an ML-DSA-issuer mdoc and preserves issuerAuth`() = runBlocking {
        // --- real wallet issuance plumbing, in-memory ---
        val storage = EphemeralStorage()
        val secureArea = SoftwareSecureArea.create(storage)
        val secureAreaRepository = SecureAreaRepository.Builder().add(secureArea).build()
        val documentManager = DocumentManagerImpl(
            identifier = "mldsa-probe",
            storage = storage,
            secureAreaRepository = secureAreaRepository,
        )

        // 1) create the document -> wallet generates the (P-256) device key in the SecureArea.
        val unsigned = documentManager.createDocument(
            format = MsoMdocFormat(docType = PID_DOCTYPE),
            createSettings = CreateDocumentSettings(
                secureAreaIdentifier = secureArea.identifier,
                createKeySettings = SoftwareCreateKeySettings.Builder()
                    .setAlgorithm(Algorithm.ESP256)
                    .build(),
                numberOfCredentials = 1,
            ),
        ).getOrThrow()

        val signer = unsigned.getPoPSigners().first()
        val keyInfo = signer.getKeyInfo()

        // 2) mint an ML-DSA-issuer mdoc binding that exact device key.
        val mdocBytes = mintMldsaIssuerMdoc(deviceKey = keyInfo.publicKey)

        // 3) store it through the real certifier path.
        val issued = documentManager.storeIssuedDocument(
            unsignedDocument = unsigned,
            issuerProvidedData = listOf(
                IssuerProvidedCredential(publicKeyAlias = keyInfo.alias, data = mdocBytes),
            ),
        ).getOrThrow()

        // 4) read the stored issuer bytes back and confirm the ML-DSA issuerAuth is intact.
        val storedBytes = issued.findCredential()!!.issuerProvidedData.toByteArray()
        val issuerAuth = CoseSign1.fromDataItem(Cbor.decode(storedBytes)["issuerAuth"])

        assertEquals(
            COSE_ALG_ML_DSA_65,
            issuerAuth.protectedHeaders[CoseNumberLabel(Cose.COSE_LABEL_ALG)]!!.asNumber,
        )
        assertNull(
            "an ML-DSA issuerAuth must carry no x5chain",
            issuerAuth.unprotectedHeaders[CoseNumberLabel(Cose.COSE_LABEL_X5CHAIN)],
        )
        val coseKey = issuerAuth.unprotectedHeaders[CoseTextLabel("issuerKey")]!!
        assertEquals(COSE_KTY_AKP, coseKey[1L].asNumber)
        assertEquals(ML_DSA_65_PK_BYTES, coseKey[-1L].asBstr.size)
        assertEquals(ML_DSA_65_SIG_BYTES, issuerAuth.signature.size)
        assertTrue("stored bytes should be non-empty", storedBytes.isNotEmpty())
    }

    /** Builds a well-formed ISO 18013-5 `IssuerSigned` whose `issuerAuth` is ML-DSA-65 shaped. */
    private fun mintMldsaIssuerMdoc(deviceKey: EcPublicKey): ByteArray {
        val issuerPk = ByteArray(ML_DSA_65_PK_BYTES) { (it and 0xFF).toByte() }
        val signature = ByteArray(ML_DSA_65_SIG_BYTES) { ((it * 7) and 0xFF).toByte() }

        val birthItem = issuerSignedItem(0L, "birth_date", "1990-07-15".toDataItem())
        val natItem = issuerSignedItem(1L, "nationality", "DE".toDataItem())
        val sha256 = MessageDigest.getInstance("SHA-256")

        val mso = MobileSecurityObjectGenerator(
            digestAlgorithm = Algorithm.SHA256,
            docType = PID_DOCTYPE,
            deviceKey = deviceKey,
        ).apply {
            addDigestIdsForNamespace(
                PID_NAMESPACE,
                mapOf(0L to sha256.digest(birthItem), 1L to sha256.digest(natItem)),
            )
            setValidityInfo(
                signed = Instant.fromEpochSeconds(1_767_225_600L),   // 2026-01-01
                validFrom = Instant.fromEpochSeconds(1_767_225_600L),
                validUntil = Instant.fromEpochSeconds(1_893_456_000L), // 2030-01-01
                expectedUpdate = null,
            )
        }.generate()

        // issuerAuth payload = #6.24(bstr .cbor MSO) — the ISO-standard tag-24 wrapping.
        val issuerAuth = CoseSign1(
            protectedHeaders = mapOf<CoseLabel, org.multipaz.cbor.DataItem>(
                CoseNumberLabel(Cose.COSE_LABEL_ALG) to COSE_ALG_ML_DSA_65.toDataItem(),
            ),
            unprotectedHeaders = mapOf<CoseLabel, org.multipaz.cbor.DataItem>(
                // Raw ML-DSA-65 issuer key as an AKP COSE_Key — no x5chain (no PQ PKI profile yet).
                CoseTextLabel("issuerKey") to buildCborMap {
                    put(1.toDataItem(), COSE_KTY_AKP.toDataItem())
                    put(3.toDataItem(), COSE_ALG_ML_DSA_65.toDataItem())
                    put((-1).toDataItem(), Bstr(issuerPk))
                },
            ),
            signature = signature,
            payload = Cbor.encode(Tagged(CBOR_TAG_ENCODED, Bstr(mso))),
        )

        val issuerSigned = buildCborMap {
            put(
                "nameSpaces".toDataItem(),
                buildCborMap {
                    put(
                        PID_NAMESPACE.toDataItem(),
                        buildCborArray {
                            add(Tagged(CBOR_TAG_ENCODED, Bstr(birthItem)))
                            add(Tagged(CBOR_TAG_ENCODED, Bstr(natItem)))
                        },
                    )
                },
            )
            put("issuerAuth".toDataItem(), issuerAuth.toDataItem())
        }
        // issuerProvidedData for an mdoc IS the `IssuerSigned` structure (nameSpaces + issuerAuth),
        // matching what the OpenID4VCI flow base64-decodes and hands to the certifier.
        return Cbor.encode(issuerSigned)
    }

    /** Canonical `IssuerSignedItem` bytes (the inner CBOR that gets tag-24 wrapped in nameSpaces). */
    private fun issuerSignedItem(digestId: Long, element: String, value: org.multipaz.cbor.DataItem): ByteArray =
        Cbor.encode(
            buildCborMap {
                put("digestID".toDataItem(), digestId.toDataItem())
                put("random".toDataItem(), Bstr(ByteArray(16) { it.toByte() }))
                put("elementIdentifier".toDataItem(), element.toDataItem())
                put("elementValue".toDataItem(), value)
            },
        )
}
