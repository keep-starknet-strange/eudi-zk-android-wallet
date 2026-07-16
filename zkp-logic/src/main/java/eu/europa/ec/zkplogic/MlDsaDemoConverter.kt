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

import com.kss.euid.zk.sdk.demoDevicePublicKey
import com.kss.euid.zk.sdk.demoMintMlDsaSignedPidMdoc

/**
 * TEST BRIDGE — not a production capability.
 *
 * There is no post-quantum PID issuer/PKI, so to exercise the (ML-DSA-only) prover we take a real
 * P-256 issuer-signed PID and re-issue it under the SDK's deterministic **demo** ML-DSA issuer,
 * rebinding it to the **mock** demo ML-DSA device key. The result is a genuine ML-DSA-signed mdoc
 * the prover accepts; the verifier pins `sha256(demoIssuerPublicKey())` as its trust anchor.
 *
 * @param p256IssuerSigned the existing P-256 PID's `IssuerSigned` CBOR (what the credential stored).
 * @return the converted ML-DSA `IssuerSigned` CBOR.
 */
fun convertPidToMlDsa(p256IssuerSigned: ByteArray): ByteArray =
    demoMintMlDsaSignedPidMdoc(p256IssuerSigned, demoDevicePublicKey())
