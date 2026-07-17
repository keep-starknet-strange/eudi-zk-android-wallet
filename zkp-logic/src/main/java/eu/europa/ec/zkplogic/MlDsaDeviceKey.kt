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

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature

/**
 * The wallet's real, hardware-backed **ML-DSA-65 device key** in the Android Keystore, for the
 * post-quantum mdoc device-auth path. The private key is generated once (Android 16+/KeyMint) under
 * [ALIAS] and never leaves secure hardware; only the public key and signatures come out.
 *
 * Encodings are what the STWO prover accepts, confirmed on-device by `MlDsaKeystoreProbeTest`:
 * - the JCA public key is X.509/SPKI; the raw FIPS 204 `pkEncode` (1952 B) is its trailing bytes,
 * - `Signature("ML-DSA")` produces raw FIPS 204 `sigEncode` (3309 B) directly — no unwrapping,
 * - signing is pure ML-DSA with an empty context.
 *
 * Requires an ML-DSA-capable Keystore (Android 16 / API 36+). This replaces the SDK's mock demo
 * device key: [publicKey] feeds the mint, [sign] produces the presentation `deviceSignature`.
 */
object MlDsaDeviceKey {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val ALIAS = "euidi-mldsa-device-key"
    private const val KEY_ALGORITHM = "ML-DSA-65"
    private const val SIGNATURE_ALGORITHM = "ML-DSA"
    private const val ML_DSA_65_PK_BYTES = 1952

    /** The device's raw FIPS 204 `pkEncode` (1952 B), generating the key on first use. */
    fun publicKey(): ByteArray {
        ensureKey()
        val spki = keyStore().getCertificate(ALIAS)?.publicKey?.encoded
            ?: error("Android Keystore has no ML-DSA public key for alias '$ALIAS'")
        require(spki.size >= ML_DSA_65_PK_BYTES) {
            "unexpected ML-DSA SPKI size ${spki.size} (< $ML_DSA_65_PK_BYTES)"
        }
        // JCA returns X.509/SPKI; the raw pkEncode is the trailing bytes (probe-confirmed).
        return spki.copyOfRange(spki.size - ML_DSA_65_PK_BYTES, spki.size)
    }

    /**
     * Sign [message] (a COSE `Sig_structure`) with the device key; returns the raw FIPS 204
     * `sigEncode` (3309 B) to place in the mdoc `deviceSignature`.
     */
    fun sign(message: ByteArray): ByteArray {
        ensureKey()
        val privateKey = keyStore().getKey(ALIAS, null) as PrivateKey
        return Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initSign(privateKey)
            update(message)
            sign()
        }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun ensureKey() {
        if (keyStore().containsAlias(ALIAS)) return
        KeyPairGenerator.getInstance(KEY_ALGORITHM, ANDROID_KEYSTORE).apply {
            initialize(
                KeyGenParameterSpec.Builder(
                    ALIAS,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                ).build()
            )
        }.generateKeyPair()
    }
}
