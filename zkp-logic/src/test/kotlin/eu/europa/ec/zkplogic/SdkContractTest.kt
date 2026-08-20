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

import com.kss.euid.zk.sdk.IssuerKey
import com.kss.euid.zk.sdk.NatMode
import com.kss.euid.zk.sdk.PredicateMode
import com.kss.euid.zk.sdk.ProductPublicStatementV1
import com.kss.euid.zk.sdk.ZkPublicStatement
import com.kss.euid.zk.sdk.isoAlpha2ToNumeric
import com.kss.euid.zk.sdk.predicateModeFromToken
import com.kss.euid.zk.sdk.verifyIdentity
import com.kss.euid.zk.sdk.zkContractV1
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Exercises the STWO SDK's pure FFI surface on the host JVM via the `eu-id-zk-sdk-jvm` fat jar (JNA
 * loads the desktop native — no emulator). Uses no Multipaz / Android types.
 *
 * A real prove→verify round trip needs a valid, issuer-and-device-signed mdoc `Document`, which is
 * built with Multipaz types — see [StwoZkSystemRoundTripTest]. Here we only cover the contract
 * constants, the token/ISO helpers, and that a garbage proof fails closed.
 */
class SdkContractTest {

    private fun sampleStatement(ageThreshold: UInt? = 18u) = ZkPublicStatement.ProductV1(
        ProductPublicStatementV1(
            specId = "stwo-euid-pid-v1",
            version = 1u,
            doctype = "eu.europa.ec.eudi.pid.1",
            namespace = "eu.europa.ec.eudi.pid.1",
            issuerKey = IssuerKey.MlDsa(ByteArray(32) { 0x11 }), // SHA-256 of the trusted issuer pkEncode
            todayEpochDay = 7305,
            nonce = byteArrayOf(0xA, 0xB, 0xC),
            predicateMode = PredicateMode.AND,
            ageThresholdYears = ageThreshold,
            acceptedNumericCountries = listOf(56u, 196u, 300u),
            natMode = NatMode.ANY,
        ),
    )

    @Test
    fun contract_exposes_stable_identifiers() {
        val c = zkContractV1()
        assertEquals("stwo-euid-v1", c.systemName)
        assertEquals("stwo-euid-pid-v1", c.specIdPid)
        assertEquals("eu.europa.ec.eudi.pid.1", c.pidNamespace)
        assertEquals("min_age", c.paramMinAge)
        assertEquals("nationality_in_set", c.resultNatInSet)
    }

    @Test
    fun predicate_mode_from_token_round_trips() {
        assertEquals(PredicateMode.AGE, predicateModeFromToken("age"))
        assertEquals(PredicateMode.AND, predicateModeFromToken("and"))
        assertNull(predicateModeFromToken("nope"))
    }

    @Test
    fun iso_alpha2_to_numeric_has_full_coverage() {
        assertEquals(300u, isoAlpha2ToNumeric("GR"))
        assertEquals(196u, isoAlpha2ToNumeric("cy")) // case-insensitive
        assertEquals(840u, isoAlpha2ToNumeric("US")) // not just EU
        assertNull(isoAlpha2ToNumeric("ZZ"))
    }

    @Test
    fun verify_rejects_a_garbage_proof() {
        val rejected = runCatching { !verifyIdentity(sampleStatement(), byteArrayOf(0, 0, 0)).ok }
            .getOrDefault(true)
        assertTrue(rejected)
    }
}
