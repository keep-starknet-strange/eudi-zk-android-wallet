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

/**
 * Process-global, consume-once carrier for the last ZK proof's timing/size metrics.
 *
 * [StwoZkSystem.generateProof] runs on a background prover thread deep inside the Multipaz library,
 * with no return channel to the app's success screen. Since presentations are one-at-a-time, a single
 * volatile snapshot is enough. [consume] clears the snapshot so a subsequent non-ZK presentation shows
 * nothing rather than stale numbers.
 *
 * ponytail: global singleton, fine for one-at-a-time presentations; make it a keyed map if concurrent.
 */
object ZkProofMetrics {

    /** @property reissueMs in-memory P-256→ML-DSA re-sign; [proveMs] STWO proving; [proofSizeBytes] proof size. */
    data class Snapshot(val reissueMs: Long, val proveMs: Long, val proofSizeBytes: Int)

    @Volatile
    private var last: Snapshot? = null

    fun record(snapshot: Snapshot) {
        last = snapshot
    }

    /** Returns the last snapshot and clears it, so each is shown at most once. */
    fun consume(): Snapshot? = last.also { last = null }
}
