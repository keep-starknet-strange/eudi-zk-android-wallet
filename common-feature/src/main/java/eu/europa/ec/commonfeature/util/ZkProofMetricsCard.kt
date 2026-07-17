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

package eu.europa.ec.commonfeature.util

import eu.europa.ec.uilogic.component.AppIcons
import eu.europa.ec.uilogic.component.ListItemDataUi
import eu.europa.ec.uilogic.component.ListItemMainContentDataUi
import eu.europa.ec.uilogic.component.ListItemTrailingContentDataUi
import eu.europa.ec.uilogic.component.wrap.ExpandableListItemUi
import eu.europa.ec.zkplogic.ZkProofMetrics

/**
 * Consumes the last ZK proof's [ZkProofMetrics] snapshot and renders it as an expandable card for the
 * presentation success screen, or null when the presentation produced no ZK proof (consume-once, so a
 * subsequent non-ZK presentation shows nothing). Shared by both the proximity and remote success flows.
 *
 * ponytail: demo metrics card, labels hardcoded (not localized) — wire to resources if it ships.
 */
fun zkProofMetricsCard(): ExpandableListItemUi.NestedListItem? {
    val metrics = ZkProofMetrics.consume() ?: return null

    fun row(id: String, label: String, value: String) = ExpandableListItemUi.SingleListItem(
        header = ListItemDataUi(
            itemId = id,
            mainContentData = ListItemMainContentDataUi.Text(text = label),
            supportingText = value,
        )
    )

    val proveValue = if (metrics.proveMs >= 1_000L) {
        "%.1f s".format(metrics.proveMs / 1_000.0)
    } else {
        "${metrics.proveMs} ms"
    }
    val sizeValue = "%.1f KB".format(metrics.proofSizeBytes / 1_024.0)

    return ExpandableListItemUi.NestedListItem(
        header = ListItemDataUi(
            itemId = "zk_proof_metrics",
            mainContentData = ListItemMainContentDataUi.Text(text = "ZK proof metrics"),
            trailingContentData = ListItemTrailingContentDataUi.Icon(iconData = AppIcons.KeyboardArrowDown),
        ),
        nestedItems = listOf(
            row("zk_metric_reissue", "Re-sign & re-issue", "${metrics.reissueMs} ms"),
            row("zk_metric_prove", "Proof generation", proveValue),
            row("zk_metric_size", "Proof size", sizeValue),
        ),
        isExpanded = false,
    )
}
