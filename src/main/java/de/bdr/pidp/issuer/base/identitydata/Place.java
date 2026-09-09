/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.identitydata;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.jspecify.annotations.Nullable;

public record Place(
    @JsonProperty("structured_place") @Nullable StructuredPlace structuredPlace,
    @JsonProperty("freetext_place") @Nullable String freetextPlace,
    @JsonProperty("no_place_info") @Nullable String noPlaceInfo
) {
}
