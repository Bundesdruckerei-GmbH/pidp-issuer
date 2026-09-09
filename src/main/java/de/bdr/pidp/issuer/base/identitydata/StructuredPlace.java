/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.identitydata;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.jspecify.annotations.Nullable;

public record StructuredPlace(
    @JsonProperty("street") @Nullable String street,
    @JsonProperty("city") @Nullable String city,
    @JsonProperty("country") @Nullable String country,
    @JsonProperty("state") @Nullable String state,
    @JsonProperty("zip_code") @Nullable String zipCode
) {
}
