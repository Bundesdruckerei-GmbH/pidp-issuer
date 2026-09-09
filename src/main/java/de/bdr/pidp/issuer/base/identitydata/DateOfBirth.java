/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.identitydata;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.jspecify.annotations.Nullable;

public record DateOfBirth(
    @JsonProperty("date_value") @Nullable String dateValue,
    @JsonProperty("date_string") @Nullable String dateString
) {
}
