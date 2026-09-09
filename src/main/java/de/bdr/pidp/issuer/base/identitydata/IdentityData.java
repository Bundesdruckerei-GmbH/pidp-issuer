/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.identitydata;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.jspecify.annotations.Nullable;

public record IdentityData(
    @JsonProperty("document_type") @Nullable String documentType,
    @JsonProperty("issuing_state") @Nullable String issuingState,
    @JsonProperty("date_of_expiry") String dateOfExpiry,
    @JsonProperty("given_names") @Nullable String givenNames,
    @JsonProperty("family_names") @Nullable String familyNames,
    @JsonProperty("artistic_name") @Nullable String artisticName,
    @JsonProperty("academic_title") @Nullable String academicTitle,
    @JsonProperty("date_of_birth") @Nullable DateOfBirth dateOfBirth,
    @JsonProperty("place_of_birth") @Nullable Place placeOfBirth,
    @JsonProperty("nationality") @Nullable String nationality,
    @JsonProperty("birth_name") @Nullable String birthName,
    @JsonProperty("place_of_residence") @Nullable Place placeOfResidence,
    @JsonProperty("restricted_id") @Nullable RestrictedId restrictedId
) {
}
