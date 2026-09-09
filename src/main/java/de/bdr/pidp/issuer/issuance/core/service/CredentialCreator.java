/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.core.service;

import com.nimbusds.jose.jwk.JWK;
import de.bdr.pidp.issuer.issuance.core.StatusReference;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public interface CredentialCreator {
    ZoneId localZoneId = ZoneId.of("Europe/Berlin");

    String create(@NotNull PIDIdentityData data, @NotNull JWK holderBindingKey, @Nullable StatusReference status, Validity validity);

    default LocalDate getExpirationDate(@NotNull PIDIdentityData data, @NotNull LocalDate maxExpirationDate) {
        var dataExpirationDate = LocalDate.parse(data.dateOfExpiry(), DateTimeFormatter.ISO_LOCAL_DATE);
        return maxExpirationDate.isAfter(dataExpirationDate) ? dataExpirationDate : maxExpirationDate;
    }

    record Validity(Instant validFrom, Instant validUntil) {}
}
