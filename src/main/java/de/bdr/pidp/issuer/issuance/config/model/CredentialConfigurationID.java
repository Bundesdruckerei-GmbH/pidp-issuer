/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.config.model;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Optional;

@Getter
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public enum CredentialConfigurationID {
    SD_JWT_V1("pid-sd-jwt"),
    SD_JWT_V2("pid-sd-jwt_2"),
    SD_JWT_V3_BETA("pid-sd-jwt_3-beta"),
    MSO_MDOC_V1("pid-mso-mdoc"),
    MSO_MDOC_V2("pid-mso-mdoc_2"),
    MSO_MDOC_V3_BETA("pid-mso-mdoc_3-beta");

    private final String name;

    public static Optional<CredentialConfigurationID> getCredentialConfigurationID(String idValue) {
        for (CredentialConfigurationID id : CredentialConfigurationID.values()) {
            if (id.name.equals(idValue)) {
                return Optional.of(id);
            }
        }
        return Optional.empty();
    }
}
