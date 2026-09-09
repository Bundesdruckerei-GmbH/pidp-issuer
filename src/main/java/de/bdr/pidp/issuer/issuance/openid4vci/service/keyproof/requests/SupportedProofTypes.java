/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.requests;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public enum SupportedProofTypes {
    JWT(JwtProofType.INSTANCE.getValue()),
    ATTESTATION(AttestationProofType.INSTANCE.getValue());

    @Getter
    private final String value;

    public static SupportedProofTypes findByName(String value) {
        for (SupportedProofTypes supportedProofType : values()) {
            if (supportedProofType.value.equals(value)) {
                return supportedProofType;
            }
        }
        return null;
    }
}
