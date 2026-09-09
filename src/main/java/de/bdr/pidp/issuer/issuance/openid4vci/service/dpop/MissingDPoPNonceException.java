/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service.dpop;

import com.nimbusds.jose.JWSAlgorithm;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Set;

@Getter
@RequiredArgsConstructor
public class MissingDPoPNonceException extends RuntimeException {
    private final Set<JWSAlgorithm> acceptedAlgs;
}
