/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.domain;

import com.nimbusds.jwt.SignedJWT;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidClientException;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidRequestException;

import java.text.ParseException;
import java.util.List;
import java.util.Map;

public abstract class OAuthRequest {
    protected static final String CLIENT_ID_PARAM = "client_id";

    private static final String CLIENT_ATTESTATION_HEADER = "OAuth-Client-Attestation".toLowerCase();
    private static final String CLIENT_ATTESTATION_POP_HEADER = "OAuth-Client-Attestation-PoP".toLowerCase();

    String readRequiredParam(Map<String, String> params, String paramName) {
        var value = params.get(paramName);
        if (value == null || value.isEmpty()) {
            throw new InvalidRequestException(InvalidRequestException.missingParameter(paramName));
        }
        return value;
    }

    SignedJWT readClientAttestation(Map<String, List<String>> allHeaders) {
        var attestation = allHeaders.get(CLIENT_ATTESTATION_HEADER);
        if (attestation == null || attestation.isEmpty()) {
            throw new InvalidClientException("Client Attestation not found");
        }
        if (attestation.size() != 1) {
            throw new InvalidClientException("Client Attestation expected exactly one header");
        }
        try {
            return SignedJWT.parse(attestation.getFirst());
        } catch (ParseException e) {
            throw new InvalidClientException("Client Attestation JWT could not be parsed", e);
        }
    }

    SignedJWT readClientAttestationPoP(Map<String, List<String>> allHeaders) {
        var attestationPoP = allHeaders.get(CLIENT_ATTESTATION_POP_HEADER);
        if (attestationPoP == null || attestationPoP.isEmpty()) {
            throw new InvalidClientException("Client Attestation PoP not found");
        }
        if (attestationPoP.size() != 1) {
            throw new InvalidClientException("Client Attestation PoP expected exactly one header");
        }
        try {
            return SignedJWT.parse(attestationPoP.getFirst());
        } catch (ParseException e) {
            throw new InvalidClientException("Client Attestation PoP JWT could not be parsed", e);
        }
    }
}
