/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidAccessTokenException;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidCredentialRequestException;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidProofException;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.UnknownCredentialConfigurationException;
import de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.requests.CustomProofsDeserializer;
import de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.requests.Proof;
import de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.requests.ProofParseException;
import lombok.Getter;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;
import org.springframework.util.StringUtils;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.annotation.JsonDeserialize;
import tools.jackson.databind.exc.InvalidDefinitionException;
import tools.jackson.databind.json.JsonMapper;

import java.text.ParseException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class CredentialRequest {
    private static final String DPOP_KEY = "DPoP";
    private static final String AUTHORIZATION_KEY = HttpHeaders.AUTHORIZATION.toLowerCase();

    private static final JsonMapper JSON_MAPPER = new JsonMapper();

    @Getter
    private final String httpMethod;

    @Getter
    private final SignedJWT accessToken;

    @Getter
    @Nullable
    private final List<String> dpopHeaders;

    private final CredentialRequestBody credentialRequestBody;

    public CredentialRequest(String httpMethod, Map<String, List<String>> allHeaders, String body) {
        this.httpMethod = httpMethod;
        var authHeader = allHeaders.get(AUTHORIZATION_KEY);
        this.accessToken = parseAuthorization(authHeader);
        this.dpopHeaders = allHeaders.get(DPOP_KEY.toLowerCase());
        try {
            this.credentialRequestBody = JSON_MAPPER.readValue(body, CredentialRequestBody.class);
        } catch (InvalidDefinitionException e) {
            if (e.getType().isTypeOrSubTypeOf(Proof.class)) {
                throw new InvalidProofException("Proof JWT could not be parsed", e);
            } else {
                throw new InvalidCredentialRequestException("Credential request could not be parsed", e.getOriginalMessage(), e);
            }
        } catch (JacksonException jpe) {
            switch (jpe.getCause()) {
                case ProofParseException ipe -> throw new InvalidProofException("Proof JWT could not be parsed", ipe);
                case IllegalArgumentException iae -> throw new InvalidCredentialRequestException(iae.getMessage(), iae);
                case UnknownCredentialConfigurationException ucce -> throw ucce;
                case null, default -> throw new InvalidCredentialRequestException(jpe.getMessage(), jpe);
            }
        } catch (IllegalArgumentException e) {
            throw new InvalidCredentialRequestException(e.getMessage(), e);
        }
    }

    public List<Proof> getProofs() {
        return credentialRequestBody.getProofs();
    }

    public CredentialConfigurationID getCredentialConfigurationID() {
        return credentialRequestBody.getCredentialConfigurationID();
    }

    public @Nullable CredentialEncryption getCredentialEncryption() {
        return credentialRequestBody.getCredentialEncryption();
    }

    private SignedJWT parseAuthorization(@Nullable List<String> authorization) {
        if (authorization == null || authorization.isEmpty()) {
            throw new InvalidAccessTokenException(InvalidAccessTokenException.Reason.MISSING_TOKEN);
        }
        var parts = authorization.getFirst().split(" ");
        if (parts.length != 2 || !parts[0].equals(DPOP_KEY)) {
            throw new InvalidAccessTokenException(InvalidAccessTokenException.Reason.MISSING_TOKEN);
        }
        if (parts[1].isBlank()) {
            throw new InvalidAccessTokenException(InvalidAccessTokenException.Reason.INVALID_TOKEN);
        }
        try {
            return SignedJWT.parse(parts[1]);
        } catch (ParseException _) {
            throw new InvalidAccessTokenException(InvalidAccessTokenException.Reason.INVALID_TOKEN, "could not parse access token");
        }
    }

    public record CredentialEncryption(JWK jwk, EncryptionMethod enc) {
        @JsonCreator
        public CredentialEncryption(@JsonProperty(required = true, value = "jwk") Map<String, Object> jwkJson, @JsonProperty(required = true, value = "enc") String encString) {
            JWK jwk;
            try {
                jwk = JWK.parse(jwkJson);
            } catch (ParseException e) {
                throw new IllegalArgumentException("credential_response_encryption jwk could not be parsed", e);
            }
            var enc = EncryptionMethod.parse(encString);
            this(jwk, enc);
        }
    }

    @Getter
    @JsonIgnoreProperties(ignoreUnknown = true)
    private static class CredentialRequestBody {

        private final List<Proof> proofs;
        private final CredentialConfigurationID credentialConfigurationID;
        @Nullable
        private final CredentialEncryption credentialEncryption;

        public CredentialRequestBody(
            @Nullable @JsonProperty("proofs") @JsonDeserialize(using = CustomProofsDeserializer.class) List<Proof> proofs,
            @Nullable @JsonProperty("credential_configuration_id") String credentialConfigurationID,
            @Nullable @JsonProperty("credential_response_encryption") CredentialEncryption credentialEncryption) {
            if (!StringUtils.hasText(credentialConfigurationID)) {
                throw new IllegalArgumentException("credential_configuration_id parameter is missing");
            }
            this.proofs = Objects.requireNonNullElse(proofs, Collections.emptyList());
            this.credentialConfigurationID = CredentialConfigurationID.getCredentialConfigurationID(credentialConfigurationID)
                .orElseThrow(() -> new UnknownCredentialConfigurationException(credentialConfigurationID));
            this.credentialEncryption = credentialEncryption;
        }
    }
}
