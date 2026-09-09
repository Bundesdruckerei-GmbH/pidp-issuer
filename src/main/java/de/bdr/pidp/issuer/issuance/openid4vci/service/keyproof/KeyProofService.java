/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.bdr.pidp.issuer.base.IssuedAtValidationResult;
import de.bdr.pidp.issuer.base.IssuedAtValidator;
import de.bdr.pidp.issuer.issuance.config.IssuanceConfiguration;
import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import de.bdr.pidp.issuer.issuance.config.model.CredentialIssuerMetadata;
import de.bdr.pidp.issuer.issuance.config.model.SupportedProofType;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidNonceException;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidProofException;
import de.bdr.pidp.issuer.issuance.openid4vci.service.CNonceService;
import de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.requests.JwtProof;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

@Service
public class KeyProofService {
    private static final JOSEObjectType EXPECTED_PROOF_TYPE = new JOSEObjectType("openid4vci-proof+jwt");
    private static final String NONCE_CLAIM = "nonce";
    private final CNonceService cNonceService;
    private final Duration proofValidity;
    private final Duration proofTimeTolerance;
    private final String credentialIssuerIdentifier;
    private final Map<CredentialConfigurationID, List<JWSAlgorithm>> supportedJwsAlgorithms;

    public KeyProofService(IssuanceConfiguration configuration, CredentialIssuerMetadata metadata, CNonceService cNonceService) {
        this.cNonceService = cNonceService;
        this.proofValidity = configuration.getProofValidity();
        this.proofTimeTolerance = configuration.getProofTimeTolerance();
        this.credentialIssuerIdentifier = metadata.credentialIssuer().getValue();
        this.supportedJwsAlgorithms = new EnumMap<>(CredentialConfigurationID.class);
        for (var entry : metadata.credentialConfigurationsSupported().entrySet()) {
            var credentialID = entry.getKey();
            var credentialConfig = entry.getValue();

            var proofTypes = credentialConfig.proofTypesSupported();
            if (proofTypes != null) {
                var attestationProofType = proofTypes.get(SupportedProofType.JWT);
                if (attestationProofType != null) {
                    supportedJwsAlgorithms.put(credentialID, attestationProofType.proofSigningAlgValuesSupported());
                }
            }
        }
    }

    public Collection<JWK> validateJwtProofs(String clientId, CredentialConfigurationID credentialID, Collection<String> validatedNonce, Collection<JwtProof> proofs) {
        return proofs.stream().map(proof -> validateJwtProof(clientId, credentialID, validatedNonce, proof)).toList();
    }

    private JWK validateJwtProof(String clientId, CredentialConfigurationID credentialID, Collection<String> validatedNonces, JwtProof jwtProof) {
        var signedJwt = jwtProof.getSignedJwt();
        var supportedJWSAlgorithms = supportedJwsAlgorithms.get(credentialID);
        expect(supportedJWSAlgorithms != null, "JWT proof not supported for given credential_configuration_id");
        validateProofHeader(signedJwt.getHeader(), supportedJWSAlgorithms);
        var claims = parseJwtClaims(signedJwt);
        var requestTime = Instant.now();
        validateJwtProofClaims(claims, clientId, requestTime);
        validateNonce(claims, validatedNonces);

        verifySignature(signedJwt);
        return signedJwt.getHeader().getJWK();
    }

    private void validateJwtProofClaims(JWTClaimsSet claims, String clientId, Instant requestTime) {
        expect(clientId.equals(claims.getIssuer()), "Proof JWT issuer invalid");

        var audience = List.of(credentialIssuerIdentifier);
        expect(audience.equals(claims.getAudience()), "Proof JWT audience invalid");

        IssuedAtValidationResult issuedAtValidationResult = IssuedAtValidator.validate(claims.getIssueTime().toInstant(), requestTime, proofTimeTolerance, proofValidity);
        switch (issuedAtValidationResult) {
            case NOT_PRESENT -> throw exception("Proof JWT issuance is missing");
            case IN_FUTURE -> throw exception("Proof JWT is issued in the future");
            case TOO_OLD -> throw exception("Proof JWT issuance is too old");
            case VALID -> {
                // issued at is valid, nothing to do
            }
        }
    }

    private void validateProofHeader(JWSHeader header, List<JWSAlgorithm> supportedJWSAlgorithms) {
        expect(supportedJWSAlgorithms.contains(header.getAlgorithm()), "Proof JWT algorithm not supported");

        expect(EXPECTED_PROOF_TYPE.equals(header.getType()), "Proof JWT type mismatch, expected to be " + EXPECTED_PROOF_TYPE.getType());

        expectNonNull(header.getJWK(), "Proof JWT header should contain a JWK");

        expect(header.getKeyID() == null, "Proof JWT header keyId should not be present");

        expect(header.getX509CertChain() == null || header.getX509CertChain().isEmpty(), "Proof JWT header X509CertChain should not be present");

        expect(header.getCustomParam("trust_chain") == null, "Proof JWT header trust chain should not be present");
    }

    private void validateNonce(JWTClaimsSet claims, Collection<String> validatedNonces) {
        String nonceClaim = parseNonceClaim(claims);
        expectNonNull(nonceClaim, "Proof JWT claim " + NONCE_CLAIM + " not present");
        if (!validatedNonces.contains(nonceClaim)) {
            if (!cNonceService.consume(nonceClaim)) {
                throw invalidNonce("Proof JWT credential %s invalid".formatted(NONCE_CLAIM));
            }
            validatedNonces.add(nonceClaim);
        }
    }

    private String parseNonceClaim(JWTClaimsSet claims) {
        try {
            return claims.getStringClaim(NONCE_CLAIM);
        } catch (ParseException e) {
            throw exception("Proof JWT claim " + NONCE_CLAIM + " could not be parsed", e);
        }
    }

    private void verifySignature(SignedJWT signedJwt) {
        try {
            var verifier = new ECDSAVerifier(signedJwt.getHeader().getJWK().toECKey());
            expect(signedJwt.verify(verifier), "Proof JWT signature is invalid");
        } catch (JOSEException e) {
            throw exception("Proof JWT signature could not be verified", e);
        }
    }

    private JWTClaimsSet parseJwtClaims(JWT jwt) {
        try {
            return jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw exception("Proof JWT claims could not be parsed", e);
        }
    }

    private void expect(boolean condition, String message) {
        if (!condition) {
            throw exception(message);
        }
    }

    private void expectNonNull(@Nullable Object value, String message) {
        if (value == null) {
            throw exception(message);
        }
    }

    private InvalidProofException exception(String message, Exception e) {
        return new InvalidProofException(message, e);
    }

    private InvalidProofException exception(String message) {
        return new InvalidProofException(message);
    }

    private InvalidNonceException invalidNonce(String message) {
        return new InvalidNonceException(message);
    }
}
