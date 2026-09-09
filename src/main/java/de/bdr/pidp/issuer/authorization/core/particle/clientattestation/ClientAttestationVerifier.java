/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle.clientattestation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import com.nimbusds.openid.connect.sdk.Nonce;
import de.bdr.pidp.issuer.authorization.config.ReadOnlyAuthMetadata;
import de.bdr.pidp.issuer.authorization.core.AuthorizationConfiguration;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidClientException;
import de.bdr.pidp.issuer.authorization.core.service.AuthChallengeService;
import de.bdr.pidp.issuer.base.jwt.SecurityContextJWSKeySelector;
import de.bdr.pidp.issuer.base.jwt.StatusListRef;
import de.bdr.pidp.issuer.base.jwt.X5CJWSKeySelector;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;

@NullMarked
@Component
public class ClientAttestationVerifier {
    public static final JOSEObjectType CLIENT_ATTESTATION_TYPE = new JOSEObjectType("oauth-client-attestation+jwt");
    public static final JOSEObjectType CLIENT_ATTESTATION_POP_TYPE = new JOSEObjectType("oauth-client-attestation-pop+jwt");

    private final JWTProcessor<ClientAttestationSecurityContext> jwtProcessor;
    private final JWTProcessor<ClientAttestationSecurityContext> jwtPoPProcessor;
    private final boolean challengeSupported;
    private final AuthChallengeService challengeService;

    @Autowired
    public ClientAttestationVerifier(AuthorizationConfiguration config, ReadOnlyAuthMetadata metadata, AuthChallengeService challengeService) {
        this(Set.copyOf(metadata.getClientAttestationSigningAlgValuesSupported()),
            Set.copyOf(metadata.getClientAttestationPoPSigningAlgValuesSupported()),
            config.getCredentialIssuerIdentifier(),
            config.allowSelfSignedAttestationCert(),
            config.getProofTimeTolerance(),
            metadata.isChallengeSupported(),
            challengeService
        );
    }

    public ClientAttestationVerifier(Set<JWSAlgorithm> jwsAlgorithmsSupported, Set<JWSAlgorithm> popJwsAlgorithmsSupported, String issuerIdentifier, boolean allowSelfSigned, Duration proofTimeTolerance, boolean challengeSupported, AuthChallengeService challengeService) {
        this.jwtProcessor = buildJwtProcessor(jwsAlgorithmsSupported, allowSelfSigned, (int) proofTimeTolerance.toSeconds());
        this.jwtPoPProcessor = buildPoPJwtProcessor(popJwsAlgorithmsSupported, issuerIdentifier, (int) proofTimeTolerance.toSeconds());
        this.challengeSupported = challengeSupported;
        this.challengeService = challengeService;
    }

    public AttestationValues verify(SignedJWT attestation, SignedJWT attestationPoP, Set<X509Certificate> certs, String clientId) {
        var cCheck = challengeSupported ? challengeCheck() : null;
        var ctx = new ClientAttestationSecurityContext(certs, clientId, cCheck);
        try {
            jwtProcessor.process(attestation, ctx);
        } catch (BadJOSEException | KeySourceException e) {
            throw new InvalidClientException("Client Attestation is invalid: " + e.getMessage(), e);
        }  catch (JOSEException e) {
            throw new InvalidClientException("Client Attestation is invalid", e);
        }

        try {
            jwtPoPProcessor.process(attestationPoP, ctx);
        } catch (BadJOSEException | KeySourceException e) {
            throw new InvalidClientException("Client Attestation PoP is invalid: " + e.getMessage(), e);
        }  catch (JOSEException e) {
            throw new InvalidClientException("Client Attestation PoP is invalid", e);
        }

        return new AttestationValues(
            Objects.requireNonNull(ctx.getKey()),
            ctx.getStatusListRef()
        );
    }

    private Predicate<@Nullable Nonce> challengeCheck() {
        return nonce -> nonce != null && challengeService.consume(nonce.getValue());
    }

    private static DefaultJWTProcessor<ClientAttestationSecurityContext> buildJwtProcessor(Set<JWSAlgorithm> jwsAlgorithmsSupported, boolean allowSelfSigned, int timeToleranceSeconds) {
        var processor = new DefaultJWTProcessor<ClientAttestationSecurityContext>();

        var typeVerifier = new DefaultJOSEObjectTypeVerifier<ClientAttestationSecurityContext>(CLIENT_ATTESTATION_TYPE);
        processor.setJWSTypeVerifier(typeVerifier);

        var keySelector = new X5CJWSKeySelector<ClientAttestationSecurityContext>(jwsAlgorithmsSupported, allowSelfSigned);
        processor.setJWSKeySelector(keySelector);

        var claimsVerifier = new ClientAttestationClaimsVerifier(timeToleranceSeconds);
        processor.setJWTClaimsSetVerifier(claimsVerifier);
        return processor;
    }

    private static DefaultJWTProcessor<ClientAttestationSecurityContext> buildPoPJwtProcessor(Set<JWSAlgorithm> jwsAlgorithmsSupported, String issuerIdentifier, int timeToleranceSeconds) {
        var processor = new DefaultJWTProcessor<ClientAttestationSecurityContext>();

        var typeVerifier = new DefaultJOSEObjectTypeVerifier<ClientAttestationSecurityContext>(CLIENT_ATTESTATION_POP_TYPE);
        processor.setJWSTypeVerifier(typeVerifier);

        var keySelector = new SecurityContextJWSKeySelector<ClientAttestationSecurityContext>(jwsAlgorithmsSupported);
        processor.setJWSKeySelector(keySelector);

        var claimsVerifier = new ClientAttestationPoPClaimsVerifier(issuerIdentifier, timeToleranceSeconds);
        processor.setJWTClaimsSetVerifier(claimsVerifier);
        return processor;
    }

    public record AttestationValues(JWK confirmationKey, @Nullable StatusListRef statusListRef) {
    }
}
