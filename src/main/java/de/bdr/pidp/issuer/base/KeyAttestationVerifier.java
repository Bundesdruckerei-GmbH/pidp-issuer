/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import de.bdr.pidp.issuer.base.jwt.X5CJWSKeySelector;
import org.jspecify.annotations.NullMarked;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.Set;

@NullMarked
public abstract class KeyAttestationVerifier {
    public static final JOSEObjectType KEY_ATTESTATION_TYPE = new JOSEObjectType("key-attestation+jwt");

    protected final Set<JWSAlgorithm> signingAlgValuesSupported;

    protected final DefaultJWTProcessor<KeyAttestationSecurityContext> jwtProcessor;

    protected KeyAttestationVerifier(Set<JWSAlgorithm> signingAlgValuesSupported, List<String> supportedKeyStorage, List<String> supportedUserAuthentication, boolean allowSelfSigned, Duration proofTimeTolerance) {
        this.signingAlgValuesSupported = signingAlgValuesSupported;
        jwtProcessor = buildJwtProcessor(signingAlgValuesSupported, supportedKeyStorage, supportedUserAuthentication, allowSelfSigned, (int) proofTimeTolerance.toSeconds());
    }

    public abstract List<JWK> verify(SignedJWT jwt, Set<X509Certificate> certs, Collection<String> validatedNonces);

    private static DefaultJWTProcessor<KeyAttestationSecurityContext> buildJwtProcessor(
        Set<JWSAlgorithm> signingAlgValuesSupported,
        List<String> supportedKeyStorage,
        List<String> supportedUserAuthentication,
        boolean allowSelfSigned,
        int proofTimeSeconds
    ) {
        var processor = new DefaultJWTProcessor<KeyAttestationSecurityContext>();

        var typeVerifier = new DefaultJOSEObjectTypeVerifier<KeyAttestationSecurityContext>(KEY_ATTESTATION_TYPE);
        processor.setJWSTypeVerifier(typeVerifier);

        var keySelector = new X5CJWSKeySelector<KeyAttestationSecurityContext>(signingAlgValuesSupported, allowSelfSigned);
        processor.setJWSKeySelector(keySelector);

        var claimsVerifier = new KeyAttestationClaimsVerifier(supportedKeyStorage, supportedUserAuthentication, proofTimeSeconds);
        processor.setJWTClaimsSetVerifier(claimsVerifier);
        return processor;
    }
}
