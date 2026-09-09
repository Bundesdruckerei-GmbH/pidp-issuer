/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle.keyattestation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.as.ReadOnlyAuthorizationServerMetadata;
import de.bdr.pidp.issuer.authorization.core.AuthorizationConfiguration;
import de.bdr.pidp.issuer.authorization.core.exception.DPoPValidationException;
import de.bdr.pidp.issuer.base.KeyAttestationSecurityContext;
import de.bdr.pidp.issuer.base.KeyAttestationVerifier;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Set;

@NullMarked
@Slf4j
@Component
public class DPoPKeyAttestationVerifier extends KeyAttestationVerifier {

    public DPoPKeyAttestationVerifier(Set<JWSAlgorithm> signingAlgValuesSupported, List<String> supportedKeyStorage, List<String> supportedUserAuthentication, boolean allowSelfSigned, Duration proofTimeTolerance) {
        super(signingAlgValuesSupported, supportedKeyStorage, supportedUserAuthentication, allowSelfSigned, proofTimeTolerance);
    }

    @Autowired
    public DPoPKeyAttestationVerifier(AuthorizationConfiguration config, ReadOnlyAuthorizationServerMetadata metadata) {
        this(Set.copyOf(metadata.getDPoPJWSAlgs()),
                Arrays.asList(config.getKeyStorageTypes()),
                Arrays.asList(config.getUserAuthenticationTypes()),
                config.allowSelfSignedAttestationCert(),
                config.getProofTimeTolerance());
    }

    public List<JWK> verify(SignedJWT jwt, Set<X509Certificate> certs) {
        return verify(jwt, certs, null);
    }

    @Override
    public List<JWK> verify(SignedJWT jwt, Set<X509Certificate> certs, @Nullable Collection<String> validatedNonces) {
        var ctx = new KeyAttestationSecurityContext(certs, null);
        try {
            jwtProcessor.process(jwt, ctx);
        } catch (BadJOSEException | KeySourceException e) {
            log.debug(e.getMessage(), e);
            throw DPoPValidationException.invalidDPoPProof(signingAlgValuesSupported, "Key attestation JWT invalid: " + e.getMessage());
        } catch (JOSEException e) {
            log.debug(e.getMessage(), e);
            throw DPoPValidationException.invalidDPoPProof(signingAlgValuesSupported, "Key attestation JWT invalid");
        }

        return ctx.getKeys();
    }
}
