/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Issuer;
import de.bdr.pidp.issuer.base.jwk.LazyJWKSource;
import de.bdr.pidp.issuer.base.jwt.InsufficientScopeException;
import de.bdr.pidp.issuer.base.jwt.JOSEObjectTypes;
import de.bdr.pidp.issuer.issuance.config.IssuanceConfiguration;
import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import de.bdr.pidp.issuer.issuance.config.model.CredentialIssuerMetadata;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidAccessTokenException;
import de.bdr.pidp.issuer.issuance.openid4vci.out.authorization.AuthorizationDiscoveryAdapter;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Set;

@NullMarked
@Component
public class AccessTokenValidator {

    private final AuthorizationDiscoveryAdapter discovery;
    private final CredentialIssuerMetadata metadata;

    private final JWTProcessor<AccessTokenSecurityContext> processor;

    private final Set<JWSAlgorithm> signingAlgValuesSupported;

    public AccessTokenValidator(CredentialIssuerMetadata metadata, IssuanceConfiguration configuration, AuthorizationDiscoveryAdapter discovery) {
        this.discovery = discovery;
        this.metadata = metadata;
        signingAlgValuesSupported = Set.copyOf(discovery.getDPoPSigningAlgorithms());
        processor = buildJwtProcessor(metadata.credentialIssuer(), configuration.getProofTimeTolerance());
    }

    public JWTClaimsSet validate(SignedJWT accessToken, CredentialConfigurationID configID) {
        var authIssuer = discovery.getIssuer();
        var scope = metadata.credentialConfigurationsSupported().get(configID).scope();
        var context = new AccessTokenSecurityContext(authIssuer, new Scope(scope));
        try {
            return processor.process(accessToken, context);
        } catch (InsufficientScopeException e) {
            throw new InvalidAccessTokenException(InvalidAccessTokenException.Reason.INSUFFICIENT_SCOPE, e.getMessage());
        } catch (BadJOSEException | JOSEException e) {
            throw new InvalidAccessTokenException(InvalidAccessTokenException.Reason.INVALID_TOKEN, e.getMessage());
        }
    }

    private DefaultJWTProcessor<AccessTokenSecurityContext> buildJwtProcessor(
        Issuer credentialIssuer,
        Duration clockSkew
    ) {
        var jwtProcessor = new DefaultJWTProcessor<AccessTokenSecurityContext>();

        var typeVerifier = new DefaultJOSEObjectTypeVerifier<AccessTokenSecurityContext>(JOSEObjectTypes.ACCESS_TOKEN);
        jwtProcessor.setJWSTypeVerifier(typeVerifier);

        var keySource = new LazyJWKSource<AccessTokenSecurityContext>(_ -> discovery.getJWKSet());
        var keySelector = new JWSVerificationKeySelector<>(signingAlgValuesSupported, keySource);
        jwtProcessor.setJWSKeySelector(keySelector);

        var claimsVerifier = new AccessTokenClaimsVerifier(credentialIssuer, (int) clockSkew.toSeconds());
        jwtProcessor.setJWTClaimsSetVerifier(claimsVerifier);
        return jwtProcessor;
    }
}
