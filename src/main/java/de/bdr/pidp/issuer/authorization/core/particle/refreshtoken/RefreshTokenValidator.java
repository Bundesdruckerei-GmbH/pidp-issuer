/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle.refreshtoken;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Issuer;
import de.bdr.pidp.issuer.authorization.config.ReadOnlyAuthMetadata;
import de.bdr.pidp.issuer.authorization.core.AuthorizationConfiguration;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidGrantException;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidScopeException;
import de.bdr.pidp.issuer.authorization.core.service.TemporarySignerProvider;
import de.bdr.pidp.issuer.authorization.port.out.RefreshTokenSignerPortOut;
import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.base.crypto.KeyID;
import de.bdr.pidp.issuer.base.jwk.LazyJWKSource;
import de.bdr.pidp.issuer.base.jwt.InsufficientScopeException;
import de.bdr.pidp.issuer.base.jwt.JOSEObjectTypes;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Objects;

@NullMarked
@Component
public class RefreshTokenValidator {

    private final JWTProcessor<RefreshTokenSecurityContext> processor;
    @Nullable
    private final TemporarySignerProvider temporarySignerProvider;
    @Nullable
    private final RefreshTokenSignerPortOut refreshTokenSignerProvider;

    public RefreshTokenValidator(ReadOnlyAuthMetadata metadata, AuthorizationConfiguration configuration, @Nullable TemporarySignerProvider temporarySignerProvider, @Nullable RefreshTokenSignerPortOut refreshTokenSignerProvider) {
        if (refreshTokenSignerProvider == null && temporarySignerProvider == null) {
            throw new PidServerException("No SignerProvider initialized");
        }
        this.refreshTokenSignerProvider = refreshTokenSignerProvider;
        processor = buildJwtProcessor(metadata.getIssuer(), configuration.getProofTimeTolerance());
        this.temporarySignerProvider = temporarySignerProvider;
    }

    public JWTClaimsSet validate(SignedJWT refreshToken, String clientID, Base64URL dPoPJWKThumbprint, Scope scope) {
        var context = new RefreshTokenSecurityContext(clientID, dPoPJWKThumbprint, scope);
        try {
            return processor.process(refreshToken, context);
        } catch (InsufficientScopeException e) {
            throw new InvalidScopeException(e);
        } catch (BadJOSEException | JOSEException e) {
            throw new InvalidGrantException("Refresh token invalid", e);
        }
    }

    private DefaultJWTProcessor<RefreshTokenSecurityContext> buildJwtProcessor(
        Issuer authIssuer,
        Duration clockSkew
    ) {
        var jwtProcessor = new DefaultJWTProcessor<RefreshTokenSecurityContext>();

        var typeVerifier = new DefaultJOSEObjectTypeVerifier<RefreshTokenSecurityContext>(JOSEObjectTypes.REFRESH_TOKEN);
        jwtProcessor.setJWSTypeVerifier(typeVerifier);

        if (refreshTokenSignerProvider != null) {
            var keySource = refreshTokenSignerProvider.<RefreshTokenSecurityContext>jwkSource();
            var keySelector = new JWSVerificationKeySelector<>(JWSAlgorithm.Family.EC, keySource);
            jwtProcessor.setJWSKeySelector(keySelector);
        } else {
            var keySource = new LazyJWKSource<RefreshTokenSecurityContext>(keyIDs -> new JWKSet(keyIDs.stream().map(
                keyID -> (JWK) temporarySignerProvider.findPublicKey(new KeyID(keyID))).filter(Objects::nonNull).toList()));
            var keySelector = new JWSVerificationKeySelector<>(JWSAlgorithm.Family.EC, keySource);
            jwtProcessor.setJWSKeySelector(keySelector);
        }

        var claimsVerifier = new RefreshTokenClaimsVerifier(authIssuer, (int) clockSkew.toSeconds());
        jwtProcessor.setJWTClaimsSetVerifier(claimsVerifier);
        return jwtProcessor;
    }
}
