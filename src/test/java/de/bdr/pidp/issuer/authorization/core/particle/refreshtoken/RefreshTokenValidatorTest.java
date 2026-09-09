/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle.refreshtoken;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.Scope;
import de.bdr.pidp.issuer.authorization.adapter.out.HSMRefreshTokenSignerAdapter;
import de.bdr.pidp.issuer.authorization.config.MetaTestData;
import de.bdr.pidp.issuer.authorization.config.ReadOnlyAuthMetadata;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidGrantException;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidScopeException;
import de.bdr.pidp.issuer.authorization.core.exception.OAuthException;
import de.bdr.pidp.issuer.authorization.core.service.TemporarySignerProvider;
import de.bdr.pidp.issuer.base.constants.RefreshTokenClaims;
import de.bdr.pidp.issuer.base.crypto.KeyID;
import de.bdr.pidp.issuer.testdata.ClientIds;
import de.bdr.pidp.issuer.testdata.TestRefreshTokenIssuer;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.InstanceOfAssertFactories.type;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

@ExtendWith(SpringExtension.class)
class RefreshTokenValidatorTest {
    private final TemporarySignerProvider temporarySignerProvider = mock(TemporarySignerProvider.class);
    private final HSMRefreshTokenSignerAdapter hsmRefreshTokenSignerProvider = mock(HSMRefreshTokenSignerAdapter.class);
    private final ReadOnlyAuthMetadata metadata = MetaTestData.AUTH_METADATA;
    private final Base64URL dpopJWKThumbprint = Base64URL.encode("See you later, validator");
    private final Scope scope = new Scope("pid");
    private final String clientID = ClientIds.validClientIdForSelfSigned().toString();
    private final JWTClaimsSet refreshTokenClaims = TestRefreshTokenIssuer
        .defaultClaims(dpopJWKThumbprint)
        .claim(RefreshTokenClaims.SCOPE, scope.toString())
        .claim(RefreshTokenClaims.CLIENT_ID, clientID)
        .build();
    private final SignedJWT refreshToken = TestRefreshTokenIssuer.buildRefreshToken(refreshTokenClaims);

    private RefreshTokenValidator validator;

    @Nested
    class NonHSM {

        @BeforeEach
        void setUp() {
            validator = new RefreshTokenValidator(metadata, de.bdr.pidp.issuer.authorization.ConfigTestData.AUTH_CONFIG, temporarySignerProvider, null);
        }

        @Test
        void success() {
            initSignerProvider();

            var claims = validator.validate(refreshToken, clientID, dpopJWKThumbprint, scope);

            assertThat(claims).isEqualTo(refreshTokenClaims);
        }

        @Test
        void successWithoutRequestScope() {
            initSignerProvider();

            var claims = validator.validate(refreshToken, clientID, dpopJWKThumbprint, new Scope());

            assertThat(claims).isEqualTo(refreshTokenClaims);
        }

        @Test
        void invalidClientID() {
            initSignerProvider();

            assertThatThrownBy(() -> validator.validate(refreshToken, "Vendetta", dpopJWKThumbprint, scope))
                .asInstanceOf(type(InvalidGrantException.class))
                .extracting(OAuthException::getErrorCode)
                .isEqualTo("invalid_grant");
        }

        @Test
        void invalidDPoPJWKThumbprint() {
            initSignerProvider();

            assertThatThrownBy(() -> validator.validate(refreshToken, clientID, Base64URL.encode("I’ll be back"), scope))
                .asInstanceOf(type(InvalidGrantException.class))
                .extracting(OAuthException::getErrorCode)
                .isEqualTo("invalid_grant");
        }

        @Test
        void invalidSignature() {
            doReturn(TestUtils.generateEcKey().toPublicJWK()).when(temporarySignerProvider).findPublicKey(any());

            assertThatThrownBy(() -> validator.validate(refreshToken, clientID, dpopJWKThumbprint, scope))
                .asInstanceOf(type(InvalidGrantException.class))
                .extracting(OAuthException::getErrorCode)
                .isEqualTo("invalid_grant");
        }

        @Test
        void missingSignature() {
            initSignerProvider();

            var unsignedRefreshToken = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), new JWTClaimsSet.Builder().build());

            assertThatThrownBy(() -> validator.validate(unsignedRefreshToken, clientID, dpopJWKThumbprint, scope))
                .asInstanceOf(type(InvalidGrantException.class))
                .extracting(OAuthException::getErrorCode)
                .isEqualTo("invalid_grant");
        }

        @Test
        void insufficientScope() {
            initSignerProvider();

            var claims = TestRefreshTokenIssuer.defaultClaims(Base64URL.encode("Es heißt Levi-o-sa, nicht Leviosaaa!"))
                .claim(RefreshTokenClaims.SCOPE, "Wutschen und Wedeln").build();
            var insufficientRefreshToken = TestRefreshTokenIssuer.buildRefreshToken(claims);

            assertThatThrownBy(() -> validator.validate(insufficientRefreshToken, clientID, dpopJWKThumbprint, scope))
                .asInstanceOf(type(InvalidScopeException.class))
                .extracting(OAuthException::getErrorCode)
                .isEqualTo("invalid_scope");
        }

        @Test
        void invalidJOSEType() {
            initSignerProvider();

            var exhaustToken = TestUtils.buildJWT(refreshTokenClaims, new JOSEObjectType("exhaust-token+jwt"), TestRefreshTokenIssuer.SIGNING_EC_KEY);

            assertThatThrownBy(() -> validator.validate(exhaustToken, clientID, dpopJWKThumbprint, scope))
                .asInstanceOf(type(InvalidGrantException.class))
                .extracting(OAuthException::getErrorCode)
                .isEqualTo("invalid_grant");
        }

        private void initSignerProvider() {
            doReturn(TestRefreshTokenIssuer.SIGNING_EC_KEY.toPublicJWK()).when(temporarySignerProvider)
                .findPublicKey(new KeyID(TestRefreshTokenIssuer.SIGNING_EC_KEY.getKeyID()));
        }
    }

    @Nested
    class HSM {

        @SuppressWarnings("unchecked")
        private final JWKSource<RefreshTokenSecurityContext> source = (JWKSource<RefreshTokenSecurityContext>) mock(JWKSource.class);

        @BeforeEach
        void setUp() {
            doReturn(source).when(hsmRefreshTokenSignerProvider).jwkSource();
            validator = new RefreshTokenValidator(metadata, de.bdr.pidp.issuer.authorization.ConfigTestData.AUTH_CONFIG, temporarySignerProvider, hsmRefreshTokenSignerProvider);
        }

        @Test
        void success() throws KeySourceException {
            initSignerProvider();

            var claims = validator.validate(refreshToken, clientID, dpopJWKThumbprint, scope);

            assertThat(claims).isEqualTo(refreshTokenClaims);
        }

        @Test
        void successWithoutRequestScope() throws KeySourceException {
            initSignerProvider();

            var claims = validator.validate(refreshToken, clientID, dpopJWKThumbprint, new Scope());

            assertThat(claims).isEqualTo(refreshTokenClaims);
        }

        @Test
        void invalidClientID() throws KeySourceException {
            initSignerProvider();

            assertThatThrownBy(() -> validator.validate(refreshToken, "Vendetta", dpopJWKThumbprint, scope))
                .asInstanceOf(type(InvalidGrantException.class))
                .extracting(OAuthException::getErrorCode)
                .isEqualTo("invalid_grant");
        }

        @Test
        void invalidDPoPJWKThumbprint() throws KeySourceException {
            initSignerProvider();

            assertThatThrownBy(() -> validator.validate(refreshToken, clientID, Base64URL.encode("I’ll be back"), scope))
                .asInstanceOf(type(InvalidGrantException.class))
                .extracting(OAuthException::getErrorCode)
                .isEqualTo("invalid_grant");
        }

        @Test
        void invalidSignature() throws KeySourceException {
            doReturn(List.of(TestUtils.generateEcKey())).when(source).get(any(), any(RefreshTokenSecurityContext.class));

            assertThatThrownBy(() -> validator.validate(refreshToken, clientID, dpopJWKThumbprint, scope))
                .asInstanceOf(type(InvalidGrantException.class))
                .extracting(OAuthException::getErrorCode)
                .isEqualTo("invalid_grant");
        }

        @Test
        void missingSignature() throws KeySourceException {
            initSignerProvider();

            var unsignedRefreshToken = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), new JWTClaimsSet.Builder().build());

            assertThatThrownBy(() -> validator.validate(unsignedRefreshToken, clientID, dpopJWKThumbprint, scope))
                .asInstanceOf(type(InvalidGrantException.class))
                .extracting(OAuthException::getErrorCode)
                .isEqualTo("invalid_grant");
        }

        @Test
        void insufficientScope() throws KeySourceException {
            initSignerProvider();

            var claims = TestRefreshTokenIssuer.defaultClaims(Base64URL.encode("Es heißt Levi-o-sa, nicht Leviosaaa!"))
                .claim(RefreshTokenClaims.SCOPE, "Wutschen und Wedeln").build();
            var insufficientRefreshToken = TestRefreshTokenIssuer.buildRefreshToken(claims);

            assertThatThrownBy(() -> validator.validate(insufficientRefreshToken, clientID, dpopJWKThumbprint, scope))
                .asInstanceOf(type(InvalidScopeException.class))
                .extracting(OAuthException::getErrorCode)
                .isEqualTo("invalid_scope");
        }

        @Test
        void invalidJOSEType() throws KeySourceException {
            initSignerProvider();

            var exhaustToken = TestUtils.buildJWT(refreshTokenClaims, new JOSEObjectType("exhaust-token+jwt"), TestRefreshTokenIssuer.SIGNING_EC_KEY);

            assertThatThrownBy(() -> validator.validate(exhaustToken, clientID, dpopJWKThumbprint, scope))
                .asInstanceOf(type(InvalidGrantException.class))
                .extracting(OAuthException::getErrorCode)
                .isEqualTo("invalid_grant");
        }

        @Test
        void unresolvableKID() throws KeySourceException {
            doReturn(Collections.emptyList()).when(source).get(any(), any(RefreshTokenSecurityContext.class));

            assertThatThrownBy(() -> validator.validate(refreshToken, clientID, dpopJWKThumbprint, scope))
                .asInstanceOf(type(InvalidGrantException.class))
                .extracting(OAuthException::getErrorCode)
                .isEqualTo("invalid_grant");
        }

        private void initSignerProvider() throws KeySourceException {
            doReturn(List.of(TestRefreshTokenIssuer.SIGNING_EC_KEY.toPublicJWK())).when(source).get(any(), any(RefreshTokenSecurityContext.class));
        }
    }
}
