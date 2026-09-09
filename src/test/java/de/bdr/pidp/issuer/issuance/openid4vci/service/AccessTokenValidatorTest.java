/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.Issuer;
import de.bdr.pidp.issuer.base.constants.AccessTokenClaims;
import de.bdr.pidp.issuer.issuance.ConfigTestData;
import de.bdr.pidp.issuer.issuance.config.IssuanceTestMetadata;
import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import de.bdr.pidp.issuer.issuance.config.model.CredentialIssuerMetadata;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidAccessTokenException;
import de.bdr.pidp.issuer.issuance.openid4vci.out.authorization.AuthorizationDiscoveryAdapter;
import de.bdr.pidp.issuer.testdata.TestAccessTokenIssuer;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.InstanceOfAssertFactories.type;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

@ExtendWith(SpringExtension.class)
class AccessTokenValidatorTest {

    private final AuthorizationDiscoveryAdapter discovery = mock(AuthorizationDiscoveryAdapter.class);
    private final CredentialIssuerMetadata metadata = IssuanceTestMetadata.ISSUANCE_METADATA;
    private final JWTClaimsSet accessTokenClaims = TestAccessTokenIssuer.defaultClaims(Base64URL.encode("Ein Hering hat doch so viele Federn")).build();
    private final SignedJWT accessToken = TestAccessTokenIssuer.buildAccessToken(accessTokenClaims);

    private AccessTokenValidator validator;

    @BeforeEach
    void setUp() {
        doReturn(List.of(JWSAlgorithm.ES256)).when(discovery).getDPoPSigningAlgorithms();
        validator = new AccessTokenValidator(metadata, ConfigTestData.ISSUANCE_CONFIG, discovery);
    }

    @Test
    void success() {
        doReturn(metadata.credentialIssuer()).when(discovery).getIssuer();
        doReturn(new JWKSet(TestAccessTokenIssuer.SIGNING_EC_KEY.toPublicJWK())).when(discovery).getJWKSet();

        var claims = validator.validate(accessToken, CredentialConfigurationID.SD_JWT_V1);

        assertThat(claims).isEqualTo(accessTokenClaims);
    }

    @Test
    void invalidCredentialIssuer() {
        doReturn(new Issuer("DIP-Issuer")).when(discovery).getIssuer();
        doReturn(new JWKSet(TestAccessTokenIssuer.SIGNING_EC_KEY.toPublicJWK())).when(discovery).getJWKSet();

        assertThatThrownBy(() -> validator.validate(accessToken, CredentialConfigurationID.SD_JWT_V1))
            .asInstanceOf(type(InvalidAccessTokenException.class))
            .extracting(InvalidAccessTokenException::getReason)
            .isEqualTo(InvalidAccessTokenException.Reason.INVALID_TOKEN);
    }

    @Test
    void invalidSignature() {
        doReturn(metadata.credentialIssuer()).when(discovery).getIssuer();
        doReturn(new JWKSet(TestUtils.generateEcKey().toPublicJWK())).when(discovery).getJWKSet();

        assertThatThrownBy(() -> validator.validate(accessToken, CredentialConfigurationID.SD_JWT_V1))
            .asInstanceOf(type(InvalidAccessTokenException.class))
            .extracting(InvalidAccessTokenException::getReason)
            .isEqualTo(InvalidAccessTokenException.Reason.INVALID_TOKEN);
    }

    @Test
    void missingSignature() {
        doReturn(metadata.credentialIssuer()).when(discovery).getIssuer();
        doReturn(new JWKSet(TestAccessTokenIssuer.SIGNING_EC_KEY.toPublicJWK())).when(discovery).getJWKSet();

        var unsignedAccessToken = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), new JWTClaimsSet.Builder().build());

        assertThatThrownBy(() -> validator.validate(unsignedAccessToken, CredentialConfigurationID.SD_JWT_V1))
            .asInstanceOf(type(InvalidAccessTokenException.class))
            .extracting(InvalidAccessTokenException::getReason)
            .isEqualTo(InvalidAccessTokenException.Reason.INVALID_TOKEN);
    }

    @Test
    void insufficientScope() {
        doReturn(metadata.credentialIssuer()).when(discovery).getIssuer();
        doReturn(new JWKSet(TestAccessTokenIssuer.SIGNING_EC_KEY.toPublicJWK())).when(discovery).getJWKSet();

        var claims = TestAccessTokenIssuer.defaultClaims(Base64URL.encode("Es heißt Levi-o-sa, nicht Leviosaaa!"))
            .claim(AccessTokenClaims.SCOPE, "Wutschen und Wedeln").build();
        var insufficientAccessToken = TestAccessTokenIssuer.buildAccessToken(claims);

        assertThatThrownBy(() -> validator.validate(insufficientAccessToken, CredentialConfigurationID.SD_JWT_V1))
            .asInstanceOf(type(InvalidAccessTokenException.class))
            .extracting(InvalidAccessTokenException::getReason)
            .isEqualTo(InvalidAccessTokenException.Reason.INSUFFICIENT_SCOPE);
    }

    @Test
    void invalidSigningAlg() {
        doReturn(List.of(JWSAlgorithm.RS256)).when(discovery).getDPoPSigningAlgorithms();
        var rsaValidator = new AccessTokenValidator(metadata, ConfigTestData.ISSUANCE_CONFIG, discovery);

        doReturn(metadata.credentialIssuer()).when(discovery).getIssuer();
        doReturn(new JWKSet(TestAccessTokenIssuer.SIGNING_EC_KEY.toPublicJWK())).when(discovery).getJWKSet();

        assertThatThrownBy(() -> rsaValidator.validate(accessToken, CredentialConfigurationID.SD_JWT_V1))
            .asInstanceOf(type(InvalidAccessTokenException.class))
            .extracting(InvalidAccessTokenException::getReason)
            .isEqualTo(InvalidAccessTokenException.Reason.INVALID_TOKEN);
    }

    @Test
    void invalidJOSEType() {
        doReturn(metadata.credentialIssuer()).when(discovery).getIssuer();
        doReturn(new JWKSet(TestAccessTokenIssuer.SIGNING_EC_KEY.toPublicJWK())).when(discovery).getJWKSet();

        var exitToken = TestUtils.buildJWT(accessTokenClaims, new JOSEObjectType("exit-token+jwt"), TestAccessTokenIssuer.SIGNING_EC_KEY);

        assertThatThrownBy(() -> validator.validate(exitToken, CredentialConfigurationID.SD_JWT_V1))
            .asInstanceOf(type(InvalidAccessTokenException.class))
            .extracting(InvalidAccessTokenException::getReason)
            .isEqualTo(InvalidAccessTokenException.Reason.INVALID_TOKEN);
    }
}
