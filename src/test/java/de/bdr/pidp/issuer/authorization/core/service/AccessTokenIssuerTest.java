/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import de.bdr.pidp.issuer.authorization.core.AuthorizationConfiguration;
import de.bdr.pidp.issuer.authorization.core.domain.SeedCredentialReference;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.vault.core.VaultTemplate;

import java.text.ParseException;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

@SpringBootTest
class AccessTokenIssuerTest {

    @Autowired
    private AccessTokenIssuer tokenIssuer;

    @Autowired
    private VaultTemplate vaultTemplate;

    @Autowired
    private AuthorizationConfiguration configuration;

    @Test
    void issueAccessTokenSuccess() throws JOSEException, ParseException {
        // given
        var key = vaultTemplate.opsForTransit(configuration.getKms().getTransitPath()).getKey(configuration.getAtSigAlias());
        @SuppressWarnings("unchecked")
        var attributes = (Map<String, String>) Objects.requireNonNull(key).getKeys().get("1");
        var pub = attributes.get("public_key");
        var ecKey = ECKey.parseFromPEMEncodedObjects(pub);
        var verifier = new ECDSAVerifier(ecKey.toECKey());

        // when
        var atID = UUID.randomUUID();
        var token = tokenIssuer.buildAccessToken(atID, "cl", "sc", Base64URL.encode("DPoPjkt"), new SeedCredentialReference("seed_jti", "seed_sub"), "pmt_jti");

        // then
        var result = token.verify(verifier);
        assertThat(result).isTrue();
        var header = token.getHeader();
        assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
        assertThat(header.getType()).isEqualTo(new JOSEObjectType("at+jwt"));
        assertThat(header.getKeyID()).isEqualTo(configuration.getAtSigAlias() + "/1");
        var claims = token.getJWTClaimsSet();
        assertThat(claims.getIssuer()).isEqualTo(configuration.getCredentialIssuerIdentifier());
        assertThat(claims.getSubject()).isEqualTo("seed_sub");
        assertThat(claims.getIssueTime()).isBeforeOrEqualTo(Instant.now());
        assertThat(claims.getJWTID()).isEqualTo(atID.toString());
        assertThat(claims.getStringClaim("client_id")).isEqualTo("cl");
        assertThat(claims.getStringClaim("scope")).isEqualTo("sc");
        assertThatNoException().isThrownBy(() -> {
            var cnf = JWKThumbprintConfirmation.parse(claims);
            assertThat(cnf).isNotNull().extracting(JWKThumbprintConfirmation::getValue).isEqualTo(Base64URL.encode("DPoPjkt"));
        });
        assertThat(claims.getAudience()).hasSize(1).containsExactly(configuration.getCredentialIssuerIdentifier());
        assertThat(claims.getExpirationTime()).isAfter(Instant.now());
        assertThat(claims.getStringClaim("https://pid-provider.bundesdruckerei.de/seed_credential_ref")).isEqualTo("seed_jti");
    }
}
