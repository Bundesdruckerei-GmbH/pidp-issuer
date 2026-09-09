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
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import de.bdr.pidp.issuer.authorization.core.AuthorizationConfiguration;
import de.bdr.pidp.issuer.authorization.core.domain.SeedCredential;
import de.bdr.pidp.issuer.base.crypto.VersionedKeyID;
import de.bdr.pidp.issuer.base.crypto.hsm.HSMSigningService;
import org.assertj.core.data.TemporalUnitLessThanOffset;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

@SpringBootTest(properties = "hsm.enabled=true")
class RefreshTokenIssuerHSMTest {

    @Autowired
    private RefreshTokenIssuer tokenIssuer;

    @Autowired
    private HSMSigningService hsmSigningAuthorization;

    @Autowired
    private AuthorizationConfiguration configuration;

    @Test
    void success() throws JOSEException, ParseException {
        // when
        var seedExp = Instant.now().plus(5, ChronoUnit.DAYS);
        var token = tokenIssuer.buildRefreshToken("cl", "sc",  Base64URL.encode("DPoPjkt"), new SeedCredential("Mein Schatz", "seed_ref", "seed_sub", seedExp));

        // then
        var rawCert = hsmSigningAuthorization.getCertificate(VersionedKeyID.parse(token.getHeader().getKeyID()));
        var cert = X509CertUtils.parse(rawCert);
        var key = ECKey.parse(cert);
        var verifier = new ECDSAVerifier(key);

        var result = token.verify(verifier);
        assertThat(result).isTrue();
        var header = token.getHeader();
        assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.ES384);
        assertThat(header.getType()).isEqualTo(new JOSEObjectType("rt+jwt"));
        assertThat(header.getKeyID()).isEqualTo(configuration.getRtSigAliasHsm() + "/0");
        var claims = token.getJWTClaimsSet();
        assertThat(claims.getIssuer()).isEqualTo(configuration.getCredentialIssuerIdentifier());
        assertThat(claims.getSubject()).isEqualTo("seed_sub");
        assertThat(claims.getIssueTime()).isBeforeOrEqualTo(Instant.now());
        assertThat(claims.getJWTID()).isNotNull();
        Assertions.assertDoesNotThrow(() -> UUID.fromString(claims.getJWTID()));
        assertThat(claims.getStringClaim("client_id")).isEqualTo("cl");
        assertThat(claims.getStringClaim("scope")).isEqualTo("sc");
        assertThatNoException().isThrownBy(() -> {
            var cnf = JWKThumbprintConfirmation.parse(claims);
            assertThat(cnf).isNotNull().extracting(JWKThumbprintConfirmation::getValue).isEqualTo(Base64URL.encode("DPoPjkt"));
        });
        assertThat(claims.getAudience()).hasSize(1).containsExactly(configuration.getCredentialIssuerIdentifier());
        assertThat(claims.getExpirationTime().toInstant()).isCloseTo(seedExp, new TemporalUnitLessThanOffset(1, ChronoUnit.SECONDS));
        assertThat(claims.getStringClaim("https://pid-provider.bundesdruckerei.de/seed_credential")).isEqualTo("Mein Schatz");
    }

    @Test
    void expLimitedByMaxLifetime() throws ParseException {
        // when
        var exp = Instant.now().plus(configuration.getRefreshTokenMaxLifetime());
        var seedExp = exp.plus(5, ChronoUnit.DAYS);
        var token = tokenIssuer.buildRefreshToken("cl", "sc",  Base64URL.encode("DPoPjkt"), new SeedCredential("Mein Schatz", "seed_ref", "seed_sub", seedExp));

        // then
        var claims = token.getJWTClaimsSet();
        assertThat(claims.getExpirationTime().toInstant()).isCloseTo(exp, new TemporalUnitLessThanOffset(1, ChronoUnit.SECONDS));
    }
}

