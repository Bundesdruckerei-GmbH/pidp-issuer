/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base;

import com.nimbusds.jwt.proc.BadJWTException;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KeyAttestationClaimsVerifierTest {

    private final String validNonce = RandomUtil.randomString();
    private final int maxClockSkew = 30;
    private final KeyAttestationClaimsVerifier verifier = new KeyAttestationClaimsVerifier(
            List.of("iso_18045_high"),
            List.of("iso_18045_high"),
            maxClockSkew
    );
    private final KeyAttestationClaimsVerifier verifierNoOptional = new KeyAttestationClaimsVerifier(
            null,
            null,
            maxClockSkew
    );

    private KeyAttestationSecurityContext context;

    @BeforeEach
    void setUp() {
        context = new KeyAttestationSecurityContext(
            TestUtils.KEY_ATTESTATION_TRUST_ANCHOR,
            nonce -> nonce != null && nonce.getValue().equals(validNonce)
        );
    }

    @Test
    void success() throws BadJWTException {
        var claims = TestUtils.getKeyAttestationClaimsBuilderWithDefaults(validNonce)
                .build();

        verifier.verify(claims, context);

        assertThat(context.getKeys()).isEqualTo(TestUtils.ATTESTED_KEYS);
    }

    @Test
    void missingIssueTime() {
        var claims = TestUtils.getKeyAttestationClaimsBuilderWithDefaults(validNonce)
                .issueTime(null)
                .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
                .isInstanceOf(BadJWTException.class)
                .hasMessage("Missing JWT issue time (iat) claim");
    }

    @Test
    void aheadIssueTime() {
        var claims = TestUtils.getKeyAttestationClaimsBuilderWithDefaults(validNonce)
                .issueTime(Date.from(Instant.now().plusSeconds(maxClockSkew * 2)))
                .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
                .isInstanceOf(BadJWTException.class)
                .hasMessage("JWT issue time ahead of current time");
    }

    @Test
    void aheadIssueTimeWithinTolerance() throws BadJWTException {
        var claims = TestUtils.getKeyAttestationClaimsBuilderWithDefaults(validNonce)
                .issueTime(Date.from(Instant.now().plusSeconds(maxClockSkew / 2)))
                .build();

        verifier.verify(claims, context);

        assertThat(context.getKeys()).isEqualTo(TestUtils.ATTESTED_KEYS);
    }

    @Test
    void missingExpirationTime() throws BadJWTException {
        var claims = TestUtils.getKeyAttestationClaimsBuilderWithDefaults(validNonce)
                .expirationTime(null)
                .build();

        verifier.verify(claims, context);

        assertThat(context.getKeys()).isEqualTo(TestUtils.ATTESTED_KEYS);
    }

    @Test
    void pastExpirationTime() {
        var claims = TestUtils.getKeyAttestationClaimsBuilderWithDefaults(validNonce)
                .expirationTime(Date.from(Instant.now().minusSeconds(maxClockSkew * 2)))
                .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
                .isInstanceOf(BadJWTException.class)
                .hasMessage("Expired JWT");
    }

    @Test
    void pastExpirationTimeWithinTolerance() throws BadJWTException {
        var claims = TestUtils.getKeyAttestationClaimsBuilderWithDefaults(validNonce)
                .issueTime(Date.from(Instant.now().minusSeconds(maxClockSkew / 2)))
                .build();

        verifier.verify(claims, context);

        assertThat(context.getKeys()).isEqualTo(TestUtils.ATTESTED_KEYS);
    }

    @Test
    void missingNonce() {
        var claims = TestUtils.getKeyAttestationClaimsBuilderWithDefaults(validNonce)
                .claim("nonce", null)
                .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
                .isInstanceOf(BadJWTException.class)
                .hasMessage("Missing JWT nonce (nonce) claim");
    }

    @Test
    void emptyNonce() {
        var claims = TestUtils.getKeyAttestationClaimsBuilderWithDefaults(validNonce)
                .claim("nonce", "")
                .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
                .isInstanceOf(BadJWTException.class)
                .hasMessage("Unexpected JWT nonce (nonce) claim: ''");
    }

    @Test
    void invalidNonce() {
        var claims = TestUtils.getKeyAttestationClaimsBuilderWithDefaults(validNonce)
                .claim("nonce", "invalid_nonce")
                .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
                .isInstanceOf(BadJWTException.class)
                .hasMessage("Unexpected JWT nonce (nonce) claim: 'invalid_nonce'");
    }

    @Test
    void missingKeyStorage() {
        var claims = TestUtils.getKeyAttestationClaimsBuilderWithDefaults(validNonce)
                .claim("key_storage", null)
                .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
                .isInstanceOf(BadJWTException.class)
                .hasMessage("Missing JWT key_storage claim");
    }

    @Test
    void unparsableKeyStorage() {
        var claims = TestUtils.getKeyAttestationClaimsBuilderWithDefaults(validNonce)
                .claim("key_storage", "this is not an array")
                .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
                .isInstanceOf(BadJWTException.class)
                .hasMessageStartingWith("Invalid JWT key_storage claim: ");
    }

    @Test
    void noSupportedKeyStorage() {
        var claims = TestUtils.getKeyAttestationClaimsBuilderWithDefaults(validNonce)
                .claim("key_storage", List.of("iso_18045_low"))
                .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
                .isInstanceOf(BadJWTException.class)
                .hasMessage("Invalid JWT key_storage claim: does not contain supported key_storage");
    }

    @Test
    void ignoreKeyStorageWhenNotSupported() throws BadJWTException {
        var claims = TestUtils.getKeyAttestationClaimsBuilderWithDefaults(validNonce)
                .claim("key_storage", List.of("iso_18045_low"))
                .build();

        verifierNoOptional.verify(claims, context);

        assertThat(context.getKeys()).isEqualTo(TestUtils.ATTESTED_KEYS);
    }

    @Test
    void missingUserAuthentication() {
        var claims = TestUtils.getKeyAttestationClaimsBuilderWithDefaults(validNonce)
                .claim("user_authentication", null)
                .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
                .isInstanceOf(BadJWTException.class)
                .hasMessage("Missing JWT user_authentication claim");
    }

    @Test
    void unparsableUserAuthentication() {
        var claims = TestUtils.getKeyAttestationClaimsBuilderWithDefaults(validNonce)
                .claim("user_authentication", "this is not an array")
                .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
                .isInstanceOf(BadJWTException.class)
                .hasMessageStartingWith("Invalid JWT user_authentication claim: ");
    }

    @Test
    void noSupportedUserAuthentication() {
        var claims = TestUtils.getKeyAttestationClaimsBuilderWithDefaults(validNonce)
                .claim("user_authentication", List.of("iso_18045_low"))
                .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
                .isInstanceOf(BadJWTException.class)
                .hasMessage("Invalid JWT user_authentication claim: does not contain supported user_authentication");
    }

    @Test
    void ignoreUserAuthenticationWhenNotSupported() throws BadJWTException {
        var claims = TestUtils.getKeyAttestationClaimsBuilderWithDefaults(validNonce)
                .claim("user_authentication", List.of("iso_18045_low"))
                .build();

        verifierNoOptional.verify(claims, context);

        assertThat(context.getKeys()).isEqualTo(TestUtils.ATTESTED_KEYS);
    }

    @Test
    void missingAttestedKeys() {
        var claims = TestUtils.getKeyAttestationClaimsBuilderWithDefaults(validNonce)
                .claim("attested_keys", null)
                .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
                .isInstanceOf(BadJWTException.class)
                .hasMessage("Missing JWT attested_keys claim");
    }

    @Test
    void unparsableAttestedKeysJWKs() {
        var claims = TestUtils.getKeyAttestationClaimsBuilderWithDefaults(validNonce)
                .claim("attested_keys", List.of("iso_18045_low"))
                .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
                .isInstanceOf(BadJWTException.class)
                .hasMessageStartingWith("Invalid JWT attested_keys claim: ");
    }

    @Test
    void unparsableAttestedKeys() {
        var claims = TestUtils.getKeyAttestationClaimsBuilderWithDefaults(validNonce)
                .claim("attested_keys", "this is not an array")
                .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
                .isInstanceOf(BadJWTException.class)
                .hasMessageStartingWith("Invalid JWT attested_keys claim: ");
    }
}
