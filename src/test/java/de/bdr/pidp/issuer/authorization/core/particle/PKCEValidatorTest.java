/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle;

import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import de.bdr.pidp.issuer.authorization.config.MetaTestData;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidGrantException;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidRequestException;
import de.bdr.pidp.issuer.testdata.ValidTestData;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.stream.IntStream;

class PKCEValidatorTest {

    private final PKCEValidator subject = new PKCEValidator(MetaTestData.AUTH_METADATA);
    private final CodeChallengeMethod challengeMethod = CodeChallengeMethod.S256;
    private final String challengeMethodValue = challengeMethod.getValue();

    @Test
    void validateCodeChallengeSuccess() {
        Assertions.assertThatNoException().isThrownBy(() ->
            subject.validateCodeChallenge(ValidTestData.CODE_CHALLENGE, challengeMethod));
    }

    @Test
    void validateCodeChallengeUnsupportedMethod() {
        Assertions.assertThatThrownBy(() ->
                subject.validateCodeChallenge(ValidTestData.CODE_CHALLENGE, CodeChallengeMethod.PLAIN))
            .isInstanceOf(InvalidRequestException.class);
    }

    @ValueSource(strings = {"NotBase64", "SW52YWxpZExlbmd0aAo="})
    @ParameterizedTest
    void validateCodeChallengeInvalidCodeChallenge(String invalidCodeChallenge) {
        Assertions.assertThatThrownBy(() ->
                subject.validateCodeChallenge(invalidCodeChallenge, challengeMethod))
            .isInstanceOf(InvalidRequestException.class);
    }

    @Test
    void validateCodeVerifierSuccess() {
        Assertions.assertThatNoException().isThrownBy(() ->
            subject.validateCodeVerifier(ValidTestData.CODE_VERIFIER, ValidTestData.CODE_CHALLENGE, challengeMethodValue));
    }

    @Test
    void validateCodeVerifierSuccessParallel() {
        Assertions.assertThatNoException().isThrownBy(() -> IntStream.range(1, 100).parallel().forEach(_ ->
            subject.validateCodeVerifier(ValidTestData.CODE_VERIFIER, ValidTestData.CODE_CHALLENGE, challengeMethodValue)));
    }

    @ValueSource(strings = {"TooShort", "TooooooooooooooooooooooooooooLong", "Invalid chars^"})
    @ParameterizedTest
    void validateCodeVerifierInvalidCodeVerifier(String invalidCodeVerifier) {
        Assertions.assertThatThrownBy(() ->
                subject.validateCodeVerifier(invalidCodeVerifier, ValidTestData.CODE_CHALLENGE, challengeMethodValue))
            .isInstanceOf(InvalidRequestException.class);
    }

    @Test
    void validateCodeVerifierNoMatch() {
        var invalidCodeVerifier = ValidTestData.CODE_VERIFIER.replace("A", "B");

        Assertions.assertThatThrownBy(() ->
                subject.validateCodeVerifier(invalidCodeVerifier, ValidTestData.CODE_CHALLENGE, challengeMethodValue))
            .isInstanceOf(InvalidGrantException.class);
    }
}
