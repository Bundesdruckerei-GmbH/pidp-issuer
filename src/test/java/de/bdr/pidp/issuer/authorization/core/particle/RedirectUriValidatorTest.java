/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle;

import de.bdr.pidp.issuer.authorization.core.exception.InvalidGrantException;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidRequestException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static de.bdr.pidp.issuer.testdata.ValidTestData.REDIRECT_URI;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

class RedirectUriValidatorTest {

    private final RedirectUriValidator validator = new RedirectUriValidator();

    private static Stream<Arguments> validRedirectUriProvider() {
        return Stream.of(
            Arguments.arguments("com.example.app:/oauth2redirect/example-provider"),
            Arguments.arguments("com.example.app:/oauth2redirect?example=provider"),
            Arguments.arguments("com.example.app:/?oauth2redirect=example-provider"),
            Arguments.arguments("com.example.app:/"),

            Arguments.arguments("https://app.example.com/oauth2redirect/example-provider"),
            Arguments.arguments("https://app.example.com/oauth2redirect?example=provider"),
            Arguments.arguments("https://app.example.com?oauth2redirect=example-provider"),
            Arguments.arguments("https://example"),

            Arguments.arguments("http://127.0.0.1:51004/oauth2redirect/example-provider"),
            Arguments.arguments("http://127.0.0.1:65535/oauth2redirect/example-provider"),
            Arguments.arguments("http://127.0.0.1:51004/oauth2redirect?example=provider"),
            Arguments.arguments("http://127.0.0.1:51004?oauth2redirect=example-provider"),
            Arguments.arguments("http://127.0.0.1:51004"),
            Arguments.arguments("http://[::1]:61023/oauth2redirect/example-provider"),
            Arguments.arguments("http://[::1]:61023/oauth2redirect?example=provider"),
            Arguments.arguments("http://[::1]:61023?oauth2redirect=example-provider"),
            Arguments.arguments("http://[::1]:61023")
        );
    }

    private static Stream<Arguments> invalidRedirectUriProvider() {
        return Stream.of(
            Arguments.arguments(" "),
            Arguments.arguments("com%example%app:/oauth2redirect/example-provider"),
            Arguments.arguments(".com.example.app:/oauth2redirect/example-provider"),
            Arguments.arguments("1com.example.app:/oauth2redirect/example-provider"),
            Arguments.arguments("com.example.app:"),
            Arguments.arguments("https://"),
            Arguments.arguments("https   app example com"),
            Arguments.arguments("https://app.example.com: 1"),
            Arguments.arguments("127.0.0.1:51004/oauth2redirect/example-provider"),
            Arguments.arguments("[::1]:61023/oauth2redirect/example-provider")
        );
    }

    private static Stream<Arguments> unsupportedRedirectUriProvider() {
        return Stream.of(
            Arguments.arguments("localhost:/oauth2redirect/example-provider"),
            Arguments.arguments("com-example-app:/oauth2redirect/example-provider"),
            Arguments.arguments("com.example.app://oauth2redirect/example-provider"),
            Arguments.arguments("com.example.app/oauth2redirect/example-provider"),
            Arguments.arguments("com.example.app:/oauth2redirect/example-provider#fragment"),
            Arguments.arguments("com.example.app.:/oauth2redirect/example-provider"),
            Arguments.arguments("com.example.app"),

            Arguments.arguments("htpps://app.example.com/oauth2redirect/example-provider"),
            Arguments.arguments("https:/app.example.com/oauth2redirect/example-provider"),
            Arguments.arguments("https://app.example.com/oauth2redirect/example-provider#fragment"),
            Arguments.arguments("https://?oauth2redirect=example-provider"),

            Arguments.arguments("http://localhost:51004"),
            Arguments.arguments("http://127.0.0.2:51004/oauth2redirect/example-provider"),
            Arguments.arguments("http://127.0.0.1/oauth2redirect/example-provider"),
            Arguments.arguments("http://127.0.0.1:51004/oauth2redirect/example-provider#fragment"),
            Arguments.arguments("http://127.0.0.1:65536/oauth2redirect/example-provider"),
            Arguments.arguments("http://[::2]:61023/oauth2redirect/example-provider"),
            Arguments.arguments("http://[::1]/oauth2redirect/example-provider"),
            Arguments.arguments("http://[::1]:61023/oauth2redirect/example-provider#fragment")
        );
    }

    @ParameterizedTest
    @MethodSource("validRedirectUriProvider")
    void processValidation(String redirectUri) {
        assertThatNoException().isThrownBy(() -> validator.validateRedirectUri(redirectUri));
    }

    @Test
    void processComparation() {
        assertThatNoException().isThrownBy(() -> validator.validateRedirectUri(REDIRECT_URI, REDIRECT_URI));
    }

    @ParameterizedTest
    @MethodSource("invalidRedirectUriProvider")
    void processInvalidRedirectUri(String redirectUri) {
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() -> validator.validateRedirectUri(redirectUri))
            .withMessage("Redirect URI not a valid URI");
    }

    @ParameterizedTest
    @MethodSource("unsupportedRedirectUriProvider")
    void processUnsupportedRedirectUri(String redirectUri) {
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() -> validator.validateRedirectUri(redirectUri))
            .withMessage("Redirect URI unsupported");
    }

    @Test
    void processDifferentRedirectUri() {
        assertThatExceptionOfType(InvalidGrantException.class).isThrownBy(() -> validator.validateRedirectUri("https://redirect.localhost:1", "https://redirect.localhost:2"))
            .withMessage("Invalid redirect URI");
    }
}
