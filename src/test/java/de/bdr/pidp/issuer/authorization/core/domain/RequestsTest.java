/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.domain;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class RequestsTest {

    private static Stream<Arguments> arguments() {
        return Stream.of(
                Arguments.argumentSet("pushed authorization path", Requests.PUSHED_AUTHORIZATION_REQUEST, "par"),
                Arguments.argumentSet("authorization path", Requests.AUTHORIZATION_REQUEST, "authorize"),
                Arguments.argumentSet("finish authorization path", Requests.FINISH_AUTHORIZATION_REQUEST, "finish-authorization"),
                Arguments.argumentSet("token path", Requests.TOKEN_REQUEST, "token"),
                Arguments.argumentSet("credential path", Requests.CREDENTIAL_REQUEST, "credential")
        );
    }

    @DisplayName("Validate path")
    @ParameterizedTest
    @MethodSource("arguments")
    void test(Requests request, String expected) {
        assertThat(request.getPath()).isEqualTo(expected);
    }
}
