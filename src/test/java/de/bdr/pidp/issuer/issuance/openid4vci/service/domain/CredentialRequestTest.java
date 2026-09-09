/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service.domain;

import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidAccessTokenException;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidCredentialRequestException;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidProofException;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.UnknownCredentialConfigurationException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpMethod;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static de.bdr.pidp.issuer.issuance.RequestUtil.HTTP_HEADER;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CredentialRequestTest {

    private static final String HTTP_METHOD_POST = HttpMethod.POST.name();

    @Test
    @DisplayName("invalid json")
    void test001() {
        var body = """
                { {
                    "credential_configuration_id": "%s",
                    "proofs": {
                       \s
                    }
                }\s
                """.formatted(CredentialConfigurationID.SD_JWT_V1.getName());
        assertThatThrownBy(() -> new CredentialRequest(HTTP_METHOD_POST, HTTP_HEADER, body))
            .isInstanceOf(InvalidCredentialRequestException.class)
            .hasMessageStartingWith("Unexpected character ('{'");
    }

    @Test
    @DisplayName("invalid proofs")
    void test002() {
        var body = """
                {
                    "credential_configuration_id": "%s",
                    "proofs": {
                       \s
                    }
                }\s
                """.formatted(CredentialConfigurationID.SD_JWT_V1.getName());
        assertThatThrownBy(() -> new CredentialRequest(HTTP_METHOD_POST, HTTP_HEADER, body))
            .isInstanceOf(InvalidProofException.class)
            .hasMessage("Proof JWT could not be parsed");
    }

    @Test
    @DisplayName("illegal proof")
    void test003() {
        var body = """
                {
                    "credential_configuration_id": "%s",
                    "proofs": {
                       "jwt": ["illegal"]
                    }
                }""".formatted(CredentialConfigurationID.SD_JWT_V1.getName());
        assertThatThrownBy(() -> new CredentialRequest(HTTP_METHOD_POST, HTTP_HEADER, body))
            .isInstanceOf(InvalidProofException.class)
            .hasMessage("Proof JWT could not be parsed");
    }

    @Test
    @DisplayName("illegal proof type")
    void test004() {
        var body = """
                {
                    "credential_configuration_id": "%s",
                    "proofs": {
                       "illegal": ["eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJraWQiOiJjb1Rzd1Z5YVlpajBiQW5lbFVKZVhwdnk0bzBuTGpJaVJnMGRzVkM2ZHcybyIsIngiOiJpWnVpMGZMTUFLUGFpZUxUdkc3aEI1UTVDZW9IQWRETzBhdjU0ZjVyMjRJIiwieSI6ImNVaTRxdVBMT0JpZWRrMUlEUnEzQWFlNmg4MjdBNW9EWS1XRG1GRDRtZmsiLCJhbGciOiJFUzI1NiJ9fQ.eyJpc3MiOiIxNTJlNzU2Ni1iMzM2LTExZjAtOWU5MS0wMDE1NWQ1MGQyYTgiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODQiLCJpYXQiOjE3ODExODc4NTMsIm5vbmNlIjoiUHdiMUxaREFFMzRON3VuRjNENThDejBBa2xtcElaYkZsOWxnUlljWEdtYzkifQ.2j0wI3WrVPPOOJDZDWKHf07jvrjJHbDVmm9ZMzMxORc0B-q5lSnhAQ98p8EerDbcNqZABBxcy1qEEjYackducQ"]
                    }
                }""".formatted(CredentialConfigurationID.SD_JWT_V1.getName());
        assertThatThrownBy(() -> new CredentialRequest(HTTP_METHOD_POST, HTTP_HEADER, body))
            .isInstanceOf(InvalidProofException.class)
            .hasMessage("Proof JWT could not be parsed");
    }

    @Test
    @DisplayName("unknown CredentialConfigurationID")
    void test005() {
        var body = """
                {
                    "credential_configuration_id": "unknown",
                    "proofs": {
                       "jwt": ["eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJraWQiOiJjb1Rzd1Z5YVlpajBiQW5lbFVKZVhwdnk0bzBuTGpJaVJnMGRzVkM2ZHcybyIsIngiOiJpWnVpMGZMTUFLUGFpZUxUdkc3aEI1UTVDZW9IQWRETzBhdjU0ZjVyMjRJIiwieSI6ImNVaTRxdVBMT0JpZWRrMUlEUnEzQWFlNmg4MjdBNW9EWS1XRG1GRDRtZmsiLCJhbGciOiJFUzI1NiJ9fQ.eyJpc3MiOiIxNTJlNzU2Ni1iMzM2LTExZjAtOWU5MS0wMDE1NWQ1MGQyYTgiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODQiLCJpYXQiOjE3ODExODc4NTMsIm5vbmNlIjoiUHdiMUxaREFFMzRON3VuRjNENThDejBBa2xtcElaYkZsOWxnUlljWEdtYzkifQ.2j0wI3WrVPPOOJDZDWKHf07jvrjJHbDVmm9ZMzMxORc0B-q5lSnhAQ98p8EerDbcNqZABBxcy1qEEjYackducQ"]
                    }
                }""";
        assertThatThrownBy(() -> new CredentialRequest(HTTP_METHOD_POST, HTTP_HEADER, body))
            .isInstanceOf(UnknownCredentialConfigurationException.class)
            .hasMessage("credential_configuration_id \"unknown\" not supported");
    }

    @Test
    @DisplayName("missing CredentialConfigurationID")
    void test006() {
        var body = """
                {
                    "proofs": {
                       "jwt": ["eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJraWQiOiJjb1Rzd1Z5YVlpajBiQW5lbFVKZVhwdnk0bzBuTGpJaVJnMGRzVkM2ZHcybyIsIngiOiJpWnVpMGZMTUFLUGFpZUxUdkc3aEI1UTVDZW9IQWRETzBhdjU0ZjVyMjRJIiwieSI6ImNVaTRxdVBMT0JpZWRrMUlEUnEzQWFlNmg4MjdBNW9EWS1XRG1GRDRtZmsiLCJhbGciOiJFUzI1NiJ9fQ.eyJpc3MiOiIxNTJlNzU2Ni1iMzM2LTExZjAtOWU5MS0wMDE1NWQ1MGQyYTgiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODQiLCJpYXQiOjE3ODExODc4NTMsIm5vbmNlIjoiUHdiMUxaREFFMzRON3VuRjNENThDejBBa2xtcElaYkZsOWxnUlljWEdtYzkifQ.2j0wI3WrVPPOOJDZDWKHf07jvrjJHbDVmm9ZMzMxORc0B-q5lSnhAQ98p8EerDbcNqZABBxcy1qEEjYackducQ"]
                    }
                }""";
        assertThatThrownBy(() -> new CredentialRequest(HTTP_METHOD_POST, HTTP_HEADER, body))
            .isInstanceOf(InvalidCredentialRequestException.class)
            .hasMessage("credential_configuration_id parameter is missing");
    }

    @ParameterizedTest
    @ValueSource(strings = {"DPoP", "DPo 1234", "DPoP \t", "DPoP 1234"})
    @EmptySource
    @DisplayName("distinct invalid authorization header")
    void test007(String authorization) {
        var body = """
                {
                    "credential_configuration_id": "%s",
                    "proofs": {
                       "jwt": ["eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJraWQiOiJjb1Rzd1Z5YVlpajBiQW5lbFVKZVhwdnk0bzBuTGpJaVJnMGRzVkM2ZHcybyIsIngiOiJpWnVpMGZMTUFLUGFpZUxUdkc3aEI1UTVDZW9IQWRETzBhdjU0ZjVyMjRJIiwieSI6ImNVaTRxdVBMT0JpZWRrMUlEUnEzQWFlNmg4MjdBNW9EWS1XRG1GRDRtZmsiLCJhbGciOiJFUzI1NiJ9fQ.eyJpc3MiOiIxNTJlNzU2Ni1iMzM2LTExZjAtOWU5MS0wMDE1NWQ1MGQyYTgiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODQiLCJpYXQiOjE3ODExODc4NTMsIm5vbmNlIjoiUHdiMUxaREFFMzRON3VuRjNENThDejBBa2xtcElaYkZsOWxnUlljWEdtYzkifQ.2j0wI3WrVPPOOJDZDWKHf07jvrjJHbDVmm9ZMzMxORc0B-q5lSnhAQ98p8EerDbcNqZABBxcy1qEEjYackducQ"]
                    }
                }""".formatted(CredentialConfigurationID.SD_JWT_V1.getName());
        Map<String, List<String>> allHeaders = Map.of("authorization", List.of(authorization));
        assertThatThrownBy(() -> new CredentialRequest(HTTP_METHOD_POST, allHeaders, body))
            .isInstanceOf(InvalidAccessTokenException.class);
    }

    @Test
    @DisplayName("empty authorization header")
    void test008() {
        var body = """
                {
                    "credential_configuration_id": "%s",
                    "proofs": {
                       "jwt": ["eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJraWQiOiJjb1Rzd1Z5YVlpajBiQW5lbFVKZVhwdnk0bzBuTGpJaVJnMGRzVkM2ZHcybyIsIngiOiJpWnVpMGZMTUFLUGFpZUxUdkc3aEI1UTVDZW9IQWRETzBhdjU0ZjVyMjRJIiwieSI6ImNVaTRxdVBMT0JpZWRrMUlEUnEzQWFlNmg4MjdBNW9EWS1XRG1GRDRtZmsiLCJhbGciOiJFUzI1NiJ9fQ.eyJpc3MiOiIxNTJlNzU2Ni1iMzM2LTExZjAtOWU5MS0wMDE1NWQ1MGQyYTgiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODQiLCJpYXQiOjE3ODExODc4NTMsIm5vbmNlIjoiUHdiMUxaREFFMzRON3VuRjNENThDejBBa2xtcElaYkZsOWxnUlljWEdtYzkifQ.2j0wI3WrVPPOOJDZDWKHf07jvrjJHbDVmm9ZMzMxORc0B-q5lSnhAQ98p8EerDbcNqZABBxcy1qEEjYackducQ"]
                    }
                }""".formatted(CredentialConfigurationID.SD_JWT_V1.getName());
        Map<String, List<String>> emptyHeader = Map.of("authorization", List.of());
        Assertions.assertAll(
            () -> assertThatThrownBy(() -> new CredentialRequest(HTTP_METHOD_POST, emptyHeader, body))
                .isInstanceOf(InvalidAccessTokenException.class),
            () -> assertThatThrownBy(() -> new CredentialRequest(HTTP_METHOD_POST, Collections.emptyMap(), body))
                .isInstanceOf(InvalidAccessTokenException.class)

        );
    }
}
