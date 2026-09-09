/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle;

import de.bdr.pidp.issuer.authorization.core.AuthorizationConfiguration;
import de.bdr.pidp.issuer.authorization.core.domain.data.AuthSession;
import de.bdr.pidp.issuer.authorization.port.out.IdentificationDataPortOut;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.time.Duration;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthorizationHandlerTest {

    public static Stream<Arguments> provider() {
        return Stream.of(
                Arguments.arguments("http://localhost:8080", "http://localhost:8080/finish-authorization?issuer_state="),
                Arguments.arguments("https://pidi.localhost", "https://pidi.localhost/finish-authorization?issuer_state=")
        );
    }

    @DisplayName("Verify result url and issuer_state in session")
    @ParameterizedTest
    @MethodSource("provider")
    void test001(String hostname, String resultUrlPrefix) throws MalformedURLException {
        var identificationProvider = Mockito.mock(IdentificationDataPortOut.class);
        var samlRedirectUrl = "https://saml.request.localhost/path?SAMLRequest=abcde";
        when(identificationProvider.startIdentificationProcess(any(), anyString(), anyString())).
                thenReturn(URI.create(samlRedirectUrl).toURL());
        var authorizationHandlerUT = new AuthorizationHandler(getAuthConfig(hostname), identificationProvider);
        long sessionId = TestUtils.randomSessionId();
        AuthSession session = new AuthSession(sessionId);

        URL samlAuthRequestUrl = authorizationHandlerUT.processAuthRequest(session);

        String issuerState = session.getIssuerState();
        assertThat(issuerState).isNotNull();
        verify(identificationProvider)
                .startIdentificationProcess(URI.create(resultUrlPrefix + issuerState).toURL(), issuerState, String.valueOf(sessionId));
        assertThat(samlAuthRequestUrl.toString()).startsWith(samlRedirectUrl);
    }

    private AuthorizationConfiguration getAuthConfig(String hostname) throws MalformedURLException {
        var config = new AuthorizationConfiguration();
        config.setAccessTokenLifetime(Duration.ofSeconds(60));
        config.setAuthorizationCodeLifetime(Duration.ofSeconds(60));
        config.setRequestUriLifetime(Duration.ofSeconds(60));
        config.setPopNonceLifetime(Duration.ofSeconds(60));
        config.setProofTimeTolerance(Duration.ofSeconds(60));
        config.setProofValidity(Duration.ofSeconds(60));
        config.setSessionExpirationTime(Duration.ofMinutes(60));
        config.setKeyStorageTypes(new String[]{"iso_18045_high", "iso_18045_moderate", "iso_18045_enhanced-basic"});
        config.setUserAuthenticationTypes(new String[]{"iso_18045_high", "iso_18045_moderate", "iso_18045_basic"});
        config.setAtSigAlias("pp_at_auth_local");
        config.setBaseUrl(URI.create(hostname).toURL());
        return config;
    }
}
