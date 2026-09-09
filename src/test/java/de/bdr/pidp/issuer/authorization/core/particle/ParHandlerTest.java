/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle;

import de.bdr.pidp.issuer.authorization.config.MetaTestData;
import de.bdr.pidp.issuer.authorization.core.domain.ParResult;
import de.bdr.pidp.issuer.authorization.core.domain.data.AuthSession;
import de.bdr.pidp.issuer.authorization.core.exception.UnsupportedResponseTypeException;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static de.bdr.pidp.issuer.authorization.ConfigTestData.AUTH_CONFIG;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class ParHandlerTest {
    private final ParHandler parHandler = new ParHandler(MetaTestData.AUTH_METADATA, AUTH_CONFIG);

    @DisplayName("Verify exception when invalid response_type parameter")
    @Test
    void test001() {
        var params = RequestUtil.getValidParRequestParams();
        params.put("response_type", "invalid");
        var request = RequestUtil.getParRequest(params);
        var session = new AuthSession(TestUtils.randomSessionId());

        assertThatThrownBy(() -> parHandler.processPushedAuthRequest(request, session))
            .isInstanceOf(UnsupportedResponseTypeException.class)
            .hasFieldOrPropertyWithValue("errorCode", "unsupported_response_type");
    }

    @DisplayName("Verify store data in session when valid response_type parameter")
    @Test
    void test002() {
        var request = RequestUtil.getParRequest();
        var session = mock(AuthSession.class);

        ParResult parResult = parHandler.processPushedAuthRequest(request, session);

        verify(session).addGeneratedParProperties(anyString(), any(Instant.class));

        assertThat(parResult.requestUri()).startsWith("urn:ietf:params:oauth:request_uri:").hasSize(78);
        assertThat(parResult.requestUriLifetime()).isEqualTo(Duration.ofSeconds(60));
    }
}
