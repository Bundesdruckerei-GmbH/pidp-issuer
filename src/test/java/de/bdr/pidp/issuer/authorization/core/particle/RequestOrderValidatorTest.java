/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle;

import de.bdr.pidp.issuer.authorization.core.domain.Requests;
import de.bdr.pidp.issuer.authorization.core.domain.data.AuthSession;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidRequestException;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


class RequestOrderValidatorTest {
    @Test
    void successValidation() {
        AuthSession session = new AuthSession(TestUtils.randomSessionId());
        session.setNextExpectedRequest(Requests.PUSHED_AUTHORIZATION_REQUEST);

        assertThatCode(() -> RequestOrderValidator.validateRequest(session, Requests.PUSHED_AUTHORIZATION_REQUEST))
            .doesNotThrowAnyException();
    }

    @Test
    void errorValidation() {
        AuthSession session = new AuthSession(TestUtils.randomSessionId());
        session.setNextExpectedRequest(Requests.FINISH_AUTHORIZATION_REQUEST);

        assertThatThrownBy(() -> RequestOrderValidator.validateRequest(session, Requests.TOKEN_REQUEST))
            .isInstanceOf(InvalidRequestException.class)
            .hasMessage(Requests.TOKEN_REQUEST.name()+ " is not the allowed next request");
    }
}
