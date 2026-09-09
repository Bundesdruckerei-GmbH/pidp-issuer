/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.flows;

import de.bdr.pidp.issuer.authorization.core.domain.data.AuthSession;
import de.bdr.pidp.issuer.authorization.core.service.DPoPNonceService;
import de.bdr.pidp.issuer.authorization.port.out.TokenIntrospectDataPortOut;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class TokenIntrospectServiceTest {

    private final String accessTokenID = "Mein Schatz";

    @Mock
    private TokenIntrospectDataPortOut tokenIntrospectDataPortOut;

    @Mock
    private DPoPNonceService dPoPNonceService;

    @InjectMocks
    private TokenIntrospectService service;

    @Test
    void successGetDPoPNonce() {
        // given - mock session
        var mockSession = Mockito.mock(AuthSession.class);
        doReturn(mockSession).when(tokenIntrospectDataPortOut).loadByAccessTokenID(accessTokenID);

        // when
        service.getDPoPNonce(accessTokenID);

        // then
        verify(tokenIntrospectDataPortOut).loadByAccessTokenID(accessTokenID);
        verify(dPoPNonceService).fetchFromAuthSession(mockSession);
    }

    @Test
    void successProvideAndStore() {
        // given - mock session
        var mockSession = Mockito.mock(AuthSession.class);
        doReturn(mockSession).when(tokenIntrospectDataPortOut).loadByAccessTokenID(accessTokenID);

        // when
        service.provideAndStore(accessTokenID);

        // then
        verify(tokenIntrospectDataPortOut).loadByAccessTokenID(accessTokenID);
        verify(dPoPNonceService).provideAndSave(mockSession);
    }
}
