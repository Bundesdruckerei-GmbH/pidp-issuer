/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.flows;

import de.bdr.pidp.issuer.authorization.core.domain.data.AuthSession;
import de.bdr.pidp.issuer.authorization.port.out.SeedCredentialDataPortOut;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class EidDataServiceTest {

    @Mock
    private SeedCredentialDataPortOut seedCredentialDataPortOut;

    @InjectMocks
    private SeedCredentialDataService service;

    @Test
    void processRequest() {
        var token = "access-token";
        var seedCredential = "seedCredential";

        // given - mock session
        var mockSession = Mockito.mock(AuthSession.class);
        doReturn(mockSession).when(seedCredentialDataPortOut).loadBySeedCredentialRef(token);
        doReturn(seedCredential).when(mockSession).getSeedCredentialData();

        // when
        var result = service.retrieveSeedCredentialData(token);

        // then
        verify(seedCredentialDataPortOut).loadBySeedCredentialRef(token);
        assertThat(result).isNotNull();
    }
}
