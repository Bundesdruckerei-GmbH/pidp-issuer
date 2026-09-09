/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle;

import de.bdr.pidp.issuer.authorization.core.exception.InvalidClientException;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidRequestException;
import de.bdr.pidp.issuer.clientconfiguration.ClientConfigurationService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class ClientIdValidatorTest {

    @Mock
    private ClientConfigurationService clientConfigurationService;

    @InjectMocks
    private ClientIdValidator validator;

    @Test
    void processValidation() {
        // given
        var clientId = UUID.randomUUID();

        // when
        doReturn(true).when(clientConfigurationService).isValidClientId(clientId);

        // then
        validator.validateClientId(clientId.toString());
        verify(clientConfigurationService).isValidClientId(clientId);
    }

    @Test
    void processComparation() {
        // given
        var clientIdString = UUID.randomUUID().toString();

        // when - then
        assertThatNoException().isThrownBy(() -> validator.validateClientId(clientIdString, clientIdString));
    }

    @Test
    void processInvalidClientId() {
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() -> validator.validateClientId("invalid-client-id"));
    }

    @Test
    void processUnknownClientId() {
        // given
        var clientId = UUID.randomUUID();
        var clientIdString = clientId.toString();

        // when
        doReturn(false).when(clientConfigurationService).isValidClientId(clientId);

        // then
        assertThatExceptionOfType(InvalidClientException.class).isThrownBy(() -> validator.validateClientId(clientIdString));
    }

    @Test
    void processDifferentClientIds() {
        // given
        var clientIdString1 = UUID.randomUUID().toString();
        var clientIdString2 = UUID.randomUUID().toString();

        // when - then
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() -> validator.validateClientId(clientIdString1, clientIdString2));
    }
}
