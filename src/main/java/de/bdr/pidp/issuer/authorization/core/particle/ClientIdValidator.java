/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle;

import de.bdr.pidp.issuer.authorization.core.exception.InvalidClientException;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidRequestException;
import de.bdr.pidp.issuer.clientconfiguration.ClientConfigurationService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@RequiredArgsConstructor
public class ClientIdValidator {
    private final ClientConfigurationService clientConfigurationService;

    public void validateClientId(final String clientIdString) {
        final UUID clientId;
        try {
            clientId = UUID.fromString(clientIdString);
        } catch (IllegalArgumentException e) {
            throw new InvalidRequestException("Invalid client id", "client id must be a valid UUID", e);
        }
        if (!clientConfigurationService.isValidClientId(clientId)) {
            throw new InvalidClientException("Client Id is not registered");
        }
    }

    public void validateClientId(final String clientIdFromRequest, final String clientIdFromSession) {
        if (!clientIdFromRequest.equals(clientIdFromSession)) {
            throw new InvalidRequestException("client_id parameter from par request doesn't match client_id");
        }
    }
}
