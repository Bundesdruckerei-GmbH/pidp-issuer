/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service;

import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import de.bdr.pidp.issuer.issuance.config.model.CredentialIssuerMetadata;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.UnknownCredentialConfigurationException;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
public class CredentialConfigurationIDValidator {

    private final Set<CredentialConfigurationID> supported;

    public CredentialConfigurationIDValidator(CredentialIssuerMetadata metadata) {
        supported = metadata.credentialConfigurationsSupported().keySet();
    }

    public void validate(CredentialConfigurationID credentialConfigurationID) {
        if (!supported.contains(credentialConfigurationID)) {
            throw new UnknownCredentialConfigurationException(credentialConfigurationID.getName());
        }
    }
}
