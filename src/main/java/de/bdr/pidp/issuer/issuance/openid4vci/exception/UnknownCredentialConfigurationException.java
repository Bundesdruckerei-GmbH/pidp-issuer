/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.exception;

import lombok.Getter;

public class UnknownCredentialConfigurationException extends OIDException {
    private static final String MESSAGE_BODY = "credential_configuration_id \"%s\" not supported";

    @Getter
    private final String credentialConfigurationId;

    public UnknownCredentialConfigurationException(String credentialConfigurationId) {
        super("unknown_credential_configuration", null, String.format(MESSAGE_BODY, credentialConfigurationId));
        this.credentialConfigurationId = credentialConfigurationId;
    }
}
