/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service.domain;

import java.util.List;

public record CredentialResult(List<String> serializedCredentials) {
}
