/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.config;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class MdcKeys {
    public static final String MDC_AUTH_SESSION_ID = "authSessionId";
    public static final String MDC_CLIENT_ID = "clientId";
}
