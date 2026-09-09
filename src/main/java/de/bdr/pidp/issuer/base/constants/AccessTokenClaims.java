/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.constants;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class AccessTokenClaims {
    public static final String SEED_CREDENTIAL_REFERENCE = "https://pid-provider.bundesdruckerei.de/seed_credential_ref";
    public static final String REFRESH_TOKEN_REFERENCE = "https://pid-provider.bundesdruckerei.de/refresh_token_ref";
    public static final String CLIENT_ID = "client_id";
    public static final String SCOPE = "scope";
}
