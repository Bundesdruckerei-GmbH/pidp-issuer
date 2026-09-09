/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.constants;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class RefreshTokenClaims {
    public static final String SEED_CREDENTIAL = "https://pid-provider.bundesdruckerei.de/seed_credential";
    public static final String CLIENT_ID = "client_id";
    public static final String SCOPE = "scope";
}
