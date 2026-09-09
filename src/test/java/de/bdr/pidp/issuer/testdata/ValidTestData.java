/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.testdata;

import de.bdr.pidp.issuer.base.BirthDate;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class ValidTestData {
    public static final String REDIRECT_URI = "https://redirect.localhost";
    public static final String CODE_CHALLENGE = "VPvsxc7h-NOKbZX9pKqzgLdc3-3VL_U8B4cKRt6r2xE";
    public static final String CODE_VERIFIER = "ABCDEFGHIJklmnopqrstUVWXYZ-._~0123456789-50Zeichen";

    public static final String BIRTH_DATE = "2000-01-01";
    public static final BirthDate LOCAL_BIRTH_DATE = new BirthDate(BIRTH_DATE);
}
