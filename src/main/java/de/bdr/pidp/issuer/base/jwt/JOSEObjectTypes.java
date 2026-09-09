/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.jwt;

import com.nimbusds.jose.JOSEObjectType;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class JOSEObjectTypes {
    public static final JOSEObjectType ACCESS_TOKEN = new JOSEObjectType("at+jwt");
    public static final JOSEObjectType REFRESH_TOKEN = new JOSEObjectType("rt+jwt");
}
