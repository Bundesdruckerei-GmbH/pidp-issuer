/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.domain;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public enum Requests {
    PUSHED_AUTHORIZATION_REQUEST(Paths.PAR),
    AUTHORIZATION_REQUEST(Paths.AUTHORIZE),
    FINISH_AUTHORIZATION_REQUEST(Paths.FINISH_AUTHORIZATION),
    TOKEN_REQUEST(Paths.TOKEN),
    CREDENTIAL_REQUEST(Paths.CREDENTIAL);

    private final String path;

    @NoArgsConstructor(access = AccessLevel.PRIVATE)
    public static class Paths {
        public static final String CHALLENGE = "challenge";
        public static final String PAR = "par";
        public static final String AUTHORIZE = "authorize";
        public static final String FINISH_AUTHORIZATION = "finish-authorization";
        public static final String TOKEN = "token";
        public static final String CREDENTIAL = "credential";
    }
}
