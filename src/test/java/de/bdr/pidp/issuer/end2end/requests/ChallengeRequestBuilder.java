/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.end2end.requests;

import org.springframework.http.HttpMethod;

public class ChallengeRequestBuilder extends RequestBuilder<ChallengeRequestBuilder> {
    public ChallengeRequestBuilder() {
        super(HttpMethod.POST);
    }

    public static ChallengeRequestBuilder valid() {
        var path = getChallengePath();
        return new ChallengeRequestBuilder()
            .withUrl(path);
    }

    public static String getChallengePath() {
        return "/challenge";
    }
}
