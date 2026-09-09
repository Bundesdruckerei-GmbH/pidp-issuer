/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.flows;

import de.bdr.pidp.issuer.authorization.core.domain.ChallengeResult;
import de.bdr.pidp.issuer.authorization.core.service.AuthChallengeService;
import org.springframework.stereotype.Service;

@Service
public class ChallengeService {

    private final AuthChallengeService authChallengeService;

    public ChallengeService(AuthChallengeService authChallengeService) {
        this.authChallengeService = authChallengeService;
    }

    public ChallengeResult processChallengeRequest() {
        var challenge = authChallengeService.provide();

        return new ChallengeResult(challenge.nonce());
    }
}
