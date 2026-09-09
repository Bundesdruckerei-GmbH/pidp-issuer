/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.in;

import de.bdr.pidp.issuer.authorization.core.domain.Requests;
import de.bdr.pidp.issuer.authorization.core.flows.ChallengeService;
import lombok.RequiredArgsConstructor;
import org.jmolecules.architecture.hexagonal.PrimaryAdapter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.JsonNode;

@PrimaryAdapter
@RestController
@RequiredArgsConstructor
@ConditionalOnProperty(value = "pidi.authorization.challenge-enabled", havingValue = "true")
public class ChallengeController {
    private final ChallengeService challengeService;

    @PostMapping(path = Requests.Paths.CHALLENGE, produces = "application/json")
    public ResponseEntity<JsonNode> challenge() {
        var challengeResult = challengeService.processChallengeRequest();

        return OAuthResponseFactory.createChallengeResponse(challengeResult);
    }
}

