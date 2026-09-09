/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.in;

import de.bdr.pidp.issuer.authorization.core.exception.OAuthException;
import de.bdr.pidp.issuer.authorization.core.service.AuthChallengeService;
import lombok.RequiredArgsConstructor;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;

@Aspect
@Component
@RequiredArgsConstructor
public class ChallengeAspect {
    private static final String CHALLENGE_HEADER = "OAuth-Client-Attestation-Challenge";
    private final AuthChallengeService authChallengeService;

    @AfterThrowing(pointcut = "execution(* de.bdr.pidp.issuer.authorization.in.OAuthController.refreshToken(..))", throwing = "ex")
    public void refreshTokenException(Exception ex) {
        if (ex instanceof OAuthException ox) {
            var challenge = authChallengeService.provide();
            ox.addHeader(CHALLENGE_HEADER, challenge.nonce());
        }
    }
}
