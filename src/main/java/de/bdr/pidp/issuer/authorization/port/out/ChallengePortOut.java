/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.port.out;

import de.bdr.pidp.issuer.base.Nonce;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

public interface ChallengePortOut {
    @Transactional
    void createAndSave(Nonce nonce);

    @Transactional
    Optional<Nonce> findAndDeleteByChallenge(String value);
}
