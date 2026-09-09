/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.out.random;

import de.bdr.pidp.issuer.identification.core.RandomProvider;
import lombok.extern.slf4j.Slf4j;
import org.jmolecules.architecture.hexagonal.SecondaryAdapter;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.Random;

@Slf4j
@Component
@SecondaryAdapter
public class RandomProviderSoftwareImpl implements RandomProvider {

    private final SecureRandom instanceStrong = new SecureRandom();
    private final Random sessionRng = initRng();
    private final Random samlRng = initRng();

    private Random initRng() {
        log.debug("~~~~ consuming entropy for RNG");
        int rand = instanceStrong.nextInt();
        if (log.isTraceEnabled()) {
            log.trace("~~~~ created RNG, first random int: {}, algo: {}, provider: {}", rand, instanceStrong.getAlgorithm(), instanceStrong.getProvider());
        }
        return instanceStrong;
    }

    @Override
    public Random getSessionRng() {
        return sessionRng;
    }

    @Override
    public Random getSamlRng() {
        return samlRng;
    }
}
