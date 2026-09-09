/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.out.persistence;

import de.bdr.pidp.issuer.base.Nonce;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
public class CNonceAdapter {
    private final CNonceRepository cNonceRepository;

    @Transactional
    public void createAndSave(Nonce nonce) {
        CNonceEntity entity = new CNonceEntity();
        entity.setNonce(nonce.nonce());
        // Postgres timestamp contains only microseconds and no nanoseconds
        entity.setExpires(nonce.expirationTime().truncatedTo(ChronoUnit.MICROS));
        cNonceRepository.save(entity);
    }

    @Transactional
    public Optional<Nonce> findAndDeleteByNonce(Nonce nonce) {
        return cNonceRepository.findFirstByNonce(nonce.nonce())
                .map(e -> {
                    cNonceRepository.delete(e);
                    return e;
                })
                .map(this::map);
    }

    @Transactional
    public void cleanupExpiredNonces(Duration timeTolerance) {
        var expiryTime = Instant.now().minus(timeTolerance);
        var count = cNonceRepository.deleteAllByExpiresBefore(expiryTime);
        log.info("Deleted {} expired c_nonces", count);
    }

    private Nonce map(final CNonceEntity entity) {
        return new Nonce(entity.getNonce(), entity.getExpires());
    }
}
