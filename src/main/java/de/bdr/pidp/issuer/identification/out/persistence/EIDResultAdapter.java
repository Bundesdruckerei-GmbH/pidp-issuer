/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.out.persistence;

import de.bdr.pidp.issuer.base.VerificationResult;
import de.bdr.pidp.issuer.identification.config.IdentificationConfiguration;
import de.bdr.pidp.issuer.identification.core.model.SeedCredentialData;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.NoSuchElementException;

@Component
@NullMarked
public class EIDResultAdapter {

    private final EIDResultRepository repository;
    private final Duration sessionLifetime;

    public EIDResultAdapter(EIDResultRepository repository, IdentificationConfiguration configuration) {
        this.repository = repository;
        sessionLifetime = configuration.getMaxIdentificationSessionDuration();
    }

    /**
     * @throws IllegalStateException a result already exists for externalId
     */
    @Transactional
    public void storeIdentification(String externalId, SeedCredentialData seedCredentialData) {
        if (repository.existsById(externalId)) {
            throw new IllegalStateException("Already received a result");
        }

        var entity = new EIDResultEntity();
        entity.setExternalId(externalId);
        entity.setExpires(getSessionExpirationTime());
        entity.setSeedCredential(seedCredentialData.seedCredential());
        entity.setJti(seedCredentialData.jti());
        entity.setSub(seedCredentialData.sub());
        entity.setExp(seedCredentialData.exp());

        repository.save(entity);
    }

    /**
     * @throws IllegalStateException a result already exists for externalId
     */
    @Transactional
    public void storeIdentificationError(String externalId, String error) {
        if (repository.existsById(externalId)) {
            throw new IllegalStateException("Already received a result");
        }

        var entity = new EIDResultEntity();
        entity.setExternalId(externalId);
        entity.setError(error);
        entity.setExpires(getSessionExpirationTime());

        repository.save(entity);
    }

    /**
     * @throws NoSuchElementException no entry found
     */
    public VerificationResult checkIdentification(String externalId) {
        var entity = repository.findById(externalId).orElseThrow();
        if (entity.getError() != null) {
            return VerificationResult.error(entity.getError());
        }
        return VerificationResult.success();
    }

    /**
     * @throws NoSuchElementException no entry found
     */
    @Transactional
    public SeedCredentialData getAndDeleteIdentification(String externalId) {
        var entity = repository.findById(externalId).orElseThrow();
        repository.deleteById(externalId);
        var seedCredential = entity.getSeedCredential();
        var jti = entity.getJti();
        var sub = entity.getSub();
        var exp = entity.getExp();
        if (seedCredential == null || jti == null || sub == null || exp == null) {
            throw new NoSuchElementException("No eID data present");
        }
        return new SeedCredentialData(seedCredential, null, jti, sub, exp);
    }

    @Transactional
    public int deleteExpired() {
        return repository.deleteAllByExpiresBefore(Instant.now());
    }

    private Instant getSessionExpirationTime() {
        return Instant.now().plus(sessionLifetime).truncatedTo(ChronoUnit.MICROS);
    }
}
