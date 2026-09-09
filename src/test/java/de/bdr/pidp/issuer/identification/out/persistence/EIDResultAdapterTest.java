/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.out.persistence;

import de.bdr.pidp.issuer.base.VerificationResult;
import de.bdr.pidp.issuer.end2end.integration.IntegrationTest;
import de.bdr.pidp.issuer.identification.core.model.SeedCredentialData;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.NoSuchElementException;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class EIDResultAdapterTest extends IntegrationTest {

    public static final String ERROR_MSG = "eine message sie zu testen, sie alle zu finden";
    public static final String SEED_CREDENTIAL = "ins seed credential zu treiben und ewig zu binden";
    private static final SeedCredentialData SEED_CREDENTIAL_DATA = new SeedCredentialData(SEED_CREDENTIAL, null, UUID.randomUUID().toString(), "Subject", Instant.now().plusSeconds(600).truncatedTo(ChronoUnit.MICROS));

    @Autowired
    private EIDResultRepository repository;
    @Autowired
    private EIDResultAdapter subject;

    @Test
    void storeSuccessfulIdentification() {
        var externalId = TestUtils.generateIssuerState();

        subject.storeIdentification(externalId, SEED_CREDENTIAL_DATA);

        var assertOnEntity = assertThat(repository.findById(externalId)).get();
        assertOnEntity.extracting(EIDResultEntity::getError).isNull();
        assertOnEntity.extracting(EIDResultEntity::getSeedCredential).isNotNull();
    }

    @Test
    void storeErrorIdentification() {
        var externalId = TestUtils.generateIssuerState();

        subject.storeIdentificationError(externalId, ERROR_MSG);

        var assertOnEntity = assertThat(repository.findById(externalId)).get();
        assertOnEntity.extracting(EIDResultEntity::getError).isEqualTo(ERROR_MSG);
        assertOnEntity.extracting(EIDResultEntity::getSeedCredential).isNull();
    }

    @Test
    void identificationAlreadyExists() {
        var externalId = storeIdentification();

        assertThatThrownBy(() -> subject.storeIdentification(externalId, SEED_CREDENTIAL_DATA))
            .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> subject.storeIdentificationError(externalId, ERROR_MSG))
            .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void checkIdentificationSuccess() {
        var externalId = storeIdentification();

        var result = subject.checkIdentification(externalId);

        assertThat(result.status()).isEqualTo(VerificationResult.VerificationStatus.SUCCESS);
    }

    @Test
    void checkIdentificationFailure() {
        var externalId = storeIdentificationError();

        var result = subject.checkIdentification(externalId);

        assertThat(result.status()).isEqualTo(VerificationResult.VerificationStatus.ERROR);
        assertThat(result.error()).isEqualTo(ERROR_MSG);
    }

    @Test
    void checkIdentificationNotFound() {
        var externalId = TestUtils.generateIssuerState();

        assertThatThrownBy(() -> subject.checkIdentification(externalId))
            .isInstanceOf(NoSuchElementException.class);
    }

    @Test
    void getAndDeleteIdentification() {
        var externalId = storeIdentification();

        var data = subject.getAndDeleteIdentification(externalId);

        assertThat(data).isEqualTo(SEED_CREDENTIAL_DATA);
        assertThat(repository.existsById(externalId)).isFalse();
    }

    @Test
    void getAndDeleteIdentificationOnFailure() {
        var externalId = storeIdentificationError();

        assertThatThrownBy(() -> subject.getAndDeleteIdentification(externalId))
            .isInstanceOf(NoSuchElementException.class);
    }

    @Test
    void getAndDeleteIdentificationNotFound() {
        var externalId = TestUtils.generateIssuerState();
        assertThatThrownBy(() -> subject.getAndDeleteIdentification(externalId))
            .isInstanceOf(NoSuchElementException.class);
    }

    private String storeIdentification() {
        var externalId = TestUtils.generateIssuerState();
        subject.storeIdentification(externalId, SEED_CREDENTIAL_DATA);
        return externalId;
    }

    private String storeIdentificationError() {
        var externalId = TestUtils.generateIssuerState();
        subject.storeIdentificationError(externalId, ERROR_MSG);
        return externalId;
    }

}
