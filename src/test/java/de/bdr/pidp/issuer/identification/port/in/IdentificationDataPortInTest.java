/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.port.in;

import de.bdr.pidp.issuer.base.VerificationResult;
import de.bdr.pidp.issuer.end2end.integration.IntegrationTest;
import de.bdr.pidp.issuer.identification.core.seedcredential.SeedCredentialService;
import de.bdr.pidp.issuer.identification.out.persistence.EIDResultAdapter;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;

import static de.bdr.pidp.issuer.testdata.PidTestData.TEST_IDENTITY_DATA;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

//@SpringBootTest(properties = {"pidi.identification.create-seed-credential=true","hsm.enabled=false"})
@ComponentScan("de.bdr.pidp.issuer.identification")
class IdentificationDataPortInTest extends IntegrationTest {

    public static final String ERROR_MSG = "eine message sie zu testen";

    @Autowired
    private IdentificationDataPortIn subject;

    @Autowired
    private EIDResultAdapter adapter;

    @Autowired
    private SeedCredentialService seedCredentialService;

    @Test
    void identificationSuccess() {
        var externalId = TestUtils.generateIssuerState();
        var seedCredentialData = seedCredentialService.createSeedCredential(TEST_IDENTITY_DATA);
        adapter.storeIdentification(externalId, seedCredentialData);

        var result = subject.checkIdentification(externalId);

        assertThat(result.status()).isEqualTo(VerificationResult.VerificationStatus.SUCCESS);
        assertThat(subject.collectEncryptedIdentification(externalId)).isNotNull()
            .extracting("seedCredential").isEqualTo(seedCredentialData.seedCredential());
    }

    @Test
    void identificationFailure() {
        var externalId = TestUtils.generateIssuerState();
        adapter.storeIdentificationError(externalId, ERROR_MSG);

        var result = subject.checkIdentification(externalId);

        assertThat(result.status()).isEqualTo(VerificationResult.VerificationStatus.ERROR);
        assertThat(result.error()).isEqualTo(ERROR_MSG);
    }

    @Test
    void checkIdentificationNotFound() {
        var externalId = TestUtils.generateIssuerState();

        assertThatThrownBy(() -> subject.checkIdentification(externalId))
            .isInstanceOf(ResourceDoesNotExistException.class);
    }

    @Test
    void collectIdentificationNotFound() {
        var externalId = TestUtils.generateIssuerState();

        assertThatThrownBy(() -> subject.collectEncryptedIdentification(externalId))
            .isInstanceOf(ResourceDoesNotExistException.class);
    }
}
