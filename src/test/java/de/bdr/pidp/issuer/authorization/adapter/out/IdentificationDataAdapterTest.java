/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.adapter.out;

import de.bdr.pidp.issuer.authorization.core.domain.SeedCredential;
import de.bdr.pidp.issuer.authorization.port.out.IdentificationFailedException;
import de.bdr.pidp.issuer.authorization.port.out.InvalidSeedCredentialException;
import de.bdr.pidp.issuer.base.VerificationResult;
import de.bdr.pidp.issuer.identification.port.in.IdentificationDataPortIn;
import de.bdr.pidp.issuer.identification.port.in.ResourceDoesNotExistException;
import de.bdr.pidp.issuer.identification.port.in.SeedCredentialDTO;
import de.bdr.pidp.issuer.identification.port.in.SeedCredentialVerificationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class IdentificationDataAdapterTest {

    private static final Exception DUMMY_EXCEPTION = new Exception();

    @Mock
    private IdentificationDataPortIn identificationDataPortIn;

    @InjectMocks
    private IdentificationDataAdapter adapter;

    @Test
    void successStartIdentificationProcess() throws URISyntaxException, MalformedURLException {
        doReturn(new URI("http://localhost:8080").toURL()).when(identificationDataPortIn).startIdentificationProcess(any(), any(), any());
        var result = adapter.startIdentificationProcess(new URI("http://localhost:8080").toURL(), "issuerState", "sessionId");

        assertThat(result).isNotNull();
        verify(identificationDataPortIn).startIdentificationProcess(any(), any(), any());
    }

    @Test
    void successCheckIdentification() {
        doReturn(VerificationResult.success()).when(identificationDataPortIn).checkIdentification(anyString());
        var result = adapter.checkIdentification("externalId");

        assertThat(result).isNotNull().isInstanceOf(VerificationResult.class);
        assertThat(result.status()).isEqualTo(VerificationResult.VerificationStatus.SUCCESS);
        verify(identificationDataPortIn).checkIdentification(anyString());
    }

    @Test
    void successCollectEncryptedIdentification() {
        SeedCredentialDTO seedCredentialDTO = new SeedCredentialDTO("seedCredential", "reference", "sub", Instant.now());
            doReturn(seedCredentialDTO).when(identificationDataPortIn).collectEncryptedIdentification(anyString());
        var result = adapter.collectEncryptedIdentification("externalId");

        assertThat(result).isNotNull()
            .isInstanceOfSatisfying(SeedCredential.class, seedCredential -> {
                assertThat(seedCredential.value()).isEqualTo(seedCredentialDTO.seedCredential());
                assertThat(seedCredential.subject()).isEqualTo(seedCredentialDTO.sub());
                assertThat(seedCredential.reference()).isEqualTo(seedCredentialDTO.jti());
                assertThat(seedCredential.exp()).isEqualTo(seedCredentialDTO.exp());
            });
        verify(identificationDataPortIn).collectEncryptedIdentification(anyString());
    }

    @Test
    void successVerifySeedCredential() {
        SeedCredentialDTO seedCredentialDTO = new SeedCredentialDTO("seedCredential", "reference", "sub", Instant.now());
        doReturn(seedCredentialDTO).when(identificationDataPortIn).verifySeedCredential(anyString());
        var result = adapter.verifySeedCredential("seedCredential");

        assertThat(result).isNotNull()
            .isInstanceOfSatisfying(SeedCredential.class, seedCredential -> {
                assertThat(seedCredential.value()).isEqualTo(seedCredentialDTO.seedCredential());
                assertThat(seedCredential.subject()).isEqualTo(seedCredentialDTO.sub());
                assertThat(seedCredential.reference()).isEqualTo(seedCredentialDTO.jti());
                assertThat(seedCredential.exp()).isEqualTo(seedCredentialDTO.exp());
            });
        verify(identificationDataPortIn).verifySeedCredential(anyString());
    }

    @Test
    void failedVerifySeedCredential() {
        doThrow(new SeedCredentialVerificationException("Verification failed")).when(identificationDataPortIn).verifySeedCredential(anyString());
        assertThatThrownBy(() ->  adapter.verifySeedCredential("seedCredential"))
            .isInstanceOf(InvalidSeedCredentialException.class).hasMessage("Verification failed");

        verify(identificationDataPortIn).verifySeedCredential(anyString());
    }

    @Test
    void failedCheckIdentification() {
        doThrow(new ResourceDoesNotExistException("Could not find eID result", DUMMY_EXCEPTION)).when(identificationDataPortIn).checkIdentification(anyString());
        assertThatThrownBy(() ->  adapter.checkIdentification("externalId"))
            .isInstanceOf(IdentificationFailedException.class).hasMessage("No identification result received yet");

        verify(identificationDataPortIn).checkIdentification(anyString());
    }

    @Test
    void failedCollectEncryptedIdentification() {
        doThrow(new ResourceDoesNotExistException("Could not collect eID data", DUMMY_EXCEPTION)).when(identificationDataPortIn).collectEncryptedIdentification(anyString());
        assertThatThrownBy(() ->  adapter.collectEncryptedIdentification("externalId"))
            .isInstanceOf(IdentificationFailedException.class).hasMessage("Could not collect eID data");

        verify(identificationDataPortIn).collectEncryptedIdentification(anyString());
    }
}
