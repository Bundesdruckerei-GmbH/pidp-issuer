/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle;

import de.bdr.pidp.issuer.authorization.core.particle.clientattestation.ClientAttestationVerifier;
import de.bdr.pidp.issuer.clientconfiguration.ClientConfigurationService;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;


@ExtendWith(MockitoExtension.class)
class ClientAttestationValidatorTest {

    @Mock
    private ClientAttestationVerifier clientAttestationVerifier;

    @Mock
    private ClientConfigurationService clientConfigurationService;

    @InjectMocks
    private ClientAttestationValidator validator;

    @DisplayName("Verify Client Attestation valid")
    @Test
    void test001() {
        doReturn(TestUtils.CLIENT_ATTESTATION_TRUST_ANCHOR_SELF_SIGNED).when(clientConfigurationService).getClientAttestationCerts(any());
        doReturn(new ClientAttestationVerifier.AttestationValues(TestUtils.DEVICE_PUBLIC_KEY, TestUtils.CLIENT_ATTESTATION_STATUS_LIST_REF)).when(clientAttestationVerifier).verify(any(), any(), any(), any());

        assertThatNoException().isThrownBy(() -> validator.validateClientAttestation(
            TestUtils.getValidClientAttestationJwt(), TestUtils.getValidClientAttestationPopJwt(), UUID.randomUUID().toString()));
    }
}
