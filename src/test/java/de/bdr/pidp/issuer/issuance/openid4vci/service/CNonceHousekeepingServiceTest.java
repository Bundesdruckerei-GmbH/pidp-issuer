/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service;

import de.bdr.pidp.issuer.issuance.config.IssuanceConfiguration;
import de.bdr.pidp.issuer.issuance.openid4vci.out.persistence.CNonceAdapter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import static de.bdr.pidp.issuer.issuance.ConfigTestData.ISSUANCE_CONFIG;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class CNonceHousekeepingServiceTest {

    @Mock
    private CNonceAdapter cNonceAdapter;

    @Spy
    private IssuanceConfiguration issuanceConfiguration = ISSUANCE_CONFIG;

    @InjectMocks
    private CNonceHousekeepingService subject;

    @Test
    void cleanupExpired() {
        subject.cleanupExpiredNonces();

        verify(cNonceAdapter).cleanupExpiredNonces(ISSUANCE_CONFIG.getProofTimeTolerance());
    }
}
