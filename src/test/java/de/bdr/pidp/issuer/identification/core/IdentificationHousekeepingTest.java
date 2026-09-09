/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.core;

import de.bdr.pidp.issuer.identification.core.model.AuthenticationState;
import de.bdr.pidp.issuer.identification.out.persistence.EIDResultAdapter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;

@ExtendWith(MockitoExtension.class)
class IdentificationHousekeepingTest {

    @Mock
    AuthenticationStore authenticationStore;
    @Mock
    EIDResultAdapter eidResultAdapter;
    @InjectMocks
    IdentificationHousekeeping identificationHousekeeping;

    @Test
    void test001() {
        doReturn(12).when(authenticationStore).updateStateByValidUntilBeforeAndAuthenticationStateNotIn(eq(AuthenticationState.TIMEOUT), any(), anyList());
        doReturn(15).when(authenticationStore).deleteByAuthenticationStateIn(List.of(AuthenticationState.TERMINATED, AuthenticationState.TIMEOUT));
        doReturn(17).when(eidResultAdapter).deleteExpired();
        assertThatNoException().isThrownBy(() -> identificationHousekeeping.cleanupExpiredAuthentications());
    }
}
