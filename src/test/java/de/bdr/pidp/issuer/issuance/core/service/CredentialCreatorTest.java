/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.core.service;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDate;
import java.time.Month;
import java.util.stream.Stream;

import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialCreatorTest {

    @Spy
    private CredentialCreator credentialCreator;

    @Mock
    private PIDIdentityData pidIdentityData;

    @ParameterizedTest
    @MethodSource("validValues")
    void create(String dataExpirationDate, LocalDate maxExpirationDate, LocalDate expected) {
        when(pidIdentityData.dateOfExpiry()).thenReturn(dataExpirationDate);
        Assertions.assertThat(credentialCreator.getExpirationDate(pidIdentityData, maxExpirationDate)).isEqualTo(expected);
    }

    static Stream<Arguments> validValues() {
        return Stream.of(
            arguments("2030-01-01", LocalDate.of(2040, Month.JANUARY, 1), LocalDate.of(2030, Month.JANUARY, 1)),
            arguments("2040-01-01", LocalDate.of(2030, Month.JANUARY, 1), LocalDate.of(2030, Month.JANUARY, 1))
        );
    }
}
