/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.core;

import de.bdr.pidp.issuer.identification.config.IdentificationConfiguration;
import de.bdr.pidp.issuer.identification.core.configuration.MultiSamlConfiguration;
import de.bdr.pidp.issuer.identification.core.exception.CryptoConfigException;
import de.governikus.panstar.sdk.saml.configuration.SamlConfiguration;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
class EidAuthAdapterTest {

    @Mock
    private MultiSamlConfiguration msConf1;
    @Mock
    private MultiSamlConfiguration msConf2;
    @Mock
    private MeterRegistry micrometer;
    @Spy
    private IdentificationConfiguration identificationConfiguration;

    private EidAuthAdapter out;

    @BeforeEach
    void setup() {
        out = new EidAuthAdapter(msConf1, msConf2, micrometer);
    }

    @Test
    void test_createSamlRedirectBinding_badConfig() {
        var sessionId = "session";
        var responseUrl = "https://return.localhost/saml";
        Mockito.when(msConf1.getResponseUrl()).thenReturn(responseUrl);
        SamlConfiguration configurationMock = Mockito.mock(SamlConfiguration.class);
        Mockito.when(msConf1.getConfigurations()).thenReturn(List.of(configurationMock));

        assertThrows(CryptoConfigException.class, () -> out.createSamlRedirectBindingUrl(sessionId, responseUrl));

    }
}
