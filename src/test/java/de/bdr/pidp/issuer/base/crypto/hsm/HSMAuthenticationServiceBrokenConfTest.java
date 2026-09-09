/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.crypto.hsm;

import de.bdr.pidp.issuer.base.PidServerException;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class HSMAuthenticationServiceBrokenConfTest {

    @Test
    void getKeyAttributes() {
        HSMConfiguration.HSMGroupConfiguration config =
            new HSMConfiguration.HSMGroupConfiguration("nirvana", Duration.ofMillis(10), Duration.ofMillis(20), new HSMConfiguration.CryptoUser("name", "pw", "group"));

        assertThatExceptionOfType(PidServerException.class).isThrownBy(() -> new HSMAuthenticationService(config));
    }
}
