/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.core;

import de.bdr.pidp.issuer.base.PidServerException;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.springframework.context.annotation.Configuration;

@Slf4j
@Configuration
public class OpenSAMLInitializer {

    public OpenSAMLInitializer() {
        log.debug("Calling InitializationService.initialize");
        try {
            InitializationService.initialize();
            log.debug("Done with InitializationService.initialize");
        } catch (InitializationException e) {
            log.error("OpenSAML initialization failed.", e);
            throw new PidServerException("OpenSAML initialization failed.", e);
        }
    }
}
