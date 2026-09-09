/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
/**
 * This is the eid based identification module.
 * <p>
 * It uses the panstar sdk from governikus.
 */
@ApplicationModule(allowedDependencies = {
    "base",
    "base :: jwk",
    "base :: jwt",
    "base :: crypto",
    "base :: crypto-hsm",
})
package de.bdr.pidp.issuer.identification;

import org.springframework.modulith.ApplicationModule;
