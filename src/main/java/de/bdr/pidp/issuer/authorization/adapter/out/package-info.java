/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
@NullMarked
@ApplicationModule(allowedDependencies = {
    "authorization",
    "authorization :: domain",
    "authorization :: out",
    "identification :: in",
    "base",
    "base :: jwt",
    "base :: jwk",
    "base :: crypto",
    "base :: crypto-hsm",
})
package de.bdr.pidp.issuer.authorization.adapter.out;

import org.jspecify.annotations.NullMarked;
import org.springframework.modulith.ApplicationModule;
