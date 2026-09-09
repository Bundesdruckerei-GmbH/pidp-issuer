/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
/**
 * The Authorization Server part of the pid-issuer
 */
@ApplicationModule(allowedDependencies = {
    "authorization",
    "clientconfiguration",
    "base",
    "base :: jwk",
    "base :: jwt",
    "base :: exceptions",
    "base :: requests"
    })
package de.bdr.pidp.issuer.authorization;

import org.springframework.modulith.ApplicationModule;
