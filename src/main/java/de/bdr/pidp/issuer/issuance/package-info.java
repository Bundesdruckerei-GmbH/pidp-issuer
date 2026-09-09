/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
/**
 * Issuance is the part of the pid-issuer that builds the credentials.
 */
@org.springframework.modulith.ApplicationModule(
        allowedDependencies = {
            "authorization",
            "authorization::in",
            "base",
            "base :: jwk",
            "base :: jwt",
            "base :: requests",
            "base :: crypto",
            "base :: crypto-hsm",
            "clientconfiguration",
            "identification :: in",
            "identification :: out",
            "base :: crypto"
        }
)
package de.bdr.pidp.issuer.issuance;
