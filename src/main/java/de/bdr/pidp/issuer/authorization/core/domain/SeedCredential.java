/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.domain;

import java.time.Instant;

/**
 * @param value the Seed Credential JWE
 * @param reference unique identifier and reference form Seed Credential
 * @param subject sub from Seed Credential
 * @param exp expiration time of the Seed Credential
 */
public record SeedCredential(String value, String reference, String subject, Instant exp) {
}
