/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.domain;

/**
 * @param jwtID jti from Seed Credential
 * @param subject sub from Seed Credential
 */
public record SeedCredentialReference(String jwtID, String subject) {
}
