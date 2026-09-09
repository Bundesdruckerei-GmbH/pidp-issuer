/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle;

import de.bdr.pidp.issuer.authorization.core.exception.InvalidScopeException;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;

@Component
public class ScopeValidator {
    private final Collection<String> validScopes = List.of("pid");

    public void validateScope(final String scope) {
        if (!validScopes.contains(scope)) {
            throw new InvalidScopeException("Unknown scope");
        }
    }
}
