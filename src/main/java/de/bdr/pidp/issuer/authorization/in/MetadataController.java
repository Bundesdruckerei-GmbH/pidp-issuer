/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.in;

import de.bdr.pidp.issuer.authorization.config.ReadOnlyAuthMetadata;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController("authorizationMetadataController")
class MetadataController {

    private final String authorizationMetadata;

    MetadataController(ReadOnlyAuthMetadata metadata) {
        this.authorizationMetadata = metadata.toJSONObject().toJSONString();
    }

    @GetMapping(path = {"/.well-known/oauth-authorization-server"}, produces = "application/json")
    String getAuthorizationMetadata() {
        return authorizationMetadata;
    }
}
