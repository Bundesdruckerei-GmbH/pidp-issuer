/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.out.rs;

import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.service.annotation.HttpExchange;
import org.springframework.web.service.annotation.PostExchange;

@HttpExchange
interface PIDLifecycleClient {
    String API_KEY_HEADER = "x-api-key";

    @PostExchange(value = "/pid-credential/lifecycle", contentType = "application/json")
    void registerCredential(
        @RequestHeader(API_KEY_HEADER) String apiKey,
        @RequestBody BatchCredentialInfoRef batchCredentialInfoRef
    );
}
