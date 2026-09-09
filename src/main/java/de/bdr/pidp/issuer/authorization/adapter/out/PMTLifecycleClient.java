/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.adapter.out;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;
import org.springframework.web.service.annotation.PostExchange;

@HttpExchange
interface PMTLifecycleClient {
    String API_KEY_HEADER = "x-api-key";

    @PostExchange(value = "/pid-master-token/lifecycle", contentType = "application/json")
    void registerToken(
        @RequestHeader(API_KEY_HEADER) String apiKey,
        @RequestBody PIDMasterTokenRef pidMasterTokenRef
    );

    @GetExchange(value = "/pid-master-token/{tokenID}/lifecycle/status")
    ValidityStatus fetchValidityStatus(
        @RequestHeader(API_KEY_HEADER) String apiKey,
        @PathVariable String tokenID
    );
}
