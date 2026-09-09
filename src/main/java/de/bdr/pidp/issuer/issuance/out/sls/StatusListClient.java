/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.out.sls;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.service.annotation.HttpExchange;
import org.springframework.web.service.annotation.PostExchange;

@HttpExchange
interface StatusListClient {
    String API_KEY_HEADER = "x-api-key";

    @PostExchange("/pools/{poolId}/new-references")
    References createReferences(
        @RequestHeader(API_KEY_HEADER) String apiKey,
        @PathVariable String poolId,
        @RequestParam("amount") int amount
    );
}
