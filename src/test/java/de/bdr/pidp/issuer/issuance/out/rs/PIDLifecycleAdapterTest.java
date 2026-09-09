/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.out.rs;

import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.base.PidpServiceUnavailableException;
import de.bdr.pidp.issuer.base.RevocationServiceConfiguration;
import de.bdr.pidp.issuer.base.jwt.StatusListRef;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.restclient.test.autoconfigure.RestClientTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import tools.jackson.databind.json.JsonMapper;

import java.net.URI;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.test.web.client.ExpectedCount.once;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withBadRequest;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * Tests for {@link PIDLifecycleAdapter} using {@code @RestClientTest} to verify the HTTP interaction.
 */
@RestClientTest(components = {PIDLifecycleAdapter.class, RevocationServiceConfiguration.class})
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PIDLifecycleAdapterTest {

    @Autowired
    private JsonMapper jsonMapper;

    @Autowired
    private RevocationServiceConfiguration config;

    @Autowired
    private PIDLifecycleAdapter pidLifecycleAdapter;

    @Autowired
    private MockRestServiceServer mockServer;

    private final String pidMasterTokenId = "master-token-id";
    private final Instant expiration = Instant.parse("2050-05-07T10:00:00Z");
    private final List<StatusListRef> statusLists = List.of(
            new StatusListRef(URI.create("https://example.com/statuslist1"), 47),
            new StatusListRef(URI.create("https://example.com/statuslist1"), 11)
    );

    private String lifecycleURL = "";

    @BeforeAll
    void setUp() {
        lifecycleURL = config.getBaseUrl() + "/pid-credential/lifecycle";
    }

    @Test
    void registerPIDs_successfulCall() {
        var batchCredentialInfoRef = new BatchCredentialInfoRef(pidMasterTokenId,
            statusLists.stream().map(s -> new CredentialInfoRef(expiration, new TokenStatusListRef(s.uri(), s.index()))).toList());
        String jsonContent = jsonMapper.writeValueAsString(batchCredentialInfoRef);

        mockServer.expect(once(), requestTo(lifecycleURL))
            .andExpect(method(HttpMethod.POST))
            .andExpect(header(PIDLifecycleClient.API_KEY_HEADER, config.getApiKey()))
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(content().string(jsonContent))
            .andRespond(withSuccess());

        pidLifecycleAdapter.registerPIDs(pidMasterTokenId, expiration, statusLists);
        mockServer.verify();
    }

    @Test
    void registerPIDs_httpClientError_throwsPidServerException() {
        mockServer.expect(once(), requestTo(lifecycleURL))
                .andRespond(withBadRequest());

        String message = assertThrows(PidServerException.class, () ->
            pidLifecycleAdapter.registerPIDs(pidMasterTokenId, expiration, statusLists)).getMessage();
        assertEquals("Revocation lifecycle request rejected", message);
    }

    @Test
    void registerPIDs_restClientException_throwsPidpServiceUnavailableException() {
        mockServer.expect(once(), requestTo(lifecycleURL))
                .andRespond(withServerError());

        String message = assertThrows(PidpServiceUnavailableException.class, () ->
            pidLifecycleAdapter.registerPIDs(pidMasterTokenId, expiration, statusLists)).getMessage();
        assertEquals("Revocation lifecycle request failed due to an unexpected error", message);
    }
}
