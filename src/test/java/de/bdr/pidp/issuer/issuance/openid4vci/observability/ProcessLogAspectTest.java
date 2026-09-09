/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.observability;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Isolated;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(OutputCaptureExtension.class)
@Isolated
class ProcessLogAspectTest {

    private final ProcessLogAspect aspect = new ProcessLogAspect();
    private final JsonMapper jsonMapper = new JsonMapper();

    @Test
    void processLogIncoming(CapturedOutput output) {
        var request = new MockHttpServletRequest("POST", "/test");
        request.addHeader("EinTest", "am-Morgen");
        request.addParameter("vertreibt", "Fehler-und-Sorgen");
        var requestAttributes = new ServletRequestAttributes(request);
        RequestContextHolder.setRequestAttributes(requestAttributes);

        aspect.logProcessIncoming();

        assertThat(output).containsOnlyOnce("""
            Incoming request POST /test with headers: {"EinTest":["am-Morgen"]}, params: {"vertreibt":["Fehler-und-Sorgen"]}""");
    }

    @Test
    void processLogIncomingWithBody(CapturedOutput output) {
        var request = new MockHttpServletRequest("POST", "/test");
        request.addHeader("EinTest", "am-Morgen");
        var requestAttributes = new ServletRequestAttributes(request);
        RequestContextHolder.setRequestAttributes(requestAttributes);

        var body = jsonMapper.createObjectNode().put("vertreibt", "Fehler-und-Sorgen");

        aspect.logProcessIncoming(body);

        assertThat(output).containsOnlyOnce("""
            Incoming request POST /test with headers: {"EinTest":["am-Morgen"]}, body: {"vertreibt":"Fehler-und-Sorgen"}""");
    }

    @Test
    void processLogOutgoing(CapturedOutput output) {
        var request = new MockHttpServletRequest("POST", "/test");
        var requestAttributes = new ServletRequestAttributes(request);
        RequestContextHolder.setRequestAttributes(requestAttributes);

        var response = ResponseEntity.ok().header("Montag", "Der Tag").body(Map.of("an dem selbst mein Kaffee", "einen Kaffee braucht"));

        aspect.logProcessOutgoing(response);

        assertThat(output).containsOnlyOnce("""
            Outgoing response POST /test with status 200 OK, headers: [{"Montag":["Der Tag"]}], body: {"an dem selbst mein Kaffee":"einen Kaffee braucht"}""");
    }

    @Test
    void processLogOutgoingCredential(CapturedOutput output) {
        var request = new MockHttpServletRequest("POST", "/test");
        var requestAttributes = new ServletRequestAttributes(request);
        RequestContextHolder.setRequestAttributes(requestAttributes);

        var credential = jsonMapper.createObjectNode().put("credential", "Zu verstecken es gilt");
        var credentials = jsonMapper.createArrayNode().add(credential);
        JsonNode body = jsonMapper.createObjectNode().set("credentials", credentials);
        var response = ResponseEntity.ok().header("header", "zu zeigen es gilt").body(body);

        aspect.logProcessCredentialOutgoing(response);

        assertThat(output).containsOnlyOnce("""
            Outgoing response POST /test with status 200 OK, issued 1 credentials, headers: [{"header":["zu zeigen es gilt"]}]""");
    }

    @Test
    void processLogOutgoingCredentialWithResponseEncryption(CapturedOutput output) {
        var request = new MockHttpServletRequest("POST", "/test");
        var requestAttributes = new ServletRequestAttributes(request);
        RequestContextHolder.setRequestAttributes(requestAttributes);

        var response = ResponseEntity.ok().header("header", "zu zeigen es gilt").body("Zu verstecken es gilt");

        aspect.logProcessCredentialOutgoing(response);

        assertThat(output).containsOnlyOnce("""
            Outgoing response POST /test with status 200 OK, response body is encrypted, headers: [{"header":["zu zeigen es gilt"]}]""");
    }
}
