/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.observability;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Isolated;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(OutputCaptureExtension.class)
@Isolated
class ProcessLogAspectTest {

    private final ProcessLogAspect aspect = new ProcessLogAspect();

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
    void processLogOutgoing(CapturedOutput output) {
        var request = new MockHttpServletRequest("POST", "/test");
        var requestAttributes = new ServletRequestAttributes(request);
        RequestContextHolder.setRequestAttributes(requestAttributes);

        var response = ResponseEntity.ok().header("Montag", "Der Tag").body(Map.of("an dem selbst mein Kaffee", "einen Kaffee braucht"));

        aspect.logProcessOutgoing(response);

        assertThat(output).containsOnlyOnce("""
            Outgoing response POST /test with status 200 OK, headers: [{"Montag":["Der Tag"]}], body: {"an dem selbst mein Kaffee":"einen Kaffee braucht"}""");
    }
}
