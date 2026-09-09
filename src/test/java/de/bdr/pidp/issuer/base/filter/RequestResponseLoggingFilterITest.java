/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.filter;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Isolated;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {"pidi.log-request-response=true", "logging.level.de.bdr.pidp.issuer.base.filter.RequestResponseLoggingFilter=DEBUG"})
@AutoConfigureMockMvc
@Isolated
@ExtendWith(OutputCaptureExtension.class)
class RequestResponseLoggingFilterITest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Verify request on unknown page will be logged")
    void test001(CapturedOutput capturedOutput) throws Exception {
        this.mockMvc.perform(get("/no-wombat-here"))
                .andExpect(status().is4xxClientError())
                .andExpect(status().isNotFound());

        assertThat(capturedOutput.getOut()).contains("Incoming Request for [GET] /no-wombat-here").contains("Outgoing Response for [GET] /no-wombat-here: Status = 404");
    }

    @Test
    @DisplayName("Verify request on releases page will be logged")
    void test002(CapturedOutput capturedOutput) throws Exception {
        this.mockMvc.perform(get("/releases"))
                .andExpect(status().isOk());

        assertThat(capturedOutput.getOut()).contains("Incoming Request for [GET] /releases").contains("Outgoing Response for [GET] /releases: Status = 200");
    }

    @Test
    @DisplayName("Verify request on nonce endpoint will be logged")
    void test003(CapturedOutput capturedOutput) throws Exception {
        this.mockMvc.perform(post("/nonce"))
                .andExpect(status().isOk());

        assertThat(capturedOutput.getOut()).contains("Incoming Request for [POST] /nonce")
                .contains("Outgoing Response for [POST] /nonce: Status = 200, Header =")
                .contains("Cache-Control=[no-store]").contains("Body = {\"c_nonce\":");
    }

    @Test
    @DisplayName("Verify that requests on favicons will be logged without details")
    void test004(CapturedOutput capturedOutput) throws Exception {
        this.mockMvc.perform(get("/favicon.png"))
            .andExpect(status().isOk());

        assertThat(capturedOutput.getOut())
            .doesNotContain("Incoming Request for [GET] /favicon.png")
            .doesNotContain("Outgoing Response for [GET] /favicon.png: Status = 200")
            .doesNotContain("Content-Type=[image/png]");
    }

    @Test
    @DisplayName("Verify that requests on html resources will be logged without details")
    void test005(CapturedOutput capturedOutput) throws Exception {
        this.mockMvc.perform(get("/"))
            .andExpect(status().isOk());

        assertThat(capturedOutput.getOut())
            .contains("Incoming Request for [GET] /")
            .contains("Outgoing Response for [GET] /: Status = 200")
            .doesNotContain("Content-Type=[text/html;charset=UTF-8]")
            .doesNotContain("<!DOCTYPE html>");
    }

    @Test
    @DisplayName("Verify that requests on css resources will be logged without details")
    void test006(CapturedOutput capturedOutput) throws Exception {
        this.mockMvc.perform(get("/css/a11y-overrides.css"))
            .andExpect(status().isOk());

        assertThat(capturedOutput.getOut())
            .doesNotContain("Incoming Request for [GET] /css/a11y-overrides.css")
            .doesNotContain("Outgoing Response for [GET] /css/a11y-overrides.css: Status = 200")
            .doesNotContain("Content-Type=[text/css]")
            .doesNotContain("text-decoration: underline;");
    }

    @Test
    @DisplayName("Verify that requests on js resources will be logged without details")
    void test007(CapturedOutput capturedOutput) throws Exception {
        this.mockMvc.perform(get("/js/mdb.umd.min.js"))
            .andExpect(status().isOk());

        assertThat(capturedOutput.getOut())
            .doesNotContain("Incoming Request for [GET] /js/mdb.umd.min.js")
            .doesNotContain("Outgoing Response for [GET] /js/mdb.umd.min.js: Status = 200")
            .doesNotContain("Content-Type=[text/javascript]")
            .doesNotContain("Material Design for Bootstrap");
    }

    @Test
    @DisplayName("Verify that requests on well known metadata will be logged without details")
    void test008(CapturedOutput capturedOutput) throws Exception {
        this.mockMvc.perform(get("/.well-known/openid-credential-issuer"))
            .andExpect(status().isOk());

        assertThat(capturedOutput.getOut())
            .contains("Incoming Request for [GET] /.well-known/openid-credential-issuer")
            .contains("Outgoing Response for [GET] /.well-known/openid-credential-issuer: Status = 200")
            .doesNotContainIgnoringCase("\"credential_issuer\": \"http://localhost:8080\",")
            .doesNotContain("\"credential_endpoint\": \"http://localhost:8080/credential\"");
    }

    @Test
    @DisplayName("Verify that requests on certificates will be logged without details")
    void test009(CapturedOutput capturedOutput) throws Exception {
        this.mockMvc.perform(get("/certificates/root-ca.crt"))
            .andExpect(status().isOk());

        assertThat(capturedOutput.getOut())
            .contains("Incoming Request for [GET] /certificates/root-ca.crt")
            .contains("Outgoing Response for [GET] /certificates/root-ca.crt: Status = 200")
            .doesNotContain("Content-Type=[text/plain;charset=UTF-8]")
            .doesNotContain("-----BEGIN CERTIFICATE-----");
    }

    @Test
    @DisplayName("Verify no logging on disabled endpoints")
    void test010(CapturedOutput capturedOutput) throws Exception {
        this.mockMvc.perform(get("/health"))
            .andExpect(status().isOk());

        assertThat(capturedOutput.getOut()).doesNotContainIgnoringCase("/health");
    }
}
