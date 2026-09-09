/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.filter;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
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

@SpringBootTest(properties = {"pidi.log-request-response=", "logging.level.de.bdr.pidp.issuer.base.filter.RequestResponseLoggingFilter=DEBUG"})
@AutoConfigureMockMvc
@ExtendWith(OutputCaptureExtension.class)
class RequestResponseNoLogITest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Verify request on releases page will not be logged")
    void test001(CapturedOutput capturedOutput) throws Exception {
        this.mockMvc.perform(get("/releases"))
                .andExpect(status().isOk());

        assertThat(capturedOutput.getOut()).doesNotContain("Incoming Request for [GET] /releases").doesNotContain("Outgoing Response for [GET] /releases: Status = 200");
    }

    @Test
    @DisplayName("Verify request on nonce endpoint will be logged")
    void test002(CapturedOutput capturedOutput) throws Exception {
        this.mockMvc.perform(post("/nonce"))
                .andExpect(status().isOk());

        assertThat(capturedOutput.getOut()).doesNotContain("Incoming Request for [POST] /nonce")
                .doesNotContain("Outgoing Response for [POST] /nonce: Status = 200");
    }
}
