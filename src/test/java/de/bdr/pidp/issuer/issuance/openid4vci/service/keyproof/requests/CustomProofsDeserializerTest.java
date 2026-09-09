/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.requests;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import tools.jackson.databind.DatabindException;
import tools.jackson.databind.annotation.JsonDeserialize;
import tools.jackson.databind.json.JsonMapper;

import java.util.List;
import java.util.Map;

class CustomProofsDeserializerTest {

    private final JsonMapper jsonMapper = JsonMapper.builder().build();

    @ParameterizedTest
    @ValueSource(strings = {"jwt", "attestation"})
    void testDeserialize(String proofType) {
        String json = """
                {
                "credential_configuration_id":"pid-sd-jwt-authenticated-channel",
                "unknown_property":"hello world",
                "verifier_pub":{"kty":"EC","use":"sig","crv":"P-256","kid":"7YhOl4bgb7ezTJXuguqBB1","x":"CcGtPmeFrcIViEgC4R_9lZDq4jAoMRe8epkz8RexwdU","y":"VnvCMhzxvteHz5lMmj_yrwoXz9Cm5gi79fEFLlL0QPI","alg":"ES256"},
                "proofs":{
                "%s":[
                "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJraWQiOiJwNVZONHR6NFFOQk5OaXFvT0pWM01GIiwieCI6IkFXdmtMUEJYTXl1cE9OaXlfdjZ5NkVvcV9hMXRuVnM2eHc2b01GeExNWkkiLCJ5IjoiYTE5cWhoMmxGVjdDZTNMNEZGUGdKNUk3QzRnTHl3eXI3NE5VSUZ6dnMtNCIsImFsZyI6IkVTMjU2In19.eyJpc3MiOiJmZWQ3OTg2Mi1hZjM2LTRmZWUtOGU2NC04OWUzYzkxMDkxZWQiLCJhdWQiOiJodHRwOi8vcGlkaS5sb2NhbGhvc3QuYmRyLmRlOjgwODAvYiIsImlhdCI6MTc1MjgzODc0MCwibm9uY2UiOiIyczlIaXowYUwwa1NTSTN4dGdjaFlrIn0.9WW4zoYsVdRyLq5AgGDoUyODGuUvRibyIaKkJ0VEM6_HyKbPO6Fjj-2PsnKBj0GsQz4QdkRfQLny_yyPIBmNMQ",
                "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJraWQiOiJwNVZONHR6NFFOQk5OaXFvT0pWM01GIiwieCI6IkFXdmtMUEJYTXl1cE9OaXlfdjZ5NkVvcV9hMXRuVnM2eHc2b01GeExNWkkiLCJ5IjoiYTE5cWhoMmxGVjdDZTNMNEZGUGdKNUk3QzRnTHl3eXI3NE5VSUZ6dnMtNCIsImFsZyI6IkVTMjU2In19.eyJpc3MiOiJmZWQ3OTg2Mi1hZjM2LTRmZWUtOGU2NC04OWUzYzkxMDkxZWQiLCJhdWQiOiJodHRwOi8vcGlkaS5sb2NhbGhvc3QuYmRyLmRlOjgwODAvYiIsImlhdCI6MTc1MjgzODc0MCwibm9uY2UiOiIyczlIaXowYUwwa1NTSTN4dGdjaFlrIn0.ZdOaIStBytQsvwKax_aNf_DsYaICtYOrA7FvlJwEdj_A8LZQZjhacBfVgOyT-SDi7R5wsM5WpNz6JiyGoWz0oQ"
                ]}
                }""".formatted(proofType);
        TestCredentialRequestBody body = jsonMapper.readValue(json, TestCredentialRequestBody.class);
        Assertions.assertNotNull(body);
        Assertions.assertEquals(2, body.proofs.size());
        Assertions.assertEquals("pid-sd-jwt-authenticated-channel", body.credentialConfigurationId);
        Assertions.assertFalse(body.verifierPub.isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"jwt", "attestation"})
    void testInvalidJwt(String proofType) {
        String json = """
                {
                "credential_configuration_id":"pid-sd-jwt-authenticated-channel",
                "unknown_property":"hello world",
                "verifier_pub":{"kty":"EC","use":"sig","crv":"P-256","kid":"7YhOl4bgb7ezTJXuguqBB1","x":"CcGtPmeFrcIViEgC4R_9lZDq4jAoMRe8epkz8RexwdU","y":"VnvCMhzxvteHz5lMmj_yrwoXz9Cm5gi79fEFLlL0QPI","alg":"ES256"},
                "proofs":{
                "%s":[
                "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJraWQiOiJwNVZONHR6NFFOQk5OaXFvT0pWM01GIiwieCI6IkFXdmtMUEJYTXl1cE9OaXlfdjZ5NkVvcV9hMXRuVnM2eHc2b01GeExNWkkiLCJ5IjoiYTE5cWhoMmxGVjdDZTNMNEZGUGdKNUk3QzRnTHl3eXI3NE5VSUZ6dnMtNCIsImFsZyI6IkVTMjU2In19.eyJpc3MiOiJmZWQ3OTg2Mi1hZjM2LTRmZWUtOGU2NC04OWUzYzkxMDkxZWQiLCJhdWQiOiJodHRwOi8vcGlkaS5sb2NhbGhvc3QuYmRyLmRlOjgwODAvYiIsImlhdCI6MTc1MjgzODc0MCwibm9uY2UiOiIyczlIaXowYUwwa1NTSTN4dGdjaFlrIn0.9WW4zoYsVdRyLq5AgGDoUyODGuUvRibyIaKkJ0VEM6_HyKbPO6Fjj-2PsnKBj0GsQz4QdkRfQLny_yyPIBmNMQ",
                "invalid1.invalid2.invalid3"
                ]}
                }""".formatted(proofType);
        var jsonMappingException = Assertions.assertThrows(DatabindException.class, () -> jsonMapper.readValue(json, TestCredentialRequestBody.class));
        var msg = jsonMappingException.getOriginalMessage();

        Assertions.assertEquals("Failed to parse jwt", msg);
    }

    @Test
    void testMissingProofType() {
        String json = """
                {
                "credential_configuration_id":"pid-sd-jwt-authenticated-channel",
                "unknown_property":"hello world",
                "verifier_pub":{"kty":"EC","use":"sig","crv":"P-256","kid":"7YhOl4bgb7ezTJXuguqBB1","x":"CcGtPmeFrcIViEgC4R_9lZDq4jAoMRe8epkz8RexwdU","y":"VnvCMhzxvteHz5lMmj_yrwoXz9Cm5gi79fEFLlL0QPI","alg":"ES256"},
                "proofs":{}
                }""";
        var jsonMappingException = Assertions.assertThrows(DatabindException.class, () -> jsonMapper.readValue(json, TestCredentialRequestBody.class));
        var msg = jsonMappingException.getOriginalMessage();

        Assertions.assertEquals("proof_type is empty or invalid", msg);
    }

    @Test
    void testProofTypeValueNotAnArray() {
        String json = """
                {
                "credential_configuration_id":"pid-sd-jwt-authenticated-channel",
                "unknown_property":"hello world",
                "verifier_pub":{"kty":"EC","use":"sig","crv":"P-256","kid":"7YhOl4bgb7ezTJXuguqBB1","x":"CcGtPmeFrcIViEgC4R_9lZDq4jAoMRe8epkz8RexwdU","y":"VnvCMhzxvteHz5lMmj_yrwoXz9Cm5gi79fEFLlL0QPI","alg":"ES256"},
                "proofs":{
                "attestation":"invalid"
                }
                }""";
        var jsonMappingException = Assertions.assertThrows(DatabindException.class, () -> jsonMapper.readValue(json, TestCredentialRequestBody.class));
        var msg = jsonMappingException.getOriginalMessage();

        Assertions.assertEquals("proof_type value needs to be an array", msg);
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private static class TestCredentialRequestBody {
        @JsonProperty(value = "credential_configuration_id", required = true)
        String credentialConfigurationId;

        @JsonProperty(value = "verifier_pub", required = true)
        Map<String, Object> verifierPub;

        @JsonProperty("proofs")
        @JsonDeserialize(using = CustomProofsDeserializer.class)
        List<Proof> proofs;
    }
}
