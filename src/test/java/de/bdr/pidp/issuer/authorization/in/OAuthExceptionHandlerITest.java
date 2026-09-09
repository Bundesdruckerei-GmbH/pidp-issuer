/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.in;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.token.DPoPTokenError;
import de.bdr.pidp.issuer.authorization.core.exception.DPoPValidationException;
import de.bdr.pidp.issuer.authorization.core.exception.ParameterTooLongException;
import de.bdr.pidp.issuer.authorization.core.exception.RequestUriExpiredException;
import de.bdr.pidp.issuer.authorization.core.flows.AuthorizationService;
import de.bdr.pidp.issuer.base.RandomUtil;
import de.bdr.pidp.issuer.sharedtest.ErrorResponseValidation;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;
import org.springframework.beans.ConversionNotSupportedException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.web.context.request.async.AsyncRequestTimeoutException;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;

import static org.mockito.ArgumentMatchers.any;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class OAuthExceptionHandlerITest {
    // I need a full SpringBootTest, so that the ControllerAdvice gets picked up,
    // a Web slice test ignores it

    private static final String CLIENT_ID = UUID.randomUUID().toString();

    private static final List<JWSAlgorithm> JSW_ALGS_LIST = JWSAlgorithm.Family.EC.stream().toList();
    private static final Set<JWSAlgorithm> JWS_ALGS = new HashSet<>(JSW_ALGS_LIST);

    @MockitoBean
    private AuthorizationService authorizationService;

    @Autowired
    private MockMvc mockMvc;

    static Stream<Exception> springInternalExceptions() {
        return Stream.of(
                new ConversionNotSupportedException("Conversion object here.", null, null),
                new HttpMessageNotWritableException("Http Message not writable!"),
                new AsyncRequestTimeoutException()
        );
    }

    static Stream<Exception> serverExceptions() {
        return Stream.of(
                new NullPointerException("null pointer exception"),
                new ArrayIndexOutOfBoundsException("array index out of bounds, as runtime exception"),
                new IllegalArgumentException("infinity")
        );
    }

    private void given_Mock_throws_exception_on_authorize(Exception exception) {
        Mockito.when(authorizationService.processAuthRequest(any()))
                .thenThrow(exception);
    }

    private ResultActions when_get_authorize() throws Exception {
        return this.mockMvc.perform(get("/authorize").queryParam("client_id", CLIENT_ID).queryParam("request_uri", "urn:ietf:params:oauth:request_uri:" + RandomUtil.randomString())
                .with(request -> {
                    request.setSecure(true);
                    return request;
                }));
    }

    @Test
    void given_MockMvc_when_getUnknownPath_then_NotFound() throws Exception {
        this.mockMvc.perform(get("/no-wombat-here")
                        .with(request -> {
                            request.setSecure(true);
                            return request;
                        }))
                .andExpect(status().is4xxClientError())
                .andExpect(status().isNotFound());
    }

    @Test
    void given_MockMvc_when_UseDpopNonceException_then_BadRequest() throws Exception {
        var nonce = RandomUtil.randomString();
        var useDpopNonceException = DPoPValidationException.useDPoPNonce(Set.of(), nonce);
        given_Mock_throws_exception_on_authorize(useDpopNonceException);

        when_get_authorize()
                .andExpect(status().isBadRequest())
                .andExpect(header().stringValues("DPoP-Nonce", nonce));
    }

    @Test
    void given_MockMvc_when_RequestUriExpiredException_then_Unauthorized() throws Exception {
        DPoPTokenError dpopTokenError = DPoPTokenError.INVALID_TOKEN
            .setDescription("Request uri expired")
            .setJWSAlgorithms(JWS_ALGS)
            .setRealm("oid4vci");
        var requestUriExpiredException = new RequestUriExpiredException(dpopTokenError);
        given_Mock_throws_exception_on_authorize(requestUriExpiredException);

        MockHttpServletResponse response = when_get_authorize()
            .andExpect(status().isUnauthorized())
            .andExpect(header().doesNotExist("DPoP-Nonce")).andReturn().getResponse();

        ErrorResponseValidation.checkAuthHeader(response.getHeader(HttpHeaders.WWW_AUTHENTICATE),
            "oid4vci", "invalid_token", "Request uri expired", JSW_ALGS_LIST);
    }

    @Test
    void given_MockMvc_when_RequestTooLargeException_then_PayloadTooLarge() throws Exception {
        given_Mock_throws_exception_on_authorize(new ParameterTooLongException("state", 2048));

        when_get_authorize()
                .andExpect(status().isContentTooLarge());
    }

    @ParameterizedTest
    @MethodSource({"serverExceptions", "springInternalExceptions"})
    void given_MockMvc_when_exception_then_ServerError(Exception exception) throws Exception {

        given_Mock_throws_exception_on_authorize(exception);

        when_get_authorize()
                .andExpect(status().is5xxServerError());
    }
}
