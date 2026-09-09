/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.in;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.token.DPoPTokenError;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidAccessTokenException;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.OIDException;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.UnknownCredentialConfigurationException;
import de.bdr.pidp.issuer.issuance.openid4vci.out.authorization.AuthorizationDiscoveryAdapter;
import de.bdr.pidp.issuer.issuance.openid4vci.service.dpop.IssuanceDPoPValidationException;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

@Slf4j
@NullMarked
@ControllerAdvice(basePackages = "de.bdr.pidp.issuer.issuance.openid4vci")
@Order(Ordered.HIGHEST_PRECEDENCE)
public class OpenID4VCIExceptionHandler {
    private static final String REALM = "oid4vci";

    private final JsonMapper mapper;
    private final Set<JWSAlgorithm> signingAlgValuesSupported;

    public OpenID4VCIExceptionHandler(JsonMapper mapper, AuthorizationDiscoveryAdapter discovery) {
        this.mapper = mapper;
        this.signingAlgValuesSupported = Set.copyOf(discovery.getDPoPSigningAlgorithms());
    }


    @ExceptionHandler({InvalidAccessTokenException.class})
    public ResponseEntity<JsonNode> handleInvalidAccessTokenException(InvalidAccessTokenException re) {
        var tokenError = switch (re.getReason()) {
            case MISSING_TOKEN -> DPoPTokenError.MISSING_TOKEN;
            case INVALID_TOKEN -> DPoPTokenError.INVALID_TOKEN;
            case INSUFFICIENT_SCOPE -> DPoPTokenError.INSUFFICIENT_SCOPE;
        };
        tokenError = tokenError.setRealm(REALM).setJWSAlgorithms(signingAlgValuesSupported);
        if (re.getErrorDescription() != null) {
            tokenError = tokenError.setDescription(re.getErrorDescription());
        }
        log.error("InvalidAccessTokenException scheme {}, error {}", tokenError.getScheme().getValue(), tokenError.getCode(), re);
        return handleTokenError(tokenError, Collections.emptyMap());
    }

    @ExceptionHandler({IssuanceDPoPValidationException.class})
    public ResponseEntity<JsonNode> handleIssuanceDPoPValidationException(IssuanceDPoPValidationException re) {
        var tokenError = re.getError();
        log.error("IssuanceDPoPValidationException scheme {}, error {}", tokenError.getScheme().getValue(), tokenError.getCode(), re);
        return handleTokenError(tokenError, re.getHeader());
    }

    private ResponseEntity<JsonNode> handleTokenError(DPoPTokenError tokenError, Map<String, String> headers) {
        var responseBuilder = ResponseEntity
            .status(tokenError.getHTTPStatusCode())
            .header(HttpHeaders.WWW_AUTHENTICATE, tokenError.toWWWAuthenticateHeader());
        headers.forEach(responseBuilder::header);
        return responseBuilder.build();
    }

    @ExceptionHandler(UnknownCredentialConfigurationException.class)
    public ResponseEntity<JsonNode> handleUnknownCredentialConfigurationException(UnknownCredentialConfigurationException oe) {
        log.error("Application Exception {}", oe.getErrorCode(), oe);
        var headers = new LinkedMultiValueMap<String, String>();
        headers.setAll(oe.getHeader());
        return createErrorResponse(HttpStatus.BAD_REQUEST, oe.getErrorCode(), oe.getErrorDescription(), headers);
    }

    @ExceptionHandler(OIDException.class)
    public ResponseEntity<JsonNode> handleOidException(OIDException oe) {
        log.error("Application Exception {}", oe.getErrorCode(), oe);
        var headers = new LinkedMultiValueMap<String, String>();
        headers.setAll(oe.getHeader());
        return createErrorResponse(HttpStatus.BAD_REQUEST, oe.getErrorCode(), oe.getErrorDescription(), headers);
    }

    private ResponseEntity<JsonNode> createErrorResponse(HttpStatus statusCode, String errorCode, @Nullable String description, @Nullable MultiValueMap<String, String> headerValues) {
        var headers = headerValues == null ? new HttpHeaders() : new HttpHeaders(headerValues);
        headers.setContentType(MediaType.APPLICATION_JSON);
        ObjectNode body = mapper.createObjectNode()
                .put("error", errorCode);
        if (description != null) {
            body.put("error_description", description);
        }
        return new ResponseEntity<>(body, headers, statusCode);
    }
}
