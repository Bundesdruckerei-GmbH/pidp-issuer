/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.in;

import de.bdr.pidp.issuer.authorization.core.exception.FinishAuthException;
import de.bdr.pidp.issuer.authorization.core.exception.OAuthException;
import de.bdr.pidp.issuer.authorization.core.exception.ParameterTooLongException;
import de.bdr.pidp.issuer.authorization.core.exception.RequestUriExpiredException;
import de.bdr.pidp.issuer.authorization.core.exception.SessionExpiredException;
import de.bdr.pidp.issuer.authorization.core.exception.SessionNotFoundException;
import lombok.RequiredArgsConstructor;
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
import org.springframework.web.util.UriComponentsBuilder;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

import static java.util.Optional.ofNullable;

@Slf4j
@NullMarked
@ControllerAdvice("de.bdr.pidp.issuer.authorization")
@Order(Ordered.HIGHEST_PRECEDENCE)
@RequiredArgsConstructor
public class OAuthExceptionHandler {

    private final JsonMapper mapper;

    @ExceptionHandler(ParameterTooLongException.class)
    public ResponseEntity<JsonNode> handleParameterTooLongException(ParameterTooLongException ex) {
        log.error("Application Exception {}", ex.getMessage(), ex);
        return createErrorResponse(HttpStatus.CONTENT_TOO_LARGE, ex.getErrorCode(), ex.getErrorDescription());
    }

    @ExceptionHandler(OAuthException.class)
    public ResponseEntity<JsonNode> handleOAuthException(OAuthException oe) {
        log.error("Application Exception {}", oe.getErrorCode(), oe);
        var headers = new LinkedMultiValueMap<String, String>();
        headers.setAll(oe.getHeader());
        return createErrorResponse(HttpStatus.BAD_REQUEST, oe.getErrorCode(), oe.getErrorDescription(), headers);
    }

    @ExceptionHandler(RequestUriExpiredException.class)
    public ResponseEntity<JsonNode> handleRequestUriExpiredException(RequestUriExpiredException re) {
        var tokenError = re.getError();
        log.error("RequestUriExpiredException scheme {}, error {}", tokenError.getScheme().getValue(), tokenError.getCode(), re);
        var responseBuilder = ResponseEntity
            .status(tokenError.getHTTPStatusCode())
            .header(HttpHeaders.WWW_AUTHENTICATE, tokenError.toWWWAuthenticateHeader());
        re.getHeader().forEach(responseBuilder::header);
        return responseBuilder.build();
    }

    @ExceptionHandler(FinishAuthException.class)
    public ResponseEntity<Object> handleFinishAuthException(FinishAuthException ex) {
        var error = ex.getError();
        var errorDescription = ex.getErrorDescription();
        var description = errorDescription == null ? ex.getCause().getMessage() : errorDescription;
        log.warn("application exception caught: {}, {}", error, description, ex.getCause());

        var givenUri = ofNullable(ex.getRedirectUri()).orElse("http://localhost:8080/");
        var redirectBuilder = UriComponentsBuilder.fromUriString(givenUri);
        if (errorDescription != null) {
            redirectBuilder.queryParam("error_description", errorDescription);
        }
        redirectBuilder.queryParam("error", error);
        if (ex.getState() != null) {
            redirectBuilder.queryParam("state", ex.getState());
        }
        return ResponseEntity
                .status(HttpStatus.FOUND)
                .header(HttpHeaders.LOCATION, redirectBuilder.toUriString())
                .build();
    }

    @ExceptionHandler(SessionNotFoundException.class)
    public ResponseEntity<JsonNode> handleSessionNotFoundException(SessionNotFoundException ex) {
        log.error("Session was not found", ex);
        return createErrorResponse(HttpStatus.BAD_REQUEST, "Bad request");
    }

    @ExceptionHandler(SessionExpiredException.class)
    public ResponseEntity<JsonNode> handleSessionExpiredException(SessionExpiredException ex) {
        log.error("Session was expired", ex);
        return createErrorResponse(HttpStatus.UNAUTHORIZED, ex.getMessage());
    }

    private ResponseEntity<JsonNode> createErrorResponse(HttpStatus status, String errorCode) {
        return createErrorResponse(status, errorCode, null, null);
    }

    private ResponseEntity<JsonNode> createErrorResponse(HttpStatus status, String errorCode, String description) {
        return createErrorResponse(status, errorCode, description, null);
    }

    private ResponseEntity<JsonNode> createErrorResponse(HttpStatus status, String errorCode, @Nullable String description, @Nullable MultiValueMap<String, String> headerValues) {
        var headers = headerValues == null ? new HttpHeaders() : new HttpHeaders(headerValues);
        headers.setContentType(MediaType.APPLICATION_JSON);
        ObjectNode body = mapper.createObjectNode()
                .put("error", errorCode);
        if (description != null) {
            body.put("error_description", description);
        }
        return new ResponseEntity<>(body, headers, status.value());
    }
}
