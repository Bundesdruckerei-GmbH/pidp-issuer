/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.in;

import de.bdr.pidp.issuer.base.PidpServiceUnavailableException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.ConversionNotSupportedException;
import org.springframework.beans.TypeMismatchException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.validation.BindException;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MissingPathVariableException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.async.AsyncRequestTimeoutException;
import org.springframework.web.multipart.support.MissingServletRequestPartException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

@Slf4j
@ControllerAdvice
public class BaseExceptionHandler {

    private static final String INTERNAL_SERVER_ERROR_MSG = "Internal server error";

    private final HttpHeaders headers = new HttpHeaders();

    private final JsonMapper mapper;

    public BaseExceptionHandler(JsonMapper mapper) {
        this.mapper = mapper;
        this.headers.setContentType(MediaType.APPLICATION_JSON);
    }

    @ExceptionHandler({HttpRequestMethodNotSupportedException.class, HttpMediaTypeNotSupportedException.class,
        HttpMediaTypeNotAcceptableException.class, MissingServletRequestParameterException.class, ServletRequestBindingException.class,
        TypeMismatchException.class, HttpMessageNotReadableException.class, MissingServletRequestPartException.class, BindException.class})
    public ResponseEntity<JsonNode> handleSpringClientException(Exception ex) {
        log.error("Spring could not process request", ex);
        return createErrorResponse(HttpStatus.BAD_REQUEST, "Bad request");
    }

    @ExceptionHandler({MissingPathVariableException.class, ConversionNotSupportedException.class,
        HttpMessageNotWritableException.class, AsyncRequestTimeoutException.class})
    public ResponseEntity<JsonNode> handleSpringInternalException(Exception ex) {
        log.error("Spring could not process request", ex);
        return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, INTERNAL_SERVER_ERROR_MSG);
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<JsonNode> handleRuntimeException(Exception ex) {
        log.error("Runtime Exception without further specification", ex);
        return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, INTERNAL_SERVER_ERROR_MSG);
    }

    @ExceptionHandler(PidpServiceUnavailableException.class)
    public ResponseEntity<JsonNode> handlePidpServiceUnavailableException(PidpServiceUnavailableException ex) {
        log.error("An error occurred while trying to process request", ex);
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
    }

    private ResponseEntity<JsonNode> createErrorResponse(HttpStatus status, String errorCode) {
        ObjectNode body = mapper.createObjectNode().put("error", errorCode);
        return new ResponseEntity<>(body, headers, status);
    }
}
