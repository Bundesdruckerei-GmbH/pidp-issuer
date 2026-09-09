/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.filter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
@Order(1) // Defines execution order for multiple filters
@ConditionalOnProperty(prefix = "pidi", name = "log-request-response", havingValue = "true")
@Slf4j
public class RequestResponseLoggingFilter implements Filter {

    private static final String MIN_OUTGOING_RESPONSE_MSG = "Outgoing Response for [{}] {}: Status = {}";
    private static final String OUTGOING_RESPOPNSE_MSG_WITH_HEADER = MIN_OUTGOING_RESPONSE_MSG + ", Header = {}";
    private static final String MIN_INCOMING_REQUEST_MSG = "Incoming Request for [{}] {}";
    private static final String HOME_PATH = "/";

    @Value("${pidi.log-request-response.without-details}")
    private String[] logWithoutDetailsArray;
    @Value("${pidi.log-request-response.disabled}")
    private String[] disabled;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (request instanceof HttpServletRequest httpServletRequest &&
            response instanceof HttpServletResponse httpServletResponse &&
            Arrays.stream(disabled).noneMatch(httpServletRequest.getRequestURI().toLowerCase()::contains)) {
            boolean logWithDetails = logDetails(httpServletRequest);

            // Wrap the request to read and modify the request body
            RequestWrapper requestWrapper = new RequestWrapper(httpServletRequest);
            logRequest(requestWrapper, logWithDetails);

            // Wrap the response to capture the body
            var responseWrapper = new ResponseWrapper(httpServletResponse);

            chain.doFilter(requestWrapper, responseWrapper);

            byte[] responseData = responseWrapper.getResponseData();
            logResponse(httpServletRequest, responseWrapper, responseData, logWithDetails);
            response.getOutputStream().write(responseData);
        } else  {
            chain.doFilter(request, response);
        }
    }

    private boolean logDetails(HttpServletRequest httpServletRequest) {
        String requestURI = httpServletRequest.getRequestURI().toLowerCase();
        // special handling for the home path, every path contains a slash
        if (requestURI.equals(HOME_PATH)) {
            return false;
        }
        return Arrays.stream(logWithoutDetailsArray).noneMatch(requestURI::contains);
    }

    private void logRequest(RequestWrapper request, boolean logWithDetails) {
        if (logWithDetails) {
            var body = printBody(request.getCachedBody(), request.getCharacterEncoding());
            if (body.isEmpty()) {
                log.debug(MIN_INCOMING_REQUEST_MSG + ": Header = {}, Parameters = {}",
                        request.getMethod(), request.getRequestURI(), getHeaderParams(request), printParameterMap(request.getParameterMap()));
            } else {
                log.debug(MIN_INCOMING_REQUEST_MSG + ": Header = {}, Parameters = {} , Body = {}",
                        request.getMethod(), request.getRequestURI(), getHeaderParams(request), printParameterMap(request.getParameterMap()), body);
            }
        } else {
            log.debug(MIN_INCOMING_REQUEST_MSG, request.getMethod(), request.getRequestURI());
        }
    }

    private void logResponse(HttpServletRequest request, ResponseWrapper response, byte[] responseData, boolean logWithDetails) {
        if (logWithDetails) {
            var body = printBody(responseData, response.getCharacterEncoding());
            if (body.isEmpty()) {
                log.debug(OUTGOING_RESPOPNSE_MSG_WITH_HEADER,
                        request.getMethod(), request.getRequestURI(), response.getStatus(), getHeaderParams(response));
            } else {
                log.debug(OUTGOING_RESPOPNSE_MSG_WITH_HEADER + ", Body = {}",
                        request.getMethod(), request.getRequestURI(), response.getStatus(), getHeaderParams(response), body);
            }
        } else {
            log.debug(MIN_OUTGOING_RESPONSE_MSG, request.getMethod(), request.getRequestURI(), response.getStatus());
        }
    }

    private Map<String, String> getHeaderParams(HttpServletRequest request) {
        Map<String, String> headerParams = new HashMap<>();
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            headerParams.put(headerName, request.getHeader(headerName));
        }
        return headerParams;
    }

    private Map<String, Collection<String>> getHeaderParams(HttpServletResponse response) {
        Map<String, Collection<String>> headerParams = new HashMap<>();
        Collection<String> headerNames = response.getHeaderNames();
        headerNames.forEach(headerName -> headerParams.put(headerName, response.getHeaders(headerName)));
        return headerParams;
    }

    private String printBody(byte[] data, String encoding) {
        if (data == null) {
            return "";
        }
        String body;
        try {
            body = new String(data, encoding);
        } catch (UnsupportedEncodingException e) {
            log.warn("Body encoding not supported", e);
            body = new String(data, StandardCharsets.UTF_8);
        }
        return body;
    }

    private String printParameterMap(Map<String, String[]> map) {
        if (map == null || map.isEmpty()) {
            return "{}";
        }
        final List<String> entries = new ArrayList<>();
        map.forEach((key, value) -> entries.add(key + "=" + printStringArray(value)));
        return "{" + String.join(", ", entries) + "}";
    }

    private String printStringArray(String[] array) {
        if (array == null || array.length == 0) {
            return "";
        } else if (array.length == 1) {
            return array[0];
        } else {
            return Arrays.toString(array);
        }
    }
}
