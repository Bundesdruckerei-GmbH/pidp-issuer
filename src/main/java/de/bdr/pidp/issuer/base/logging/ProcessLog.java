/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.logging;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import tools.jackson.databind.json.JsonMapper;

import java.util.Collections;
import java.util.Enumeration;

import static de.bdr.pidp.issuer.base.logging.LogCategory.Value.PROCESS;

@Slf4j
public abstract class ProcessLog {
    protected final JsonMapper jsonMapper = new JsonMapper();

    protected void logProcessIncoming(Object requestBody) {
        var attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes == null) {
            return;
        }
        var request = attributes.getRequest();

        var headers = getHeaderParams(request);

        try (var _ = LogCategory.mdcContext(PROCESS)) {
            ProcessLog.log.info(
                "Incoming request {} {} with headers: {}, body: {}",
                request.getMethod(),
                request.getRequestURI(),
                jsonMapper.writeValueAsString(headers),
                jsonMapper.writeValueAsString(requestBody)
            );
        }
    }

    protected void logProcessIncoming() {
        var attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes == null) {
            return;
        }
        var request = attributes.getRequest();

        var headers = getHeaderParams(request);

        try (var _ = LogCategory.mdcContext(PROCESS)) {
            log.info(
                "Incoming request {} {} with headers: {}, params: {}",
                request.getMethod(),
                request.getRequestURI(),
                jsonMapper.writeValueAsString(headers),
                jsonMapper.writeValueAsString(request.getParameterMap())
            );
        }
    }

    protected void logProcessOutgoing(ResponseEntity<?> result) {
        var attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes == null) {
            return;
        }
        var request = attributes.getRequest();

        try (var _ = LogCategory.mdcContext(PROCESS)) {
            ProcessLog.log.info(
                "Outgoing response {} {} with status {}, headers: {}, body: {}",
                request.getMethod(),
                request.getRequestURI(),
                result.getStatusCode(),
                jsonMapper.writeValueAsString(result.getHeaders().headerSet()),
                jsonMapper.writeValueAsString(result.getBody())
            );
        }
    }

    private MultiValueMap<String, String> getHeaderParams(HttpServletRequest request) {
        var headerParams = new LinkedMultiValueMap<String, String>();
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            headerParams.put(headerName, Collections.list(request.getHeaders(headerName)));
        }
        return headerParams;
    }
}
