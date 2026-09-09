/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.filter;

import jakarta.servlet.ServletException;
import org.apache.catalina.servlets.DefaultServlet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

class CacheControlHeaderFilterTest {

    CacheControlHeaderFilter subject = new CacheControlHeaderFilter();

    @DisplayName("should set no cache header on html response")
    @Test
    void htmlResponse() throws ServletException, IOException {
        var request =  new MockHttpServletRequest();
        var response = new MockHttpServletResponse();
        var filterChain = new MockFilterChain(new DefaultServlet());

        subject.doFilter(request, response, filterChain);

        assertThat(response.getHeader(HttpHeaders.CACHE_CONTROL)).isEqualTo("no-store");
        assertThat(response.getHeader(HttpHeaders.PRAGMA)).isEqualTo("no-cache");
    }
}
