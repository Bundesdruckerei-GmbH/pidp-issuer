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
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;

import java.io.IOException;

@WebFilter(urlPatterns = {"/challenge", "/par", "/authorize", "/finish-authorization", "/token", "/nonce", "/credential"})
public class CacheControlHeaderFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        httpServletResponse.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        httpServletResponse.setHeader(HttpHeaders.PRAGMA, "no-cache");
        chain.doFilter(request, response);
    }
}
