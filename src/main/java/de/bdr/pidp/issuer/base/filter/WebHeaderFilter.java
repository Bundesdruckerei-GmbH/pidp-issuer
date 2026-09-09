/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.filter;

import com.google.common.net.MediaType;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@WebFilter(urlPatterns = "/*")
public class WebHeaderFilter implements Filter {

    private static final List<String> webMimeTypes = Arrays.asList(
        MediaType.HTML_UTF_8.withoutParameters().toString(),
        MediaType.TEXT_JAVASCRIPT_UTF_8.withoutParameters().toString(),
        MediaType.CSS_UTF_8.withoutParameters().toString(),
        MediaType.JPEG.toString(),
        MediaType.PNG.toString()
    );

    public static final String STRICT_TRANSPORT_SECURITY = "Strict-Transport-Security";
    public static final String X_FRAME_OPTIONS = "X-Frame-Options";
    public static final String CONTENT_SECURITY_POLICY = "Content-Security-Policy";

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletResponse res = (HttpServletResponse) response;
        var wrapper = new WebHeaderResponseWrapper(res);
        chain.doFilter(request, wrapper);
    }

    static class WebHeaderResponseWrapper extends HttpServletResponseWrapper {
        public WebHeaderResponseWrapper(HttpServletResponse response) {
            super(response);
        }

        @Override
        public void setContentType(String type) {
            super.setContentType(type);

            final boolean isWebMimeType = webMimeTypes.stream()
                .anyMatch(type::contains);

            if (isWebMimeType) {
                setHeader(STRICT_TRANSPORT_SECURITY, "max-age=63072000; includeSubDomains; preload");
                setHeader(X_FRAME_OPTIONS, "DENY");
                setHeader(CONTENT_SECURITY_POLICY, "frame-ancestors 'none';");
            }
        }
    }
}
