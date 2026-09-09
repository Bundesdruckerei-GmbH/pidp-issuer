/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base;

import com.google.common.net.MediaType;
import de.bdr.pidp.issuer.base.filter.WebHeaderFilter;
import jakarta.servlet.ServletException;
import org.apache.catalina.servlets.DefaultServlet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class WebHeaderFilterTest {

    WebHeaderFilter subject = new WebHeaderFilter();

    @DisplayName("should set security header on responses of type")
    @ParameterizedTest(name = "{index} => mime type = {0}")
    @MethodSource("filteredMimeTypes")
    void filteredResponse(String mimeType) throws ServletException, IOException {
        var request =  new MockHttpServletRequest();
        var response = new MockHttpServletResponse();
        var filterChain = new MockFilterChain(new DefaultServlet(),
            (_, response1, _) ->
                response1.setContentType(mimeType)
        );

        subject.doFilter(request, response, filterChain);

        assertThat(response.getHeader("Strict-Transport-Security"))
            .matches(".*max-age=[1-9]\\d*.*")
            .contains("includeSubDomains; preload");
        assertThat(response.getHeader("X-Frame-Options"))
            .isEqualTo("DENY");
        assertThat(response.getHeader("Content-Security-Policy"))
            .contains("frame-ancestors 'none'");
    }

    private static Stream<Arguments> filteredMimeTypes() {
        return Stream.of(
            Arguments.arguments(MediaType.HTML_UTF_8.withoutParameters().toString()),
            Arguments.arguments(MediaType.HTML_UTF_8.toString()),
            Arguments.arguments(MediaType.TEXT_JAVASCRIPT_UTF_8.withoutParameters().toString()),
            Arguments.arguments(MediaType.TEXT_JAVASCRIPT_UTF_8.toString()),
            Arguments.arguments(MediaType.CSS_UTF_8.withoutParameters().toString()),
            Arguments.arguments(MediaType.CSS_UTF_8.toString()),
            Arguments.arguments(MediaType.JPEG.toString()),
            Arguments.arguments(MediaType.PNG.toString())
        );
    }

    @DisplayName("should not set security header on responses of type")
    @ParameterizedTest(name = "{index} => mime type = {0}")
    @MethodSource("nonFilteredMimeTypes")
    void nonFilteredResponse(String mimeType) throws ServletException, IOException {
        var request =  new MockHttpServletRequest();
        var response = new MockHttpServletResponse();
        var filterChain = new MockFilterChain(new DefaultServlet(),
                (_, response1, _) ->
                    response1.setContentType(mimeType)
        );

        subject.doFilter(request, response, filterChain);

        assertThat(response.getHeader("Strict-Transport-Security")).isNull();
        assertThat(response.getHeader("X-Frame-Options")).isNull();
        assertThat(response.getHeader("Content-Security-Policy")).isNull();
    }

    private static Stream<Arguments> nonFilteredMimeTypes() {
        return Stream.of(
            Arguments.arguments(MediaType.JSON_UTF_8.withoutParameters().toString()),
            Arguments.arguments(MediaType.JSON_UTF_8.toString()),
            Arguments.arguments(MediaType.FORM_DATA.toString())
        );
    }
}
