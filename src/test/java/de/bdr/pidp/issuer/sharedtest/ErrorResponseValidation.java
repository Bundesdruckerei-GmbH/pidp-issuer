/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.sharedtest;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertTrue;

@NullMarked
public class ErrorResponseValidation {

    public static void checkAuthHeader(@Nullable String authHeader, String realm, @Nullable String error, @Nullable String description, List<JWSAlgorithm> algs) {
        assertThat(authHeader, is(notNullValue()));

        StringBuilder sb = new  StringBuilder("DPoP realm=\"").append(realm).append("\"");
        if (error != null) {
            sb.append(", error=\"").append(error).append("\"");
        }
        if (description != null) {
            sb.append(", error_description=\"").append(description).append("\"");
        }
        sb.append(", algs=\"");
        assertThat(authHeader, startsWith(sb.toString()));

        var algsPattern = Pattern.compile("algs=\"([^\"]*)\"");
        var matcher = algsPattern.matcher(authHeader);
        assertTrue(matcher.find());
        var rawAlgs = matcher.group(1).trim();
        var actualAlgs = Arrays.stream(rawAlgs.split("\\s+")).filter(alg -> !alg.isBlank()).toList();

        var expectedAlgs = algs.stream().map(Algorithm::getName).toList();
        assertThat(actualAlgs, containsInAnyOrder(expectedAlgs.toArray()));
    }
}
