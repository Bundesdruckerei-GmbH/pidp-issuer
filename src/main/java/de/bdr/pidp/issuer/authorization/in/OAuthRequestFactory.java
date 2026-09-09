/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.in;

import de.bdr.pidp.issuer.authorization.core.domain.AuthRequest;
import de.bdr.pidp.issuer.authorization.core.domain.FinishAuthRequest;
import de.bdr.pidp.issuer.authorization.core.domain.ParRequest;
import de.bdr.pidp.issuer.authorization.core.domain.RefreshTokenRequest;
import de.bdr.pidp.issuer.authorization.core.domain.TokenRequest;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidRequestException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

@Slf4j
@Component
public class OAuthRequestFactory {
    private static final Pattern SAFE_NAME_PATTERN = Pattern.compile("[a-zA-Z0-9_.\\-]+");

    public ParRequest createParRequest(MultiValueMap<String, String> allHeaders, MultiValueMap<String, String> allParams) {
        Map<String, String> params = readParams(allParams);
        Map<String, List<String>> headers = readHeaders(allHeaders);

        return new ParRequest(headers, params);
    }

    public AuthRequest createAuthRequest(MultiValueMap<String, String> allParams) {
        Map<String, String> params = readParams(allParams);
        return new AuthRequest(params);
    }

    public FinishAuthRequest createFinishAuthRequest(MultiValueMap<String, String> allParams) {
        Map<String, String> params = readParams(allParams);
        return new FinishAuthRequest(params);
    }

    public TokenRequest createTokenRequest(MultiValueMap<String, String> allHeaders, MultiValueMap<String, String> allParams) {
        Map<String, String> params = readParams(allParams);
        Map<String, List<String>> headers = readHeaders(allHeaders);
        return new TokenRequest(headers, params);
    }

    public RefreshTokenRequest createRefreshTokenRequest(MultiValueMap<String, String> allHeaders, MultiValueMap<String, String> allParams) {
        Map<String, String> params = readParams(allParams);
        Map<String, List<String>> headers = readHeaders(allHeaders);
        return new RefreshTokenRequest(headers, params);
    }

    private static Map<String, List<String>> readHeaders(MultiValueMap<String, String> allHeaders) {
        Map<String, List<String>> headers = new HashMap<>();
        allHeaders.forEach((k, v) -> headers.put(k.toLowerCase(), v));
        return headers;
    }

    private static Map<String, String> readParams(MultiValueMap<String, String> allParams) {
        Map<String, String> params = new HashMap<>();
        Set<String> multiValued = new HashSet<>();
        for (var entry : allParams.entrySet()) {
            List<String> values = entry.getValue();
            var name = entry.getKey();
            switch (values.size()) {
                case 0:
                    log.warn("no value for param {}", safeName(name));
                    break;
                case 1:
                    params.put(name.toLowerCase(), values.getFirst());
                    break;
                default:
                    log.warn("multiple values for param {}", safeName(name));
                    multiValued.add(name);
                    break;
            }
        }
        if (!multiValued.isEmpty()) {
            var message = "multi valued parameters: " + String.join(",", multiValued);
            throw new InvalidRequestException("parameters are present more than once", message);
        }
        return params;
    }

    private static String safeName(String input) {
        var matcher = SAFE_NAME_PATTERN.matcher(input);
        if (matcher.matches()) {
            return matcher.group();
        } else {
            return "/unsafe/";
        }
    }
}
