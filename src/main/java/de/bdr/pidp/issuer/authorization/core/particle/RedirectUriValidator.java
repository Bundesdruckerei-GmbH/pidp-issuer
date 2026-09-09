/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle;

import de.bdr.pidp.issuer.authorization.core.exception.InvalidGrantException;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidRequestException;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

@Component
public class RedirectUriValidator {
    private static final Pattern PRIVATE_USE_URI_SCHEME =
        Pattern.compile("^[a-z]+\\.[a-z0-9-.+]*[a-z0-9]$", Pattern.CASE_INSENSITIVE);
    private static final List<String> LOOPBACK_INTERFACES = List.of("127.0.0.1", "[::1]");
    private static final String INVALID_REDIRECT_URI = "Invalid redirect URI";

    public void validateRedirectUri(final String redirectUri) {
        try {
            URI uri = new URI(redirectUri);
            if (!isSupportedRedirectURI(uri)) {
                throw new InvalidRequestException(INVALID_REDIRECT_URI, "Redirect URI unsupported");
            }
        } catch (URISyntaxException e) {
            throw new InvalidRequestException(INVALID_REDIRECT_URI, "Redirect URI not a valid URI", e);
        }
    }

    public void validateRedirectUri(final String redirectUriFromRequest, final String redirectUriFromSession) {
        if (!Objects.equals(redirectUriFromRequest, redirectUriFromSession)) {
            throw new InvalidGrantException(INVALID_REDIRECT_URI);
        }
    }

    private boolean isSupportedRedirectURI(URI uri) {
        return isPrivateUseSchemeURI(uri) || isClaimedHttpsSchemeURI(uri) || isLoopbackInterfaceURI(uri);
    }

    /// Valid example:
    /// ```com.example.app:/oauth2redirect/example-provider```
    private boolean isPrivateUseSchemeURI(URI uri) {
        return
            uri.getScheme() != null &&
                PRIVATE_USE_URI_SCHEME.matcher(uri.getScheme()).matches() &&
                uri.getAuthority() == null &&
                uri.getPath() != null &&
                uri.getFragment() == null;

    }

    /// Valid example:
    /// ```https://app.example.com/oauth2redirect/example-provider```
    private boolean isClaimedHttpsSchemeURI(URI uri) {
        return
            uri.getScheme() != null &&
                uri.getScheme().equals("https") &&
                uri.getAuthority() != null &&
                uri.getPath() != null &&
                uri.getFragment() == null;
    }

    /// Valid examples:
    /// ```http://127.0.0.1:51004/oauth2redirect/example-provider```
    /// ```http://[::1]:61023/oauth2redirect/example-provider```
    private boolean isLoopbackInterfaceURI(URI uri) {
        return
            uri.getScheme() != null &&
                uri.getScheme().equals("http") &&
                uri.getHost() != null &&
                LOOPBACK_INTERFACES.contains(uri.getHost()) &&
                uri.getPort() != -1 &&
                uri.getPort() < 1 << 16 &&
                uri.getPath() != null &&
                uri.getFragment() == null;
    }
}
