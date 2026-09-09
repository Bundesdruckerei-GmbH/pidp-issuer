/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.jwt;

import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import net.minidev.json.JSONObject;
import org.jspecify.annotations.Nullable;

import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.AbstractMap;
import java.util.Map;

/// Class to handle JOSE status list reference according to draft-ietf-oauth-status-list
/// ```
/// {
///   "status": {
///     "status_list": {
///       "idx": 0,
///       "uri": "https://example.com/statuslists/1"
///     }
///   }
/// }
/// ```
public record StatusListRef(URI uri, int index) {
    private static final String STATUS_CLAIM = "status";
    private static final String STATUS_LIST_CLAIM = "status_list";
    private static final String INDEX_CLAIM = "idx";
    private static final String URI_CLAIM = "uri";

    public StatusListRef(String uri, int index) {
        this(URI.create(uri), index);
    }

    public static @Nullable StatusListRef parse(final JWTClaimsSet jwtClaimsSet) throws ParseException {
        var status = jwtClaimsSet.getJSONObjectClaim(STATUS_CLAIM);
        if (status == null) {
            return null;
        }
        var statusList = JSONObjectUtils.getJSONObject(status, STATUS_LIST_CLAIM);
        if (statusList == null) {
            return null;
        }
        var uriStr = JSONObjectUtils.getString(statusList, URI_CLAIM);
        if (uriStr == null) {
            throw new ParseException("status_list expected to contain uri", 0);
        }
        URI uri;
        try {
            uri = new URI(uriStr);
        } catch (URISyntaxException e) {
            throw new ParseException(e.getReason(), e.getIndex());
        }
        var idx = JSONObjectUtils.getInt(statusList, INDEX_CLAIM);

        return new StatusListRef(uri, idx);
    }

    public Map.Entry<String, JSONObject> toJWTClaim() {
        JSONObject statusList = new JSONObject();
        statusList.put(URI_CLAIM, uri.toString());
        statusList.put(INDEX_CLAIM, index);

        JSONObject status = new JSONObject();
        status.put(STATUS_LIST_CLAIM, statusList);

        return new AbstractMap.SimpleImmutableEntry<>(STATUS_CLAIM, status);
    }
}
