/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.config.model;

import com.nimbusds.oauth2.sdk.util.OrderedJSONObject;
import de.bdr.pidp.issuer.base.JSONRepresentation;
import net.minidev.json.JSONObject;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.List;

@NullMarked
public record CredentialMetadataImpl(@Nullable List<CredentialMetadata.Display> display, @Nullable List<CredentialMetadata.Claim> claims) implements CredentialMetadata {

    @Override
    public JSONObject toJSONObject() {
        var o = new OrderedJSONObject();
        if (display != null) o.put("display", JSONRepresentation.toJSONArray(display));
        if (claims != null) o.put("claims", JSONRepresentation.toJSONArray(claims));
        return o;
    }

    public record Claim(List<String> path, @Nullable List<CredentialMetadata.Display> display) implements CredentialMetadata.Claim {
        @Override
        public JSONObject toJSONObject() {
            var o = new OrderedJSONObject().appendField("path", path);
            if (display != null) o.put("display", JSONRepresentation.toJSONArray(display));
            return o;
        }
    }

    public record Display(String name, @Nullable String locale) implements CredentialMetadata.Display {
        @Override
        public JSONObject toJSONObject() {
            var o = new OrderedJSONObject().appendField("name", name);
            if (locale != null) o.put("locale", locale);
            return o;
        }
    }
}
