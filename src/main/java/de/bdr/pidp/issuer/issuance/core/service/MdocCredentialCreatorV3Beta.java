/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.core.service;

import COSE.CoseException;
import COSE.CoseUtilKt;
import COSE.OneKey;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.openid.connect.sdk.assurance.claims.ISO3166_1Alpha2CountryCode;
import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.base.jwk.JWKUtils;
import de.bdr.pidp.issuer.issuance.core.StatusReference;
import de.bdr.pidp.issuer.issuance.core.signer.CredentialSigner;
import de.bundesdruckerei.mdoc.kotlin.core.auth.DeviceKeyInfo;
import de.bundesdruckerei.mdoc.kotlin.core.auth.IssuerSigned;
import de.bundesdruckerei.mdoc.kotlin.core.auth.StatusClaim;
import de.bundesdruckerei.mdoc.kotlin.core.auth.X5Chain;
import de.bundesdruckerei.mdoc.kotlin.core.auth.dto.ValidityRange;
import jakarta.validation.constraints.NotNull;
import org.springframework.validation.annotation.Validated;

import java.util.Base64;
import java.util.Optional;

@Validated
public class MdocCredentialCreatorV3Beta implements CredentialCreator {
    private static final String EU_NAMESPACE = "eu.europa.ec.eudi.pid.1";
    private static final String DE_NAMESPACE = "eu.europa.ec.eudi.pid.de.1";

    private final CredentialSigner signer;
    private final String docType;
    private final X5Chain x5Chain;

    public MdocCredentialCreatorV3Beta(@NotNull CredentialSigner signer, String docType) {
        this.signer = signer;
        this.docType = docType;

        var chain = signer.getCertificateChain();
        if (chain.isEmpty()) {
            throw new IllegalStateException("Empty certificates not allowed");
        }
        this.x5Chain = X5Chain.Companion.of(chain.getFirst());
    }

    @Override
    public String create(PIDIdentityData data, JWK holderBindingKey, StatusReference status, Validity validity) {
        var statusClaim = Optional.ofNullable(status)
            .map(StatusReference::toStatusListInfo)
            .map(StatusClaim::new)
            .orElse(null);

        var validFrom = validity.validFrom();
        var validUntil = validity.validUntil();

        var pidNamespace = new MdocPIDNamespaceBuilderV3Beta(EU_NAMESPACE)
            .personalData(data)
            .issuingCountry(ISO3166_1Alpha2CountryCode.DE)
            .build();
        var dePidNamespace = new MdocPIDNamespaceBuilderV3Beta(DE_NAMESPACE)
            .personalDataDe(data)
            .build();

        var deviceKey = toPublicOneKey(holderBindingKey);

        var issuerSigned = new IssuerSigned.Builder(docType, x5Chain, statusClaim)
            .setDeviceKeyInfo(new DeviceKeyInfo(deviceKey, null, null))
            .setSigningAlgorithm(signer.getAlgorithm().getCoseAlgorithm())
            .setValidityRange(new ValidityRange(validFrom, validUntil))
            .putNameSpaces(pidNamespace)
            .putNameSpaces(dePidNamespace)
            .setNowOverride$de_bundesdruckerei_mdoc_kotlin_mdoc_core(validFrom)
            .build();

        CoseUtilKt.sign(issuerSigned.getIssuerAuth(), signer);

        var mdocBytes = issuerSigned.asCBOR().EncodeToBytes();

        return Base64.getUrlEncoder().withoutPadding().encodeToString(mdocBytes);
    }

    private static OneKey toPublicOneKey(JWK holderBindingKey) {
        try {
            var devicePub = JWKUtils.toPublicKey(holderBindingKey);
            return new OneKey(devicePub, null);
        } catch (CoseException | JOSEException e) {
            throw new PidServerException("Could not convert holder binding key", e);
        }
    }
}
