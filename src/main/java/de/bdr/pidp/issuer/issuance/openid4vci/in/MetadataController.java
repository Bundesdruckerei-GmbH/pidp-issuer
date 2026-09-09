/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.in;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.Issuer;
import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.issuance.config.model.CredentialIssuerMetadata;
import de.bdr.pidp.issuer.issuance.core.signer.MetadataSigner;
import de.bdr.pidp.issuer.issuance.openid4vci.in.model.SdJwtVcMetadata;
import de.bdr.pidp.issuer.issuance.openid4vci.in.model.SdJwtVcMetadataKeys;
import de.bdr.pidp.issuer.issuance.openid4vci.service.MetadataService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.cert.CertificateEncodingException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

@RestController("issuanceMetadataController")
class MetadataController {
    protected static final String OPENIDVCI_ISSUER_METADATA_JWT_TYPE = "openidvci-issuer-metadata+jwt";

    private final Issuer credentialIssuer;
    private final String credentialIssuerMetadataJSON;
    private final JWTClaimsSet credentialIssuerMetadataJWTClaims;

    private final MetadataSigner metadataSigner;
    private final MetadataService metadataService;

    MetadataController(
        CredentialIssuerMetadata issuerMetadata,
        MetadataService metadataService,
        MetadataSigner metadataSigner
    ) throws ParseException {
        credentialIssuer = issuerMetadata.credentialIssuer();
        credentialIssuerMetadataJSON = issuerMetadata.toJSONObject().toJSONString();
        credentialIssuerMetadataJWTClaims = JWTClaimsSet.parse(credentialIssuerMetadataJSON);
        this.metadataService = metadataService;
        this.metadataSigner = metadataSigner;
    }

    @GetMapping(path = {"/.well-known/openid-credential-issuer"})
    ResponseEntity<String> getCredentialIssuerMetadataJSON() {
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.setContentType(MediaType.APPLICATION_JSON);
        return ResponseEntity.ok().headers(responseHeaders).body(credentialIssuerMetadataJSON);
    }

    @GetMapping(path = "/.well-known/openid-credential-issuer", produces = "application/jwt")
    String getCredentialIssuerMetadataJWT() {
        Base64 certChain;
        try {
            certChain = Base64.encode(metadataSigner.getAccessCertificate().getEncoded());
        } catch (CertificateEncodingException e) {
            throw new PidServerException("Failed to encode access certificate", e);
        }

        try {
            var claims = new JWTClaimsSet.Builder(credentialIssuerMetadataJWTClaims)
                .subject(credentialIssuer.getValue())
                .issueTime(new Date())
                .build();
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(metadataSigner.getSignerKey().getKeyID())
                .x509CertChain(List.of(certChain))
                .type(new JOSEObjectType(OPENIDVCI_ISSUER_METADATA_JWT_TYPE))
                .build();
            var jws = new SignedJWT(header, claims);
            jws.sign(metadataSigner.getSigner());
            return jws.serialize();
        } catch (JOSEException e) {
            throw new PidServerException("credential metadate could not be signed", e);
        }
    }

    @GetMapping(path = {"/.well-known/jwt-vc-issuer"}, produces = "application/json")
    SdJwtVcMetadata getJwtVcIssuerMetadataJSON() {
        var jwks = metadataService.getJWKs();
        if (jwks == null || jwks.isEmpty()) {
            throw new PidServerException("No certificate found");
        }
        Collection<Object> issuerJwks = new ArrayList<>();
        jwks.forEach(jwk -> issuerJwks.add(jwk.toJSONObject()));
        return new SdJwtVcMetadata(credentialIssuer.getValue(), new SdJwtVcMetadataKeys(issuerJwks));
    }
}
