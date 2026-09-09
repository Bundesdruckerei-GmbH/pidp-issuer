/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.doc.in;

import de.bdr.pidp.issuer.doc.core.QrCodeService;
import org.jmolecules.architecture.hexagonal.PrimaryAdapter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

@PrimaryAdapter
@Controller
@RequestMapping("/")
public class UiController {
    private static final String SCHEME_OPENID_CREDENTIAL_OFFER = "openid-credential-offer";
    private static final String QUERY_PARAM_CREDENTIAL_OFFER = "credential_offer";

    private static final String PID_SD_JWT = "pid-sd-jwt";
    private static final String SD_JWT_URI = "sdJwtUri";
    private static final String SD_JWT_QR = "sdJwtQr";

    private static final String PID_MSO_MDOC = "pid-mso-mdoc";
    private static final String MSO_MDOC_URI = "msoMdocUri";
    private static final String MSO_MDOC_QR = "msoMdocQr";
    private static final String CREDENTIAL_CONFIGURATION_ID_DOCS = "credentialConfigurationIdDocs";
    private static final String SUPPORTED_CONFIGURATION_IDS = "supportedConfigurationIds";
    private static final String MODEL_KEY_BASE_URL = "baseUrl";

    @Value("${pidi.base-url}")
    private String baseUrl;
    @Value("${info.app.version:unknown}")
    private String version;

    @Value("${pidi.issuance.supported-configuration-ids}")
    private List<String> supportedConfigurationIds;

    @Value("#{credentialConfigurationDocParser.parse('${pidi.doc.credential-configuration-ids}')}")
    private List<CredentialConfigurationDoc> credentialConfigurationIdDocs;

    @Value("${external-links.legal-notice}")
    private String legalNotice;
    @Value("${external-links.privacy-terms}")
    private String privacyTerms;
    @Value("${external-links.pid-signer-certificate}")
    private String pidSignerCertificate;
    @Value("${external-links.status-list-signer-certificate}")
    private String statusListSignerCertificate;

    private final QrCodeService qrCodeService;

    public UiController(QrCodeService qrCodeService) {
        this.qrCodeService = qrCodeService;
    }

    @GetMapping()
    public String getIndexView() {
        return "index";
    }

    @GetMapping("issuance-flow")
    public String issuanceFlow(Model model) throws IOException {
        URI sdJwtUri = generateUri(PID_SD_JWT);
        URI msoMdocUri = generateUri(PID_MSO_MDOC);
        model.addAllAttributes(Map.of(
                SD_JWT_URI, sdJwtUri.toString(),
                SD_JWT_QR, toPngDataUrl(qrCodeService.generateQrCode(sdJwtUri.toString(), 250)),
                MSO_MDOC_URI, msoMdocUri.toString(),
                MSO_MDOC_QR, toPngDataUrl(qrCodeService.generateQrCode(msoMdocUri.toString(), 250)),
                MODEL_KEY_BASE_URL, baseUrl));

        return "issuance-flow";
    }

    @GetMapping("sdjwt")
    public String sdJwt() {
        return "sdjwt";
    }

    @GetMapping("msomdoc")
    public String msoMdoc() {
        return "msomdoc";
    }

    @GetMapping("releases")
    public String releases() {
        return "releases";
    }

    @GetMapping("license")
    public String license() {
        return "license";
    }

    // disabled for PIDP-4359 Remove privacy terms
    //    @GetMapping("privacy-terms")
    //    public String privacy() {
    //        return "privacy";
    //    }

    @GetMapping("credential-configuration-changelog")
    public String credentialConfigurationChangelog(Model model) {

        model.addAllAttributes(Map.of(
            SUPPORTED_CONFIGURATION_IDS, supportedConfigurationIds,
            CREDENTIAL_CONFIGURATION_ID_DOCS, credentialConfigurationIdDocs
        ));

        return "credential-config-log";
    }

    @GetMapping("credential-configuration-ids")
    public String credentialcredentialConfigurationIDs() {
        return "credential-configuration-ids";
    }

    @GetMapping("credential-claims")
    public String credentialClaims() {
        return "credential-claims";
    }

    @GetMapping("error")
    public String error() {
        return "error";
    }

    @ModelAttribute("version")
    public String version() {
        return version;
    }

    @ModelAttribute("legalNotice")
    public String legalNotice() {
        return legalNotice;
    }

    @ModelAttribute("privacyTerms")
    public String privacyTerms() {
        return privacyTerms;
    }

    @ModelAttribute("pidSignerCertificate")
    public String pidSignerCertificate() { return pidSignerCertificate; }

    @ModelAttribute("statusListSignerCertificate")
    public String statusListSignerCertificate() { return statusListSignerCertificate; }

    private URI generateUri(String credentialDataType) {
        return URI.create(SCHEME_OPENID_CREDENTIAL_OFFER + "://?" +
                QUERY_PARAM_CREDENTIAL_OFFER + "=" +
                URLEncoder.encode("{\"credential_issuer\":\"" + baseUrl + "\"," +
                        "\"credential_configuration_ids\":[\"" + credentialDataType + "\"],\"grants\":{\"authorization_code\":{}}}", StandardCharsets.UTF_8)
        );
    }

    private String toPngDataUrl(BufferedImage image) throws IOException {
        try (var bytes = new ByteArrayOutputStream()) {
            ImageIO.write(image, "png", bytes);
            var imageAsBase64 = Base64.getEncoder().encodeToString(bytes.toByteArray());
            return "data:image/png;base64," + imageAsBase64;
        }
    }
}
