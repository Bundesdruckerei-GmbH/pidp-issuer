/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.clientconfiguration;

import de.bdr.pidp.issuer.clientconfiguration.config.ClientConfiguration;
import org.springframework.stereotype.Service;

import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class ClientConfigurationService {

    private final Map<UUID, Set<X509Certificate>> clientAttestationCertsMap;
    private final Map<UUID, Set<X509Certificate>> keyAttestationCertsMap;
    private final List<UUID> keyAttestationAtTokenRequestDisabledClients;

    public ClientConfigurationService(ClientConfiguration configuration) throws CertificateException {
        if (configuration.isProcessRealData()) {
            throw new IllegalStateException("Process real-data is not supported");
        } else {
            clientAttestationCertsMap = loadLocallyConfiguredTrustAnchors(configuration.getClientAttestationCert());
            keyAttestationCertsMap = loadLocallyConfiguredTrustAnchors(configuration.getKeyAttestationCert());
            keyAttestationAtTokenRequestDisabledClients = configuration.getKeyAttestationAtTokenRequestDisabledClients();
        }
    }

    private Map<UUID, Set<X509Certificate>> loadLocallyConfiguredTrustAnchors(Map<UUID, List<String>> configuration) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        return configuration.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey,
            entry ->
                entry.getValue().stream().map(certString -> {
                        try {
                            var is = getClass().getClassLoader().getResourceAsStream(certString);
                            return (X509Certificate) cf.generateCertificate(is);
                        } catch (CertificateException e) {
                            throw new ClientConfigurationInitException("Failed initializing ClientConfigurationService, error at certificate for clientId " + entry.getKey(), e);
                        }
                    }
                ).collect(Collectors.toUnmodifiableSet())
        ));
    }

    public boolean isValidClientId(UUID clientId) {
        return clientAttestationCertsMap.containsKey(clientId);
    }

    public Set<X509Certificate> getClientAttestationCerts(UUID clientId) {
        return clientAttestationCertsMap.get(clientId);
    }

    public Set<X509Certificate> getKeyAttestationCerts(UUID clientId) {
        return keyAttestationCertsMap.get(clientId);
    }

    public Set<String> getDisabledKeyAttestationClientsForTokenRequest() {
        return keyAttestationAtTokenRequestDisabledClients.stream().map(UUID::toString).collect(Collectors.toSet());
    }
}
