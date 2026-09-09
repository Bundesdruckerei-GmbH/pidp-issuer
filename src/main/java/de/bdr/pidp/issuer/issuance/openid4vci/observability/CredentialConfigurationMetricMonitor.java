/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.observability;

import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.EnumMap;
import java.util.Map;
import java.util.stream.Collectors;

@NullMarked
@Component
public class CredentialConfigurationMetricMonitor {

    private final Map<CredentialConfigurationID, Counter> counters;
    private final Counter unknownCounter;

    public CredentialConfigurationMetricMonitor(MeterRegistry meterRegistry) {
        counters = new EnumMap<>(
            Arrays.stream(CredentialConfigurationID.values()).collect(
                Collectors.toMap(
                    (CredentialConfigurationID id) -> id,
                    (CredentialConfigurationID id) -> Counter.builder("credential.configuration.usage")
                        .tag("id", id.getName())
                        .register(meterRegistry)
                )
            )
        );
        unknownCounter = Counter.builder("credential.configuration.unknown")
            .register(meterRegistry);
    }

    public void recordUsage(String idValue) {
        CredentialConfigurationID.getCredentialConfigurationID(idValue)
            .ifPresentOrElse(
                this::recordUsage,
                this::recordUnknown
            );
    }

    public void recordUsage(CredentialConfigurationID id) {
        counters.get(id).increment();
    }

    public void recordUnknown() {
        unknownCounter.increment();
    }
}
