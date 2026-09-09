/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.MalformedURLException;
import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;

class AuthorizationConfigurationTest {

    private Validator validator;

    @BeforeEach
    void setUp() {
        try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
            validator = factory.getValidator();
        }
    }

    @DisplayName("Verify baseUrl constraint checks")
    @ValueSource(strings = {"http://localhost", "https://demo.pidi.localhost"})
    @ParameterizedTest
    void test001(String baseUrl) throws MalformedURLException {
        var config = new AuthorizationConfiguration();
        config.setBaseUrl(URI.create(baseUrl).toURL());

        var violations = validator.validate(config);
        assertThat(violations).isEmpty();
    }
}
