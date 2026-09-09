/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.server.servlet.context.ServletComponentScan;
import org.springframework.retry.annotation.EnableRetry;

@EnableRetry
@SpringBootApplication
@ServletComponentScan
public class PidpIssuerApplication {
    static void main(String[] args) {
        SpringApplication.run(PidpIssuerApplication.class, args);
    }
}
