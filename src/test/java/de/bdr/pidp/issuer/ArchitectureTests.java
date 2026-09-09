/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer;

import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;
import org.jmolecules.archunit.JMoleculesArchitectureRules;
import org.jmolecules.archunit.JMoleculesDddRules;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.modulith.core.ApplicationModules;
import org.springframework.modulith.docs.Documenter;

import static org.assertj.core.api.Assertions.assertThat;

@AnalyzeClasses(packages = "de.bdr.pidp.issuer")
class ArchitectureTests {
    @ArchTest
    ArchRule dddRules = JMoleculesDddRules.all();
    @ArchTest
    ArchRule hexagonal = JMoleculesArchitectureRules.ensureHexagonal();

    @Disabled("currently spring-modulith could not be started in spring boot 4.0")
    @Test
    void verifyModules() {
        ApplicationModules.of(PidpIssuerApplication.class).verify();
    }

    @Disabled("currently spring-modulith could not be started in spring boot 4.0")
    @Test
    void writeDocumentationSnippets() {

        var modules = ApplicationModules.of(PidpIssuerApplication.class);
        assertThat(modules).isNotNull();
        new Documenter(modules)
                .writeModulesAsPlantUml()
                .writeIndividualModulesAsPlantUml()
                .writeModuleCanvases();
    }
}
