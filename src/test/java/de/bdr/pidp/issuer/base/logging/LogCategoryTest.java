/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.logging;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Isolated;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
@ExtendWith(OutputCaptureExtension.class)
@Isolated
class LogCategoryTest {

    @ParameterizedTest
    @EnumSource(LogCategory.Value.class)
    void logWithLogType(LogCategory.Value logType, CapturedOutput output) {
        try (var _ = LogCategory.mdcContext(logType)) {
            log.info("log category test");
        }
        log.info("log category test");

        assertThat(output).containsOnlyOnce("bop.app.category=" + logType.getName());
        assertThat(StringUtils.countMatches(output, "log category test")).isEqualTo(2);
    }
}
