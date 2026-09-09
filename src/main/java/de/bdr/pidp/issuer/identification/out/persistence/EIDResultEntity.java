/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.out.persistence;

import jakarta.annotation.Nullable;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Getter
@Setter
@Entity
@Table(name = "eid_result")
public class EIDResultEntity {
    @Id
    @Size(max = 255)
    @NotNull
    @Column(name = "external_id", nullable = false)
    private String externalId;

    @Nullable
    @Size(max = 255)
    @Column(name = "error")
    private String error;

    @NotNull
    @Column(name = "expires", nullable = false)
    private Instant expires;

    @Nullable
    @Column(name = "seed_credential", length = Integer.MAX_VALUE)
    private String seedCredential;

    @Nullable
    @Column(name = "jti")
    private String jti;

    @Nullable
    @Column(name = "sub")
    private String sub;

    @Nullable
    @Column(name = "exp")
    private Instant exp;
}
