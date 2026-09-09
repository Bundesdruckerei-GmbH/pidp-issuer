/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.core;

import org.jmolecules.architecture.hexagonal.SecondaryPort;

import java.util.Random;
@SecondaryPort
public interface RandomProvider {
    Random getSessionRng();
    Random getSamlRng();
}
