/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.out.rs;

import java.net.URI;
import java.time.Instant;
import java.util.List;

record BatchCredentialInfoRef(String pidMasterTokenID, List<CredentialInfoRef> credentialList) { }

record CredentialInfoRef(Instant expiration, TokenStatusListRef tokenStatusListRef) { }

record TokenStatusListRef(URI uri, int index) { }
