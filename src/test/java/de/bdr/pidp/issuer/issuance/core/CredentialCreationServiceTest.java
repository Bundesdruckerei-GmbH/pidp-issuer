/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.core;

import com.nimbusds.jose.jwk.JWK;
import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.base.PidpServiceUnavailableException;
import de.bdr.pidp.issuer.base.jwt.StatusListRef;
import de.bdr.pidp.issuer.issuance.ConfigTestData;
import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import de.bdr.pidp.issuer.issuance.core.service.CredentialCreator;
import de.bdr.pidp.issuer.issuance.out.rs.PIDLifecycleAdapter;
import de.bdr.pidp.issuer.issuance.out.sls.StatusListAdapter;
import de.bdr.pidp.issuer.testdata.PidTestData;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CredentialCreationServiceTest {

    private static final String REFRESH_TOKEN_ID = UUID.randomUUID().toString();

    private static final CredentialConfigurationID supportedID = CredentialConfigurationID.SD_JWT_V1;
    private static final StatusListAdapter statusListAdapter = mock(StatusListAdapter.class);
    private static final CredentialCreator credentialCreator = mock(CredentialCreator.class);
    private static final PIDLifecycleAdapter pidLifecycleAdapter = mock(PIDLifecycleAdapter.class);

    private static CredentialCreationService subject;

    @Captor
    ArgumentCaptor<List<StatusListRef>> statusListCaptor;
    private AutoCloseable closeable;

    @BeforeAll
    void beforeAll() {
        closeable = MockitoAnnotations.openMocks(this);
        Map<CredentialConfigurationID, CredentialCreator> creators = Map.of(
            supportedID, credentialCreator
        );
        subject = new CredentialCreationService(statusListAdapter, creators, pidLifecycleAdapter, ConfigTestData.ISSUANCE_CONFIG);
    }

    @BeforeEach
    void setUp() {
        Mockito.reset(statusListAdapter, credentialCreator, pidLifecycleAdapter);
    }

    @AfterAll
    void afterAll() throws Exception {
        closeable.close();
    }

    @Test
    void createSingleCredential() {
        // Given
        var expectedCredential = "test-credential";
        var statusReferences = provideStatusReferences(1);

        when(statusListAdapter.acquireFreeIndices(1)).thenReturn(statusReferences);
        when(credentialCreator.create(any(), any(), any(), any())).thenReturn(expectedCredential);

        var bindingKeys = provideBindingKeys(1);
        var identityData = PidTestData.TEST_IDENTITY_DATA;

        // When
        var result = subject.buildCredentials(bindingKeys, identityData, supportedID, REFRESH_TOKEN_ID);

        // Then
        assertThat(result).hasSize(1);
        assertThat(result.getFirst()).isEqualTo(expectedCredential);
        verify(credentialCreator).create(any(), eq(bindingKeys.getFirst()), eq(statusReferences.getFirst()), any());
        verify(pidLifecycleAdapter).registerPIDs(eq(REFRESH_TOKEN_ID), any(), statusListCaptor.capture());
        assertThat(statusListCaptor.getValue()).hasSize(1);
    }

    @Test
    void createMultipleCredentials() {
        // Given
        int count = 3;
        var expectedCredentials = List.of("cred1", "cred2", "cred3");
        var statusReferences = provideStatusReferences(count);

        when(statusListAdapter.acquireFreeIndices(count)).thenReturn(statusReferences);
        when(credentialCreator.create(any(), any(), any(), any()))
            .thenReturn(expectedCredentials.get(0), expectedCredentials.get(1), expectedCredentials.get(2));

        var bindingKeys = provideBindingKeys(count);
        var identityData = PidTestData.TEST_IDENTITY_DATA;

        // When
        var result = subject.buildCredentials(bindingKeys, identityData, supportedID, REFRESH_TOKEN_ID);

        // Then
        assertThat(result).containsExactlyElementsOf(expectedCredentials);
        verify(credentialCreator).create(any(), eq(bindingKeys.get(0)), eq(statusReferences.get(0)), any());
        verify(credentialCreator).create(any(), eq(bindingKeys.get(1)), eq(statusReferences.get(1)), any());
        verify(credentialCreator).create(any(), eq(bindingKeys.get(2)), eq(statusReferences.get(2)), any());
        verify(pidLifecycleAdapter).registerPIDs(eq(REFRESH_TOKEN_ID), any(), statusListCaptor.capture());
        assertThat(statusListCaptor.getValue()).hasSize(count);
    }

    @Test
    void createCredentialsWithFewerStatusReferencesThanBindingKeys() {
        // Given
        int bindingKeyCount = 3;
        int statusRefCount = 2;
        var expectedCredentials = List.of("cred1", "cred2");
        var statusReferences = provideStatusReferences(statusRefCount);

        when(statusListAdapter.acquireFreeIndices(bindingKeyCount)).thenReturn(statusReferences);
        when(credentialCreator.create(any(), any(), any(), any()))
            .thenReturn(expectedCredentials.get(0), expectedCredentials.get(1));

        var bindingKeys = provideBindingKeys(bindingKeyCount);
        var identityData = PidTestData.TEST_IDENTITY_DATA;

        // When
        var result = subject.buildCredentials(bindingKeys, identityData, supportedID, REFRESH_TOKEN_ID);

        // Then
        assertThat(result).containsExactlyElementsOf(expectedCredentials);
        verify(credentialCreator).create(any(), eq(bindingKeys.get(0)), eq(statusReferences.get(0)), any());
        verify(credentialCreator).create(any(), eq(bindingKeys.get(1)), eq(statusReferences.get(1)), any());
        verify(pidLifecycleAdapter).registerPIDs(eq(REFRESH_TOKEN_ID), any(), statusListCaptor.capture());
        assertThat(statusListCaptor.getValue()).hasSize(statusRefCount);
    }

    @Test
    void createCredentialsWithFewerBindingKeysThanStatusReferences() {
        // Given
        int bindingKeyCount = 2;
        int statusRefCount = 3;
        var expectedCredentials = List.of("cred1", "cred2");
        var statusReferences = provideStatusReferences(statusRefCount);

        when(statusListAdapter.acquireFreeIndices(bindingKeyCount)).thenReturn(statusReferences.subList(0, bindingKeyCount));
        when(credentialCreator.create(any(), any(), any(), any()))
            .thenReturn(expectedCredentials.get(0), expectedCredentials.get(1));

        var bindingKeys = provideBindingKeys(bindingKeyCount);
        var identityData = PidTestData.TEST_IDENTITY_DATA;

        // When
        var result = subject.buildCredentials(bindingKeys, identityData, supportedID, REFRESH_TOKEN_ID);

        // Then
        assertThat(result).containsExactlyElementsOf(expectedCredentials);
        verify(credentialCreator).create(any(), eq(bindingKeys.get(0)), eq(statusReferences.get(0)), any());
        verify(credentialCreator).create(any(), eq(bindingKeys.get(1)), eq(statusReferences.get(1)), any());
        verify(pidLifecycleAdapter).registerPIDs(eq(REFRESH_TOKEN_ID), any(), statusListCaptor.capture());
        assertThat(statusListCaptor.getValue()).hasSize(bindingKeyCount);
    }

    @Test
    void createCredentialsWithUnsupportedCredentialConfiguration() {
        // Given
        var unsupportedID = CredentialConfigurationID.SD_JWT_V2;
        var bindingKeys = provideBindingKeys(1);
        var identityData = PidTestData.TEST_IDENTITY_DATA;

        // When/Then
        assertThatThrownBy(() -> subject.buildCredentials(bindingKeys, identityData, unsupportedID, REFRESH_TOKEN_ID))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("Credential creator not found for credential id " + unsupportedID);
    }

//    @Test
    @ParameterizedTest
    @ValueSource(classes = {PidServerException.class, PidpServiceUnavailableException.class})
    void createCredentialsFailsWhenRegistrationOfPidsFails(Class<? extends Exception> exceptionClass) {
        // Given
        var expectedCredential = "test-credential";
        var statusReferences = provideStatusReferences(1);

        when(statusListAdapter.acquireFreeIndices(1)).thenReturn(statusReferences);
        when(credentialCreator.create(any(), any(), any(), any())).thenReturn(expectedCredential);
        doThrow(exceptionClass).when(pidLifecycleAdapter).registerPIDs(eq(REFRESH_TOKEN_ID), any(), any());

        var bindingKeys = provideBindingKeys(1);
        var identityData = PidTestData.TEST_IDENTITY_DATA;

        // When/Then
        assertThatThrownBy(() -> subject.buildCredentials(bindingKeys, identityData, supportedID, REFRESH_TOKEN_ID))
            .isInstanceOf(exceptionClass);
    }

    private List<JWK> provideBindingKeys(int count) {
        return IntStream.range(0, count).mapToObj(_ -> mock(JWK.class)).toList();
    }

    private List<StatusReference> provideStatusReferences(int count) {
        return IntStream.range(0, count).mapToObj(i -> new StatusReference("stat-uri", i)).toList();
    }
}
