--
-- Copyright 2024-2025 Bundesdruckerei GmbH
-- For the license see the accompanying file LICENSE.MD.
--

CREATE SEQUENCE IF NOT EXISTS hibernate_sequence START WITH 1 INCREMENT BY 1;
GRANT USAGE on SEQUENCE hibernate_sequence TO ${APP_USER};

CREATE TABLE IF NOT EXISTS eid_session (
    id BIGINT NOT NULL,
    authentication_state VARCHAR(20) NOT NULL,
    session_id VARCHAR(255) NOT NULL,
    saml_id VARCHAR(255),
    reference_id VARCHAR(255),
    token_id VARCHAR(255) NOT NULL,
    external_id VARCHAR(255),
    created TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    valid_until TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    redirect_url VARCHAR(1024),
    CONSTRAINT eid_session_PK PRIMARY KEY (id),
    UNIQUE (session_id),
    UNIQUE (saml_id)
);
CREATE INDEX IF NOT EXISTS vu_index ON eid_session(valid_until);
CREATE INDEX IF NOT EXISTS vu_as_index ON eid_session(valid_until, authentication_state);
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE eid_session TO ${APP_USER};

CREATE TABLE IF NOT EXISTS pidi_session (
    id BIGINT NOT NULL,
    flow VARCHAR(2),
    session TEXT,
    authorization_code VARCHAR(128),
    issuer_state VARCHAR(128),
    request_uri VARCHAR(128),
    access_token VARCHAR(128),
    next_expected_request VARCHAR(64),
    refresh_token_digest VARCHAR(128),
    created TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT timezone('utc', now()),
    expires TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    pid_issuer_session_id VARCHAR(128),
    CONSTRAINT pidi_session_PK PRIMARY KEY (id)
);
COMMENT ON COLUMN pidi_session.session IS 'The json representation of the session';
CREATE INDEX IF NOT EXISTS authorization_code_index ON pidi_session(authorization_code);
CREATE INDEX IF NOT EXISTS issuer_state_index ON pidi_session(issuer_state);
CREATE INDEX IF NOT EXISTS request_uri_index ON pidi_session(request_uri);
CREATE INDEX IF NOT EXISTS access_token_index ON pidi_session(access_token);
CREATE INDEX IF NOT EXISTS refresh_token_digest_index ON pidi_session(refresh_token_digest);
CREATE INDEX IF NOT EXISTS pid_issuer_session_id_index ON pidi_session (pid_issuer_session_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE pidi_session TO ${APP_USER};

CREATE TABLE IF NOT EXISTS pidi_nonce (
    id BIGINT NOT NULL,
    nonce VARCHAR(36) NOT NULL,
    expires TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN DEFAULT FALSE NOT NULL,
    CONSTRAINT pidi_nonce_PK PRIMARY KEY (id),
    UNIQUE (nonce)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE pidi_nonce TO ${APP_USER};

CREATE TABLE IF NOT EXISTS pin_retry_counter (
    id BIGINT NOT NULL,
    digest VARCHAR(128) NOT NULL,
    value INTEGER NOT NULL,
    expires TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT retry_counter_PK PRIMARY KEY (id),
    UNIQUE (digest)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE pin_retry_counter TO ${APP_USER};

CREATE TABLE IF NOT EXISTS c_nonce (
    id BIGINT NOT NULL,
    nonce VARCHAR(36) NOT NULL,
    expires TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT c_nonce_PK PRIMARY KEY (id),
    UNIQUE (nonce));
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE c_nonce TO ${APP_USER};
