--
-- Copyright 2024-2026 Bundesdruckerei GmbH
-- For the license see the accompanying file LICENSE.MD.
--

CREATE TABLE IF NOT EXISTS auth_session
(
    session_id                          BIGINT NOT NULL CONSTRAINT auth_session_PK PRIMARY KEY,

    access_token_id                     VARCHAR,
    authorization_code                  VARCHAR,
    authorization_code_expiration_time  TIMESTAMP WITH TIME ZONE,
    client_id                           VARCHAR,
    code_challenge                      VARCHAR,
    code_challenge_method               VARCHAR,
    dpop_nonce                          VARCHAR,
    dpop_nonce_expiration_time          TIMESTAMP WITH TIME ZONE,
    seed_credential_data                TEXT,
    seed_credential_ref                 VARCHAR,
    seed_credential_sub                 VARCHAR,
    seed_credential_expiration_time     TIMESTAMP WITH TIME ZONE,
    issuer_state                        VARCHAR,
    redirect_uri                        VARCHAR,
    refresh_token_id                    VARCHAR,
    request_uri                         VARCHAR,
    request_uri_expiration_time         TIMESTAMP WITH TIME ZONE,
    scope                               VARCHAR,
    state                               VARCHAR,
    next_expected_request               VARCHAR,

    expires                             TIMESTAMP WITH TIME ZONE NOT NULL,
    created                             TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS auth_session_access_token_id_idx ON auth_session (access_token_id);
CREATE INDEX IF NOT EXISTS auth_session_authorization_code_idx ON auth_session (authorization_code);
CREATE INDEX IF NOT EXISTS auth_session_request_uri_idx ON auth_session (request_uri);
CREATE INDEX IF NOT EXISTS auth_session_refresh_token_id_idx ON auth_session (refresh_token_id);
CREATE INDEX IF NOT EXISTS auth_session_issuer_state_idx ON auth_session (issuer_state);
CREATE INDEX IF NOT EXISTS auth_session_seed_credential_ref_idx ON auth_session (seed_credential_ref);
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE auth_session TO ${APP_USER};
