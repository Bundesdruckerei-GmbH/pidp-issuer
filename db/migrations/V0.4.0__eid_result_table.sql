--
-- Copyright 2024-2025 Bundesdruckerei GmbH
-- For the license see the accompanying file LICENSE.MD.
--

CREATE TABLE IF NOT EXISTS eid_result (
    external_id VARCHAR(255) PRIMARY KEY,
    eid_data TEXT,
    error VARCHAR(255),
    expires TIMESTAMP WITHOUT TIME ZONE NOT NULL
);
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE eid_result TO ${APP_USER};
