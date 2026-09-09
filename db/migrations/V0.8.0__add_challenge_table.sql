--
-- Copyright 2024-2026 Bundesdruckerei GmbH
-- For the license see the accompanying file LICENSE.MD.
--

CREATE TABLE IF NOT EXISTS challenge
(
    id        BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY NOT NULL,
    challenge VARCHAR(44)                                     NOT NULL UNIQUE,
    expires   TIMESTAMP WITH TIME ZONE                        NOT NULL
);
CREATE INDEX IF NOT EXISTS challenge_idx ON challenge (challenge);
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE challenge TO ${APP_USER};
