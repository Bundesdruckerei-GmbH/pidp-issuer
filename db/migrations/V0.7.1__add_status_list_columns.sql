--
-- Copyright 2024-2026 Bundesdruckerei GmbH
-- For the license see the accompanying file LICENSE.MD.
--

ALTER TABLE auth_session
    ADD COLUMN IF NOT EXISTS client_attestation_status_list_ref_uri VARCHAR,
    ADD COLUMN IF NOT EXISTS client_attestation_status_list_ref_index INT;
