--
-- Copyright 2024-2025 Bundesdruckerei GmbH
-- For the license see the accompanying file LICENSE.MD.
--

DROP TABLE IF EXISTS pidi_nonce;
DROP TABLE IF EXISTS pin_retry_counter;
ALTER TABLE IF EXISTS pidi_session DROP COLUMN IF EXISTS flow;
