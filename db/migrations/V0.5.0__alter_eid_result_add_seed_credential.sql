--
-- Copyright 2024-2026 Bundesdruckerei GmbH
-- For the license see the accompanying file LICENSE.MD.
--

ALTER TABLE IF EXISTS eid_result ADD COLUMN IF NOT EXISTS seed_credential TEXT;
