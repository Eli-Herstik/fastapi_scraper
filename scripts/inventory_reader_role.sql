-- Read-only role for the inventory service (gatekeeper-inventory repo).
--
--   psql -U postgres -d gatekeeper -v pw="'choose-a-real-password'" \
--        -f scripts/inventory_reader_role.sql
--
-- Not an alembic migration on purpose: migration history is committed to the repo and
-- must never carry credentials, and role/grant management is a deployment concern that
-- differs per environment.
--
-- Why this exists: the inventory service vendors a copy of the ORM
-- (contrib/inventory_schema.py), which means a second codebase now holds SQLAlchemy
-- models of these tables and is technically capable of calling create_all() or writing
-- to them. This role makes that structurally impossible rather than merely discouraged.
-- tests/integration/test_inventory_reader_role.py asserts the boundary holds.

CREATE ROLE inventory_reader LOGIN PASSWORD :'pw';

GRANT CONNECT ON DATABASE gatekeeper TO inventory_reader;
GRANT USAGE ON SCHEMA public TO inventory_reader;

-- Exactly the 3 tables the two endpoints read. Note the omissions: `scans` and
-- `scan_events` are not readable, and no INSERT/UPDATE/DELETE is granted anywhere.
GRANT SELECT ON apps, submissions, findings TO inventory_reader;

-- Belt and braces. A fresh role gets no table privileges implicitly, but PUBLIC has
-- historically carried schema-level rights, and future tables must not be readable by
-- default either.
REVOKE CREATE ON SCHEMA public FROM inventory_reader;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM inventory_reader;
