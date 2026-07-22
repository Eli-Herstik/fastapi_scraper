-- Separate database for the integration suite, which TRUNCATEs every table between
-- tests. Keeping it distinct from `gatekeeper` means a misconfigured TEST_DATABASE_URL
-- cannot wipe development data.
CREATE DATABASE gatekeeper_test;
