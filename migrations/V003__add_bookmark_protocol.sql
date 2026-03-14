-- Add 'bookmark' protocol support and bookmark_url column.
-- SQLite cannot alter CHECK constraints in-place, so we recreate the table.

PRAGMA foreign_keys = OFF;

CREATE TABLE apps_new (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    protocol TEXT NOT NULL CHECK (protocol IN ('oidc', 'saml', 'bookmark')),
    -- OIDC fields
    client_id TEXT UNIQUE,
    client_secret_hash TEXT,
    redirect_uris TEXT, -- JSON array
    -- SAML fields
    entity_id TEXT,
    acs_url TEXT,
    name_id_format TEXT DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    -- Bookmark fields
    bookmark_url TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

INSERT INTO apps_new (id, name, protocol, client_id, client_secret_hash, redirect_uris, entity_id, acs_url, name_id_format, bookmark_url, created_at, updated_at)
    SELECT id, name, protocol, client_id, client_secret_hash, redirect_uris, entity_id, acs_url, name_id_format, NULL, created_at, updated_at FROM apps;

DROP TABLE apps;
ALTER TABLE apps_new RENAME TO apps;

-- Recreate indexes
CREATE INDEX idx_apps_client_id ON apps(client_id);
CREATE INDEX idx_apps_entity_id ON apps(entity_id);

PRAGMA foreign_keys = ON;
