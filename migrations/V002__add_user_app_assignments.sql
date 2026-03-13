CREATE TABLE user_app_assignments (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    app_id TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    assigned_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    PRIMARY KEY (user_id, app_id)
);

CREATE INDEX idx_user_app_assignments_user ON user_app_assignments(user_id);
CREATE INDEX idx_user_app_assignments_app ON user_app_assignments(app_id);
