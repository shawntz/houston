-- Add icon_url (app logo/icon image) and launch_url (template URL with variable substitution)
ALTER TABLE apps ADD COLUMN icon_url TEXT;
ALTER TABLE apps ADD COLUMN launch_url TEXT;
