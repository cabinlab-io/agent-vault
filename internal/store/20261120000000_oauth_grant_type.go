package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		return db.Exec(`ALTER TABLE credential_oauth ADD COLUMN grant_type TEXT NOT NULL DEFAULT 'authorization_code' CHECK (grant_type IN ('authorization_code','client_credentials'))`).Error
	})
}
