package db

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

// InitializeDB initializes a SQLite database
func InitializeDB(filePath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", filePath)
	if err != nil {
		return nil, err
	}

	// Create necessary tables
	createTableQuery := `
	CREATE TABLE IF NOT EXISTS shared_files (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		file_name TEXT NOT NULL,
		recipient_id TEXT NOT NULL,
		encrypted_key BLOB NOT NULL
	);`
	if _, err := db.Exec(createTableQuery); err != nil {
		return nil, err
	}

	log.Println("Database initialized")
	return db, nil
}
