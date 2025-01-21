package db

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

// InitializeDB initializes a SQLite database and creates necessary tables
func InitializeDB(filePath string) (*sql.DB, error) {
	// Open the database
	db, err := sql.Open("sqlite3", filePath)
	if err != nil {
		return nil, err
	}

	// Create necessary tables
	createFileTableQuery := `
	CREATE TABLE IF NOT EXISTS file_metadata (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		filename TEXT NOT NULL,
		peer_id TEXT NOT NULL,
		file_size INTEGER NOT NULL,
		encryption_key TEXT NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	createFileVersionTableQuery := `
	CREATE TABLE IF NOT EXISTS file_versions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		file_id INTEGER,
		version INTEGER,
		hash TEXT NOT NULL,
		FOREIGN KEY(file_id) REFERENCES file_metadata(id)
	);`
	createPeersTableQuery := `
	CREATE TABLE IF NOT EXISTS peers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		address TEXT NOT NULL,
		last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);	
	`

	// Execute table creation queries
	if _, err := db.Exec(createFileTableQuery); err != nil {
		return nil, err
	}
	if _, err := db.Exec(createFileVersionTableQuery); err != nil {
		return nil, err
	}
	if _, err := db.Exec(createPeersTableQuery); err != nil {
		return nil, err
	}

	log.Println("Database initialized")
	return db, nil
}

// storeFileMetadata inserts file metadata into the database
func storeFileMetadata(db *sql.DB, filename, peerID, encryptionKey string, fileSize int) error {
	// Prepare the insert statement
	stmt, err := db.Prepare("INSERT INTO file_metadata(filename, peer_id, file_size, encryption_key) VALUES(?, ?, ?, ?)")
	if err != nil {
		return err // Return error instead of logging it
	}
	defer stmt.Close() // Ensure the prepared statement is closed

	// Execute the statement
	_, err = stmt.Exec(filename, peerID, fileSize, encryptionKey)
	if err != nil {
		return err // Return error instead of logging it
	}

	return nil
}
