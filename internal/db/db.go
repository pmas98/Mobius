package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

// FileMapping represents a mapping of a hash to a local file path.
type FileMapping struct {
	ID       int64
	Hash     string
	FilePath string
}

// Database wraps the SQL database.
type Database struct {
	db *sql.DB
}

// InitializeDB initializes the database and creates the necessary table.
func InitializeDB(filePath string) (*Database, error) {
	log.Println("Initializing database at path:", filePath)

	// Check if the database file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Println("Database file does not exist, creating a new one...")
	} else {
		log.Println("Database file exists, opening the existing database...")
	}

	// Open the database file (creates it if it doesn't exist)
	db, err := sql.Open("sqlite3", filePath)
	if err != nil {
		log.Printf("Error opening database: %v\n", err)
		return nil, fmt.Errorf("error opening database: %v", err)
	}

	// Create the file_mapping table if it doesn't already exist
	query := `
		CREATE TABLE IF NOT EXISTS file_mapping (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			hash TEXT NOT NULL UNIQUE,
			file_path TEXT NOT NULL
		);
	`
	if _, err := db.Exec(query); err != nil {
		log.Printf("Error creating table: %v\n", err)
		return nil, fmt.Errorf("error creating table: %v", err)
	}

	log.Println("Database initialized successfully.")
	return &Database{db: db}, nil
}

// AddFileMapping adds a new hash-to-file mapping to the database.
func (d *Database) AddFileMapping(hash, filePath string) error {
	query := "INSERT INTO file_mapping (hash, file_path) VALUES (?, ?)"
	_, err := d.db.Exec(query, hash, filePath)
	if err != nil {
		log.Printf("Error adding file mapping: %v\n", err)
		return fmt.Errorf("error adding file mapping: %w", err)
	}
	return nil
}

// GetFilePath retrieves the file path corresponding to a hash.
func (d *Database) GetFilePath(hash string) (string, error) {
	query := "SELECT file_path FROM file_mapping WHERE hash = ?"
	var filePath string
	err := d.db.QueryRow(query, hash).Scan(&filePath)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("hash not found: %s", hash)
	}
	if err != nil {
		log.Printf("Error retrieving file path: %v\n", err)
		return "", fmt.Errorf("error retrieving file path: %w", err)
	}
	return filePath, nil
}

func (d *Database) ValidateFileMappings() {
	log.Println("Validating file mappings...")

	rows, err := d.db.Query("SELECT id, file_path FROM file_mapping")
	if err != nil {
		log.Printf("Error querying file mappings: %v\n", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var id int64
		var filePath string
		if err := rows.Scan(&id, &filePath); err != nil {
			log.Printf("Error scanning row: %v\n", err)
			continue
		}

		// Check if the file exists
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			log.Printf("File not found for ID %d, path: %s. Removing entry...\n", id, filePath)
			// Delete the invalid entry
			_, err := d.db.Exec("DELETE FROM file_mapping WHERE id = ?", id)
			if err != nil {
				log.Printf("Error deleting file mapping ID %d: %v\n", id, err)
			}
		}
	}
	log.Println("File mapping validation completed.")
}

// Close closes the database connection.
func (d *Database) Close() error {
	return d.db.Close()
}
