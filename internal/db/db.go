package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	_ "github.com/mattn/go-sqlite3"
)

type FileMetadata struct {
	ID            int64
	Filename      string
	hash          string
	PeerID        string
	FileSize      int
	EncryptionKey string
	Timestamp     time.Time
}

type Database struct {
	db *sql.DB
}

type Peer struct {
	ID        string
	UserName  string
	Address   string
	PublicKey string
	AddrInfo  *peer.AddrInfo
}

var ErrFileNotFound = fmt.Errorf("file not found")
var ErrDatabaseOperation = fmt.Errorf("database operation error")

// InitializeDB initializes the database, creating it if it doesn't exist
func InitializeDB(filePath string) (*Database, error) {
	log.Println("Initializing database... on path:", filePath)
	// Check if the database file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Println("Database file does not exist, creating a new one...")

		// Database file does not exist, create it
		db, err := sql.Open("sqlite3", filePath)
		if err != nil {
			log.Printf("Error opening database: %v\n", err)
			return nil, fmt.Errorf("error opening database: %v", err)
		}

		// Create necessary tables
		createTableQueries := []string{
			`CREATE TABLE IF NOT EXISTS file_metadata (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				filename TEXT NOT NULL,
				peer_id TEXT NOT NULL,
				file_size INTEGER NOT NULL,
				encryption_key TEXT NOT NULL,
				timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
			);`,
			`CREATE TABLE IF NOT EXISTS file_versions (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				file_id INTEGER,
				version INTEGER,
				hash TEXT NOT NULL,
				FOREIGN KEY(file_id) REFERENCES file_metadata(id)
			);`,
			`CREATE TABLE IF NOT EXISTS peers (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				address TEXT NOT NULL,
				last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				name TEXT
			);

			);`,
		}

		for _, query := range createTableQueries {
			log.Printf("Executing query: %s\n", query)
			if _, err := db.Exec(query); err != nil {
				log.Printf("Error executing query '%s': %v\n", query, err)
				return nil, fmt.Errorf("error executing query '%s': %v", query, err)
			}
			log.Printf("Query executed successfully: %s\n", query)
		}

		log.Println("Database initialized successfully.")
		return &Database{db: db}, nil
	} else {
		log.Println("Database file exists, opening the existing database...")

		// Database file exists, just open it
		db, err := sql.Open("sqlite3", filePath)
		if err != nil {
			log.Printf("Error opening existing database: %v\n", err)
			return nil, fmt.Errorf("error opening existing database: %v", err)
		}

		log.Println("Database opened successfully. Proceeding with existing database.")
		return &Database{db: db}, nil
	}
}

// StoreFileMetadata inserts file metadata and initializes the file version in the database
func StoreFileMetadata(database *Database, filename, peerID, encryptionKey string, fileSize int, hash string) error {
	// Start a transaction
	tx, err := database.db.Begin()
	if err != nil {
		return fmt.Errorf("error starting transaction: %v", err)
	}

	// Insert file metadata
	stmt, err := tx.Prepare("INSERT INTO file_metadata(filename, peer_id, file_size, encryption_key) VALUES(?, ?, ?, ?)")
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("error preparing insert statement for file_metadata: %v", err)
	}
	defer stmt.Close()

	result, err := stmt.Exec(filename, peerID, fileSize, encryptionKey)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("error executing insert statement for file_metadata: %v", err)
	}

	// Get the ID of the inserted file metadata
	fileID, err := result.LastInsertId()
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("error getting last insert ID: %v", err)
	}

	// Insert initial file version
	versionStmt, err := tx.Prepare("INSERT INTO file_versions(file_id, version, hash) VALUES(?, ?, ?)")
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("error preparing insert statement for file_versions: %v", err)
	}
	defer versionStmt.Close()

	_, err = versionStmt.Exec(fileID, 1, hash) // Initial version is 1
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("error executing insert statement for file_versions: %v", err)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("error committing transaction: %v", err)
	}

	return nil
}

// GetFileMetadata retrieves file metadata by filename
func (d *Database) GetFileMetadata(filename string) (*FileMetadata, error) {
	query := `
		SELECT id, filename, peer_id, file_size, encryption_key, timestamp 
		FROM file_metadata 
		WHERE filename = ?
	`

	var metadata FileMetadata
	err := d.db.QueryRow(query, filename).Scan(
		&metadata.ID,
		&metadata.Filename,
		&metadata.PeerID,
		&metadata.FileSize,
		&metadata.EncryptionKey,
		&metadata.Timestamp,
	)

	if err == sql.ErrNoRows {
		return nil, ErrFileNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDatabaseOperation, err)
	}

	return &metadata, nil
}

// db/peers.go
func (db *Database) GetPeers() ([]*Peer, error) {
	log.Println("Starting query to fetch peers from the database...")

	rows, err := db.db.Query("SELECT id, address FROM peers")
	if err != nil {
		log.Printf("Error querying peers: %v", err)
		return nil, fmt.Errorf("failed to query peers: %w", err)
	}
	defer rows.Close()

	var peers []*Peer
	for rows.Next() {
		var peer Peer
		if err := rows.Scan(&peer.ID, &peer.Address); err != nil {
			log.Printf("Error scanning peer: %v", err)
			return nil, fmt.Errorf("failed to scan peer: %w", err)
		}
		log.Printf("Successfully scanned peer with ID: %s", peer.ID)
		peers = append(peers, &peer)
	}

	if err := rows.Err(); err != nil {
		log.Printf("Error iterating over rows: %v", err)
		return nil, fmt.Errorf("failed to iterate over rows: %w", err)
	}

	log.Printf("Successfully fetched %d peers", len(peers))

	return peers, nil
}

func (db *Database) GetPeer(address string) (*Peer, error) {
	row := db.db.QueryRow("SELECT id, address FROM peers WHERE address = ?", address)

	var peer Peer
	if err := row.Scan(&peer.ID, &peer.Address, &peer.PublicKey); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no peer found with address: %s", address)
		}
		return nil, fmt.Errorf("failed to scan peer: %w", err)
	}

	return &peer, nil
}

func (d *Database) AddPeer(peerID, name string) error {
	_, err := d.db.Exec("INSERT INTO peers (name, address, last_seen) VALUES (?, ?, ?)", name, peerID, time.Now())
	return err
}

func (d *Database) RemovePeer(peerID string) error {
	_, err := d.db.Exec("DELETE FROM peers WHERE address = ?", peerID)
	return err
}
