
// // Server-side handler
// func (fm *FileManager) handleIncomingStream(stream libp2pnetwork.Stream) {
// 	defer stream.Close()

// 	// Read request
// 	msg, err := utils.ReadMessage(stream)
// 	if err != nil {
// 		utils.WriteMessage(stream, &utils.Message{
// 			Type:  utils.ErrorResponse,
// 			Error: "Failed to read request",
// 		})
// 		return
// 	}

// 	// Decrypt the file
// 	key, key_err := fm.cryptoMgr.GetKeyForFile(msg.Hash)
// 	if key_err != nil {
// 		utils.WriteMessage(stream, &utils.Message{
// 			Type:  utils.ErrorResponse,
// 			Error: "No decryption key found",
// 		})
// 	}

// 	filePath := filepath.Join(fm.sharedDir, msg.Hash)
// 	outputFilePath := filepath.Join(fm.incomingDir, msg.Filename)
// 	if err := fm.cryptoMgr.DecryptFile(filePath, outputFilePath, key); err != nil {
// 		log.Printf("Error decrypting file: %v", err)
// 		return
// 	}

// 	// Send success response
// 	utils.WriteMessage(stream, &utils.Message{
// 		Type: utils.FileResponse,
// 	})

// 	file, err := os.Open(outputFilePath)
// 	if err != nil {
// 		utils.WriteMessage(stream, &utils.Message{
// 			Type:  utils.ErrorResponse,
// 			Error: "File not found",
// 		})
// 		return
// 	}
// 	defer file.Close()

// 	// Send file data
// 	io.Copy(stream, file)

// }

// func (fm *FileManager) handleFileDownload(stream libp2pnetwork.Stream, metadata *FileMetadata) error {
// 	// Send file hash request
// 	if err := utils.WriteMessage(stream, &utils.Message{
// 		Type:     utils.RequestFile,
// 		Hash:     metadata.Hash,
// 		Filename: metadata.Name,
// 	}); err != nil {
// 		return fmt.Errorf("failed to send file request: %w", err)
// 	}

// 	// Read response header
// 	response, err := utils.ReadMessage(stream)
// 	if err != nil {
// 		return fmt.Errorf("failed to read response: %w", err)
// 	}
// 	if response.Type == utils.ErrorResponse {
// 		return fmt.Errorf("server error: %s", response.Error)
// 	}

// 	// Create and write file
// 	filePath := filepath.Join(fm.incomingDir, metadata.Name)
// 	file, err := os.Create(filePath)
// 	if err != nil {
// 		return fmt.Errorf("failed to create file: %w", err)
// 	}
// 	defer file.Close()

// 	writer := bufio.NewWriter(file)
// 	if _, err := io.Copy(writer, stream); err != nil {
// 		return fmt.Errorf("failed to write file: %w", err)
// 	}

// 	return writer.Flush()
// }

// func (fm *FileManager) ShareFileKademlia(ctx context.Context, filePath string) error {
// 	fileInfo, err := os.Stat(filePath)
// 	if os.IsNotExist(err) {
// 		return ErrFileNotFound
// 	}

// 	filename := filepath.Base(filePath)

// 	// Handle file sharing similar to original implementation
// 	tempFile := filepath.Join(os.TempDir(), fmt.Sprintf("%s.encrypted", filename))
// 	defer os.Remove(tempFile)
// 	aes_key, key_err := fm.cryptoMgr.GenerateSymmetricKey()
// 	if key_err != nil {
// 		return fmt.Errorf("failed to generate symmetric key: %w", err)
// 	}
// 	if err := fm.cryptoMgr.EncryptFile(filePath, tempFile, aes_key); err != nil {
// 		return fmt.Errorf("failed to encrypt file: %w", err)
// 	}

// 	encryptedCopyPath := filepath.Join("shared", fmt.Sprintf("%s.enc", filename))
// 	if err := utils.CopyFile(tempFile, encryptedCopyPath); err != nil {
// 		return fmt.Errorf("failed to save encrypted file: %w", err)
// 	}

// 	// Generate the file hash and rename the file to the hash
// 	fileHash, err := utils.GenerateFileHash(encryptedCopyPath)
// 	if err != nil {
// 		return fmt.Errorf("failed to generate file hash: %w", err)
// 	}

// 	// Rename the encrypted file to its hash
// 	renamedFilePath := filepath.Join("shared", fileHash)
// 	if err := os.Rename(encryptedCopyPath, renamedFilePath); err != nil {
// 		return fmt.Errorf("failed to rename encrypted file: %w", err)
// 	}

// 	// Store the key using the hash
// 	fm.cryptoMgr.StoreKeyForFile(fileHash, aes_key)

// 	key := fmt.Sprintf("/files/%s", fileHash)
// 	metadata := &FileMetadata{
// 		Name:     filename,
// 		Hash:     fileHash,
// 		Size:     fileInfo.Size(),
// 		SharerID: fm.host.ID().String(),
// 	}

// 	hashedKey, err := utils.HashKey(fileHash)
// 	if err != nil {
// 		log.Printf("Error hashing key %s: %v", key, err)
// 		return fmt.Errorf("failed to hash key: %w", err)
// 	}

// 	if err := fm.storeToDHT(ctx, hashedKey, metadata); err != nil {
// 		return fmt.Errorf("failed to store metadata in DHT: %w", err)
// 	}

// 	fmt.Printf("File %s shared successfully, with hash: %s\n", filename, fileHash)

// 	return nil
// }

// func (fm *FileManager) FindAndDownloadFile(ctx context.Context, fileHash string) error {
// 	key := fmt.Sprintf("/files/%s", fileHash)
// 	metadata, err := fm.getFromDHT(ctx, key)
// 	if err != nil {
// 		return fmt.Errorf("failed to get metadata from DHT: %w", err)
// 	}

// 	sharerID, err := peer.Decode(metadata.SharerID)
// 	if err != nil {
// 		return fmt.Errorf("invalid sharer ID: %w", err)
// 	}

// 	// Connect to the file sharer
// 	if err := fm.host.Connect(ctx, peer.AddrInfo{ID: sharerID}); err != nil {
// 		return fmt.Errorf("failed to connect to sharer: %w", err)
// 	}

// 	// Download the file using existing mechanism
// 	stream, err := fm.host.NewStream(ctx, sharerID, protocolID)
// 	if err != nil {
// 		return fmt.Errorf("failed to open stream: %w", err)
// 	}
// 	defer stream.Close()

// 	return fm.handleFileDownload(stream, metadata)
// }

// func (fm *FileManager) getFromDHT(ctx context.Context, fileHash string) (*FileMetadata, error) {
// 	dhtKey, err := utils.HashKey(fileHash)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create DHT key: %w", err)
// 	}

// 	value, err := fm.dht.GetValue(ctx, dhtKey)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to retrieve from DHT: %w", err)
// 	}

// 	metadata := &FileMetadata{}
// 	if err := metadata.Unmarshal(value); err != nil {
// 		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
// 	}

// 	return metadata, nil
// }

// func (fm *FileManager) storeToDHT(ctx context.Context, key string, metadata *FileMetadata) error {
// 	// Ensure the DHT is available
// 	if fm.dht == nil {
// 		log.Println("Error: DHT not initialized")
// 		return fmt.Errorf("DHT not initialized")
// 	}

// 	log.Printf("Starting to marshal metadata for key: %s", key)
// 	// Marshal the metadata
// 	value, err := metadata.Marshal()
// 	if err != nil {
// 		log.Printf("Error marshaling metadata for key %s: %v", key, err)
// 		return fmt.Errorf("failed to marshal metadata: %w", err)
// 	}
// 	log.Printf("Successfully marshaled metadata for key: %s", key)

// 	// Store the value in the DHT
// 	log.Printf("Attempting to store value in DHT for key: %s", key)
// 	if err := fm.dht.PutValue(ctx, key, value); err != nil {
// 		log.Printf("Error storing value in DHT for key %s: %v", key, err)
// 		return fmt.Errorf("failed to store value in DHT: %w", err)
// 	}
// 	log.Printf("Successfully stored value in DHT for key: %s", key)

// 	return nil
// }
// end of snippet