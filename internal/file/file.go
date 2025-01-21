package file

import (
	"io"
	"mobius/internal/crypto"
	"os"
)

// EncryptFile encrypts a file and writes it to the destination
func EncryptFile(srcPath, destPath string, key []byte) error {
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	destFile, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer destFile.Close()

	data, err := io.ReadAll(srcFile)
	if err != nil {
		return err
	}

	encryptedData, err := crypto.EncryptAES(key, data)
	if err != nil {
		return err
	}

	_, err = destFile.Write(encryptedData)
	return err
}
