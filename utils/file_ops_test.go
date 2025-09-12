package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileExists(t *testing.T) {
	tempDir := t.TempDir()
	existingFile := filepath.Join(tempDir, "existing.txt")
	nonExistentFile := filepath.Join(tempDir, "nonexistent.txt")

	file, err := os.Create(existingFile)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	file.Close()

	if !FileExists(existingFile) {
		t.Fatal("FileExists returned false for existing file")
	}

	if FileExists(nonExistentFile) {
		t.Fatal("FileExists returned true for non-existent file")
	}
}

func TestSaveAndLoadPEMRoundtrip(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "roundtrip.pem")

	testData := []byte(`-----BEGIN TEST-----
VGVzdCBkYXRhIGZvciByb3VuZHRyaXAgdGVzdA==
-----END TEST-----`)

	err := SavePEMToFile(testData, testFile)
	if err != nil {
		t.Fatalf("Failed to save PEM: %v", err)
	}

	loadedData, err := LoadPEMFromFile(testFile)
	if err != nil {
		t.Fatalf("Failed to load PEM: %v", err)
	}

	if string(testData) != string(loadedData) {
		t.Fatal("PEM data changed during save/load roundtrip")
	}
}

func TestSaveToInvalidDirectory(t *testing.T) {
	testData := []byte("test data")

	err := SavePEMToFile(testData, "/invalid/directory/file.pem")
	if err == nil {
		t.Fatal("Expected error when saving to invalid directory")
	}
}

func TestLoadNonExistentFile(t *testing.T) {
	_, err := LoadPEMFromFile("/non/existent/path/file.pem")
	if err == nil {
		t.Fatal("Expected error when loading non-existent file")
	}
}

func TestFilePermissions(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "permissions.pem")

	testData := []byte("test data with specific permissions")

	err := SavePEMToFile(testData, testFile)
	if err != nil {
		t.Fatalf("Failed to save PEM: %v", err)
	}

	info, err := os.Stat(testFile)
	if err != nil {
		t.Fatalf("Failed to get file info: %v", err)
	}

	if info.Mode().Perm() != 0600 {
		t.Fatalf("Expected file permissions 0600, got %v", info.Mode().Perm())
	}
}
