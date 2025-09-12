package utils

import (
	"io/ioutil"
	"os"
)

// SavePEMToFile saves PEM data to a file with secure permissions (0600)
func SavePEMToFile(pemData []byte, filename string) error {
	return ioutil.WriteFile(filename, pemData, 0600)
}

// LoadPEMFromFile loads PEM data from a file
func LoadPEMFromFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

// FileExists checks if a file exists at the given path
func FileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}