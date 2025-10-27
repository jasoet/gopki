package vault

// Integration functions for type conversion between Vault and GoPKI will be implemented in Phase 1.
//
// Planned functions:
// - VaultCertToGoPKI(vaultCert *VaultCertificate) (*cert.Certificate, error)
// - GoPKICertToVault(c *cert.Certificate) (*VaultCertificate, error)
// - GoPKIKeyToVault[T keypair.KeyPair](keyPair T) (*VaultKey, error)
// - VaultKeyToGoPKI[T keypair.KeyPair](vaultKey *VaultKey) (T, error)
// - ExtractPrivateKey(resp *IssueResponse) (keypair.PrivateKey, error)
// - PEMChainToGoPKI(pemChain string) ([]*cert.Certificate, error)
// - GoPKIToPEMChain(certs []*cert.Certificate) (string, error)
