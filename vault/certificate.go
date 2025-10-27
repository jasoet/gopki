package vault

// Certificate operations (issue, sign, retrieve) will be implemented in Phase 1.
//
// Planned functions:
// - IssueCertificate(ctx context.Context, role string, opts *IssueOptions) (*cert.Certificate, error)
// - IssueCertificateWithKeyPair[T keypair.KeyPair](ctx context.Context, role string, keyPair T, opts *IssueOptions) (*cert.Certificate, error)
// - SignCSR(ctx context.Context, role string, csr *cert.CertificateSigningRequest, opts *SignOptions) (*cert.Certificate, error)
// - GetCertificate(ctx context.Context, serial string) (*cert.Certificate, error)
// - ListCertificates(ctx context.Context) ([]string, error)
