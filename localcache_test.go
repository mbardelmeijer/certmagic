// Copyright 2015 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certmagic

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/mholt/acmez/v3/acme"
	"golang.org/x/crypto/ocsp"
)

func testLocalCacheConfig(t *testing.T) (*Config, *ACMEIssuer, *recordingStorage, *FileStorage) {
	t.Helper()
	am := &ACMEIssuer{CA: "https://example.com/acme/directory"}
	storage := &recordingStorage{Storage: &FileStorage{Path: t.TempDir()}}
	localCache := &FileStorage{Path: t.TempDir()}
	cfg := &Config{
		Issuers:   []Issuer{am},
		Storage:   storage,
		Logger:    defaultTestLogger,
		certCache: new(Cache),
	}
	am.config = cfg
	return cfg, am, storage, localCache
}

func testCertResource(issuer Issuer, domain string) CertificateResource {
	return CertificateResource{
		SANs:           []string{domain},
		PrivateKeyPEM:  []byte("private key"),
		CertificatePEM: []byte("certificate"),
		IssuerData:     mustJSON(acme.Certificate{URL: "https://example.com/cert"}),
		issuerKey:      issuer.IssuerKey(),
	}
}

func TestLocalCache(t *testing.T) {
	ctx := context.Background()
	const domain = "example.com"

	cfg, am, storage, localCache := testLocalCacheConfig(t)
	cfg.LocalCache = localCache
	certKey := StorageKeys.SiteCert(am.IssuerKey(), domain)

	err := cfg.saveCertResource(ctx, am, testCertResource(am, domain))
	if err != nil {
		t.Fatalf("Expected no error saving cert resource, got: %v", err)
	}

	// saving writes through to the local cache, so serving the
	// certificate afterwards should not need storage at all
	storage.calls = nil
	certRes, err := cfg.loadCertResource(ctx, am, domain, cfg.cachedStorage())
	if err != nil {
		t.Fatalf("Expected no error loading cert resource, got: %v", err)
	}
	if string(certRes.CertificatePEM) != "certificate" {
		t.Errorf("Expected 'certificate', got: %s", certRes.CertificatePEM)
	}
	if len(storage.calls) > 0 {
		t.Errorf("Expected no storage calls, got: %v", storage.calls)
	}

	// as if another instance renewed the certificate
	err = storage.Store(ctx, certKey, []byte("renewed certificate"))
	if err != nil {
		t.Fatalf("Expected no error storing renewed certificate, got: %v", err)
	}

	// cluster-sensitive loads see storage, and refresh the local cache
	certRes, err = cfg.loadCertResource(ctx, am, domain, cfg.groundTruthStorage())
	if err != nil {
		t.Fatalf("Expected no error loading cert resource, got: %v", err)
	}
	if string(certRes.CertificatePEM) != "renewed certificate" {
		t.Errorf("Expected 'renewed certificate', got: %s", certRes.CertificatePEM)
	}
	cached, err := localCache.Load(ctx, certKey)
	if err != nil {
		t.Fatalf("Expected no error loading from local cache, got: %v", err)
	}
	if string(cached) != "renewed certificate" {
		t.Errorf("Expected local cache to be refreshed, got: %s", cached)
	}

	// deleting the site assets evicts them from the local cache too
	err = cfg.deleteSiteAssets(ctx, am.IssuerKey(), domain)
	if err != nil {
		t.Fatalf("Expected no error deleting site assets, got: %v", err)
	}
	if localCache.Exists(ctx, certKey) {
		t.Errorf("Expected %s to be gone from the local cache", certKey)
	}
}

func TestLocalCacheOCSPStaple(t *testing.T) {
	ctx := context.Background()
	now := time.Now().Add(-1 * time.Hour)

	issuerCert, issuerKey, issuerPEM := mustIssueTestCertificate(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test issuer"},
		NotBefore:             now,
		NotAfter:              now.Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil, nil)

	issuedCert, issuedKey, issuedPEM := mustIssueTestCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "cached.example"},
		DNSNames:     []string{"cached.example"},
		NotBefore:    now,
		NotAfter:     now.Add(30 * 24 * time.Hour),
		OCSPServer:   []string{"http://ocsp.example.test"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, issuerCert, issuerKey)

	issuedKeyPEM, err := PEMEncodePrivateKey(issuedKey)
	if err != nil {
		t.Fatalf("Expected no error encoding private key, got: %v", err)
	}
	bundle := append(append([]byte{}, issuedPEM...), issuerPEM...)

	response, err := ocsp.CreateResponse(issuerCert, issuerCert, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: issuedCert.SerialNumber,
		ThisUpdate:   now.UTC(),
		NextUpdate:   now.Add(24 * time.Hour).UTC(),
	}, issuerKey)
	if err != nil {
		t.Fatalf("Expected no error creating OCSP response, got: %v", err)
	}
	responder := startOCSPResponder(t, map[string][]byte{
		issuedCert.SerialNumber.String(): response,
	})
	t.Cleanup(responder.Close)

	cfg, _, storage, localCache := testLocalCacheConfig(t)
	cfg.LocalCache = localCache
	cfg.OCSP = OCSPConfig{
		ResponderOverrides: map[string]string{"http://ocsp.example.test": responder.URL},
	}

	// the first staple comes from the responder, and is written to both
	cert, err := makeCertificate(issuedPEM, issuedKeyPEM)
	if err != nil {
		t.Fatalf("Expected no error making certificate, got: %v", err)
	}
	err = stapleOCSP(ctx, cfg.OCSP, cfg.cachedStorage(), &cert, bundle)
	if err != nil {
		t.Fatalf("Expected no error stapling OCSP, got: %v", err)
	}
	if !bytes.Equal(cert.Certificate.OCSPStaple, response) {
		t.Fatal("Expected OCSP response to be stapled to certificate")
	}

	// stapling the same certificate again is served from the local cache
	storage.calls = nil
	cert, err = makeCertificate(issuedPEM, issuedKeyPEM)
	if err != nil {
		t.Fatalf("Expected no error making certificate, got: %v", err)
	}
	err = stapleOCSP(ctx, cfg.OCSP, cfg.cachedStorage(), &cert, bundle)
	if err != nil {
		t.Fatalf("Expected no error stapling OCSP, got: %v", err)
	}
	if !bytes.Equal(cert.Certificate.OCSPStaple, response) {
		t.Error("Expected OCSP response to be stapled from the local cache")
	}
	if len(storage.calls) > 0 {
		t.Errorf("Expected no storage calls, got: %v", storage.calls)
	}
}

func TestWarmLocalCache(t *testing.T) {
	ctx := context.Background()
	const domain = "example.com"

	cfg, am, storage, localCache := testLocalCacheConfig(t)

	// no local cache yet, so this only writes to storage
	err := cfg.saveCertResource(ctx, am, testCertResource(am, domain))
	if err != nil {
		t.Fatalf("Expected no error saving cert resource, got: %v", err)
	}
	if err = cfg.WarmLocalCache(ctx, domain); err == nil {
		t.Error("Expected an error warming without a local cache, got none")
	}

	cfg.LocalCache = localCache
	err = cfg.WarmLocalCache(ctx, domain)
	if err != nil {
		t.Fatalf("Expected no error warming local cache, got: %v", err)
	}

	storage.calls = nil
	_, err = cfg.loadCertResource(ctx, am, domain, cfg.cachedStorage())
	if err != nil {
		t.Fatalf("Expected no error loading cert resource, got: %v", err)
	}
	if len(storage.calls) > 0 {
		t.Errorf("Expected no storage calls after warming, got: %v", storage.calls)
	}

	// warming a certificate that isn't in storage must not be silently ignored
	err = cfg.WarmLocalCache(ctx, "not-in-storage.example.com")
	if err == nil {
		t.Error("Expected an error warming an unknown domain, got none")
	}
}
