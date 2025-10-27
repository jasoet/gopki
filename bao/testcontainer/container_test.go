//go:build integration

package testcontainer_test

import (
	"context"
	"testing"
	"time"

	"github.com/jasoet/gopki/bao/testcontainer"
)

func TestStart(t *testing.T) {
	ctx := context.Background()

	container, err := testcontainer.Start(ctx, testcontainer.DefaultConfig())
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer container.Terminate(ctx)

	if container.Address == "" {
		t.Error("Address is empty")
	}

	if container.Token == "" {
		t.Error("Token is empty")
	}

	t.Logf("OpenBao running at: %s", container.Address)
	t.Logf("Root token: %s", container.Token)
}

func TestStart_CustomConfig(t *testing.T) {
	ctx := context.Background()

	cfg := &testcontainer.Config{
		Image:          "openbao/openbao:2.4.3",
		RootToken:      "custom-token",
		StartupTimeout: 90 * time.Second,
		DevMode:        true,
	}

	container, err := testcontainer.Start(ctx, cfg)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer container.Terminate(ctx)

	if container.Token != "custom-token" {
		t.Errorf("Token = %s, want custom-token", container.Token)
	}

	returnedCfg := container.Config()
	if returnedCfg.RootToken != "custom-token" {
		t.Errorf("Config.RootToken = %s, want custom-token", returnedCfg.RootToken)
	}
}

func TestStart_NilConfig(t *testing.T) {
	ctx := context.Background()

	container, err := testcontainer.Start(ctx, nil)
	if err != nil {
		t.Fatalf("Start() with nil config failed: %v", err)
	}
	defer container.Terminate(ctx)

	// Should use defaults
	if container.Token != "root-token" {
		t.Errorf("Token = %s, want root-token (default)", container.Token)
	}
}

func TestEnablePKI(t *testing.T) {
	ctx := context.Background()

	container, err := testcontainer.Start(ctx, testcontainer.DefaultConfig())
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer container.Terminate(ctx)

	// Enable PKI with default TTL
	err = container.EnablePKI(ctx, "pki", "")
	if err != nil {
		t.Fatalf("EnablePKI() failed: %v", err)
	}

	// Try enabling at another path with custom TTL
	err = container.EnablePKI(ctx, "pki-intermediate", "43800h")
	if err != nil {
		t.Fatalf("EnablePKI() at custom path failed: %v", err)
	}
}

func TestEnableKV(t *testing.T) {
	ctx := context.Background()

	container, err := testcontainer.Start(ctx, testcontainer.DefaultConfig())
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer container.Terminate(ctx)

	// Enable KV v2 (default)
	err = container.EnableKV(ctx, "kv", 0)
	if err != nil {
		t.Fatalf("EnableKV() v2 failed: %v", err)
	}

	// Enable KV v2 explicitly
	err = container.EnableKV(ctx, "secret", 2)
	if err != nil {
		t.Fatalf("EnableKV() v2 explicit failed: %v", err)
	}

	// Enable KV v1
	err = container.EnableKV(ctx, "kv-v1", 1)
	if err != nil {
		t.Fatalf("EnableKV() v1 failed: %v", err)
	}
}

func TestEnableTransit(t *testing.T) {
	ctx := context.Background()

	container, err := testcontainer.Start(ctx, testcontainer.DefaultConfig())
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer container.Terminate(ctx)

	err = container.EnableTransit(ctx, "transit")
	if err != nil {
		t.Fatalf("EnableTransit() failed: %v", err)
	}
}

func TestEnableDatabase(t *testing.T) {
	ctx := context.Background()

	container, err := testcontainer.Start(ctx, testcontainer.DefaultConfig())
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer container.Terminate(ctx)

	err = container.EnableDatabase(ctx, "database")
	if err != nil {
		t.Fatalf("EnableDatabase() failed: %v", err)
	}
}

func TestEnableSSH(t *testing.T) {
	ctx := context.Background()

	container, err := testcontainer.Start(ctx, testcontainer.DefaultConfig())
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer container.Terminate(ctx)

	err = container.EnableSSH(ctx, "ssh")
	if err != nil {
		t.Fatalf("EnableSSH() failed: %v", err)
	}
}

func TestEnableTOTP(t *testing.T) {
	ctx := context.Background()

	container, err := testcontainer.Start(ctx, testcontainer.DefaultConfig())
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer container.Terminate(ctx)

	err = container.EnableTOTP(ctx, "totp")
	if err != nil {
		t.Fatalf("EnableTOTP() failed: %v", err)
	}
}

func TestEnableMultipleEngines(t *testing.T) {
	ctx := context.Background()

	container, err := testcontainer.Start(ctx, testcontainer.DefaultConfig())
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer container.Terminate(ctx)

	// Enable multiple engines
	engines := []struct {
		name string
		fn   func() error
	}{
		{"PKI", func() error { return container.EnablePKI(ctx, "pki", "") }},
		{"KV", func() error { return container.EnableKV(ctx, "secret", 2) }},
		{"Transit", func() error { return container.EnableTransit(ctx, "transit") }},
		{"Database", func() error { return container.EnableDatabase(ctx, "database") }},
		{"SSH", func() error { return container.EnableSSH(ctx, "ssh") }},
		{"TOTP", func() error { return container.EnableTOTP(ctx, "totp") }},
	}

	for _, engine := range engines {
		t.Run(engine.name, func(t *testing.T) {
			if err := engine.fn(); err != nil {
				t.Errorf("Failed to enable %s: %v", engine.name, err)
			}
		})
	}
}

func TestWaitForHealthy(t *testing.T) {
	ctx := context.Background()

	container, err := testcontainer.Start(ctx, testcontainer.DefaultConfig())
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer container.Terminate(ctx)

	// Should be healthy quickly in dev mode
	err = container.WaitForHealthy(ctx, 30*time.Second)
	if err != nil {
		t.Fatalf("WaitForHealthy() failed: %v", err)
	}
}

func TestTerminate(t *testing.T) {
	ctx := context.Background()

	container, err := testcontainer.Start(ctx, testcontainer.DefaultConfig())
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	err = container.Terminate(ctx)
	if err != nil {
		t.Errorf("Terminate() failed: %v", err)
	}

	// Calling terminate again should not error
	err = container.Terminate(ctx)
	if err != nil {
		t.Errorf("Second Terminate() failed: %v", err)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := testcontainer.DefaultConfig()

	if cfg.Image != "openbao/openbao:2.4.3" {
		t.Errorf("Image = %s, want openbao/openbao:2.4.3", cfg.Image)
	}

	if cfg.RootToken != "root-token" {
		t.Errorf("RootToken = %s, want root-token", cfg.RootToken)
	}

	if cfg.Port != "8200/tcp" {
		t.Errorf("Port = %s, want 8200/tcp", cfg.Port)
	}

	if cfg.StartupTimeout != 60*time.Second {
		t.Errorf("StartupTimeout = %v, want 60s", cfg.StartupTimeout)
	}

	if !cfg.DevMode {
		t.Error("DevMode = false, want true")
	}
}
