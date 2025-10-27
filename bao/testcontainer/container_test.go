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
