package main

import "testing"

func TestBuildExportedConfigMasksSecretsByDefault(t *testing.T) {
	t.Parallel()

	p := persistedOptions{
		AccessKey: "ACCESS1234",
		SecretKey: "SECRET1234",
		Password:  "PASSWORD1234",
	}

	exported := buildExportedConfig(p, false)
	if exported.ContainsSecrets {
		t.Fatalf("expected containsSecrets to be false")
	}
	if !hasMaskedSecrets(exported.Config) {
		t.Fatalf("expected exported config to contain masked secrets")
	}
}

func TestBuildExportedConfigWithSecrets(t *testing.T) {
	t.Parallel()

	p := persistedOptions{
		AccessKey: "ACCESS1234",
		SecretKey: "SECRET1234",
		Password:  "PASSWORD1234",
	}

	exported := buildExportedConfig(p, true)
	if !exported.ContainsSecrets {
		t.Fatalf("expected containsSecrets to be true")
	}
	if hasMaskedSecrets(exported.Config) {
		t.Fatalf("did not expect masked secrets in full export")
	}
}
