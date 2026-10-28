package config

import (
	"slices"
	"strings"
	"testing"
)

// TestNetworkAllowedDriversDefaultsUnset pins the default: no list, so no
// driver check.
func TestNetworkAllowedDriversDefaultsUnset(t *testing.T) {
	cfg, err := LoadBytes(nil)
	if err != nil {
		t.Fatalf("LoadBytes(nil) = %v", err)
	}
	if got := cfg.RequestBody.Network.AllowedDrivers; len(got) != 0 {
		t.Fatalf("allowed_drivers = %v, want empty", got)
	}
}

// TestNetworkAllowedDriversLoadsAndCrossWires reads the key at the top level
// and in a client profile, and maps it into both the network and the
// container create filter options.
func TestNetworkAllowedDriversLoadsAndCrossWires(t *testing.T) {
	cfg, err := LoadBytes([]byte(`request_body:
  network:
    allowed_drivers: [bridge, overlay]
clients:
  profiles:
    - name: on
      request_body:
        network:
          allowed_drivers: [bridge]
    - name: off
      request_body:
        network:
          allow_attachable: false
`))
	if err != nil {
		t.Fatalf("LoadBytes = %v", err)
	}
	top := cfg.RequestBody.ToFilterOptions()
	if want := []string{"bridge", "overlay"}; !slices.Equal(top.Network.Drivers.AllowedDrivers, want) || !slices.Equal(top.ContainerCreate.NetworkDrivers.AllowedDrivers, want) {
		t.Fatalf("top-level network=%v container_create=%v, want %v in both", top.Network.Drivers.AllowedDrivers, top.ContainerCreate.NetworkDrivers.AllowedDrivers, want)
	}
	on := cfg.Clients.Profiles[0].RequestBody.ToFilterOptions()
	if want := []string{"bridge"}; !slices.Equal(on.Network.Drivers.AllowedDrivers, want) || !slices.Equal(on.ContainerCreate.NetworkDrivers.AllowedDrivers, want) {
		t.Fatalf(`profile "on" network=%v container_create=%v, want %v in both`, on.Network.Drivers.AllowedDrivers, on.ContainerCreate.NetworkDrivers.AllowedDrivers, want)
	}
	off := cfg.Clients.Profiles[1].RequestBody.ToFilterOptions()
	if len(off.Network.Drivers.AllowedDrivers) != 0 || len(off.ContainerCreate.NetworkDrivers.AllowedDrivers) != 0 {
		t.Fatalf(`profile "off" has allowed_drivers %v / %v, want none`, off.Network.Drivers.AllowedDrivers, off.ContainerCreate.NetworkDrivers.AllowedDrivers)
	}
}

// TestNetworkAllowedDriversEnvOverride reads the comma-separated env var.
func TestNetworkAllowedDriversEnvOverride(t *testing.T) {
	t.Setenv("SOCKGUARD_REQUEST_BODY_NETWORK_ALLOWED_DRIVERS", "bridge,overlay")
	cfg, err := Load("/nonexistent-so-defaults-and-env-only.yaml")
	if err != nil {
		t.Fatalf("Load = %v", err)
	}
	if got, want := cfg.RequestBody.Network.AllowedDrivers, []string{"bridge", "overlay"}; !slices.Equal(got, want) {
		t.Fatalf("allowed_drivers = %v, want %v", got, want)
	}
}

// TestNetworkAllowedDriversRejectsEmptyEntry: an empty entry is a config
// error, at the top level and in a profile.
func TestNetworkAllowedDriversRejectsEmptyEntry(t *testing.T) {
	for name, yaml := range map[string]string{
		"top level": "request_body:\n  network:\n    allowed_drivers: [bridge, \" \"]\n",
		"profile":   "clients:\n  profiles:\n    - name: p\n      request_body:\n        network:\n          allowed_drivers: [\"\"]\n",
	} {
		t.Run(name, func(t *testing.T) {
			err := loadAndValidateStructural(t, yaml)
			if err == nil || !strings.Contains(err.Error(), "network.allowed_drivers[") || !strings.Contains(err.Error(), "must not be empty") {
				t.Fatalf("LoadBytes error = %v, want an empty allowed_drivers entry error", err)
			}
		})
	}
}

// TestNetworkAllowedDriversRejectsLibpodKey: the libpod routes do not apply
// the list, so the key under libpod_network is a config error.
func TestNetworkAllowedDriversRejectsLibpodKey(t *testing.T) {
	for name, yaml := range map[string]string{
		"top level": "request_body:\n  libpod_network:\n    allowed_drivers: [bridge]\n",
		"profile":   "clients:\n  profiles:\n    - name: p\n      request_body:\n        libpod_network:\n          allowed_drivers: [bridge]\n",
	} {
		t.Run(name, func(t *testing.T) {
			err := loadAndValidateStructural(t, yaml)
			if err == nil || !strings.Contains(err.Error(), "libpod_network.allowed_drivers is not supported") {
				t.Fatalf("LoadBytes error = %v, want the libpod_network.allowed_drivers error", err)
			}
		})
	}
}

// loadAndValidateStructural loads yaml and returns its structural validation
// error. A load error fails the test, so the error comes from validation.
func loadAndValidateStructural(t *testing.T, yaml string) error {
	t.Helper()
	cfg, err := LoadBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadBytes = %v", err)
	}
	return ValidateStructural(cfg)
}

// TestNetworkAllowedDriversValidConfigPasses is the control for the two
// rejection tests: a valid list validates.
func TestNetworkAllowedDriversValidConfigPasses(t *testing.T) {
	if err := loadAndValidateStructural(t, "request_body:\n  network:\n    allowed_drivers: [bridge]\n"); err != nil {
		t.Fatalf("ValidateStructural = %v, want nil", err)
	}
}
