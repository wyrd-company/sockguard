package cmd

import (
	"net/http"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
)

// TestForkCommandContainerEndpointsReadExfiltrationAck pins which
// command-container routes in docs/fork-endpoints.md need the top-level
// insecure_allow_read_exfiltration acknowledgment before a client profile may
// allow them. Each case allows one route and nothing else.
func TestForkCommandContainerEndpointsReadExfiltrationAck(t *testing.T) {
	tests := []struct {
		method  string
		path    string
		needAck bool
	}{
		{http.MethodPost, "/containers/*/attach", true},
		{http.MethodPost, "/containers/*/wait", false},
		{http.MethodPut, "/containers/*/archive", false},
		{http.MethodGet, "/containers/*/archive", true},
	}
	for _, tt := range tests {
		for _, ack := range []bool{false, true} {
			cfg := config.Defaults()
			cfg.InsecureAllowReadExfiltration = ack
			cfg.Clients.Profiles = []config.ClientProfileConfig{{
				Name: "workload",
				Rules: []config.RuleConfig{
					{Match: config.MatchConfig{Method: tt.method, Path: tt.path}, Action: "allow"},
				},
			}}
			_, err := compileClientProfiles(&cfg)
			if wantErr := tt.needAck && !ack; (err != nil) != wantErr {
				t.Errorf("%s %s with acknowledgment=%v: error = %v, want error %v", tt.method, tt.path, ack, err, wantErr)
			}
		}
	}
}
