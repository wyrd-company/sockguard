// relationships:
//
//	references: [../../../docs/content/docs/buildkit-llb-bridge, ../../../docs/fork-endpoints]
package cmd

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
)

// Only protobuf length-delimited fields are needed here. Field numbers come
// from internal/buildkitproto/control/control.pb.go (BuildKit v0.18.2).
func forkFieldProtoString(field uint64, value string) []byte {
	b := binary.AppendUvarint(nil, field<<3|2)
	b = binary.AppendUvarint(b, uint64(len(value)))
	return append(b, value...)
}

func forkFieldGRPCFrame(payload []byte) []byte {
	frame := make([]byte, 5, len(payload)+5)
	binary.BigEndian.PutUint32(frame[1:], uint32(len(payload)))
	return append(frame, payload...)
}

func TestForkFieldBuildkitProfileAndOuterSolve(t *testing.T) {
	cfg := config.Defaults()
	cfg.Upstream.Socket = shortSocketPath(t, "field-buildkit")
	cfg.Upstream.Flavor = "docker"
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false
	cfg.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: "POST", Path: "/grpc"}, Action: "allow"}}
	for _, name := range []string{"builder", "reader"} {
		body := config.RequestBodyConfig{}
		body.Buildkit.Control.Solve.Allow = true
		body.Buildkit.Control.Solve.AllowedExporters = []string{"moby", "image"}
		body.Buildkit.LLBBridge.AllowUninspectedPassthrough = name == "builder"
		cfg.Clients.Profiles = append(cfg.Clients.Profiles, config.ClientProfileConfig{Name: name, Rules: cfg.Rules, RequestBody: body})
	}
	cfg.Clients.SourceIPProfiles = []config.ClientSourceIPProfileAssignmentConfig{{Profile: "builder", CIDRs: []string{"192.0.2.0/24"}}, {Profile: "reader", CIDRs: []string{"198.51.100.0/24"}}}
	if err := config.Validate(&cfg); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var seen []forkFieldCall
	startH2CDaemonStub(t, cfg.Upstream.Socket, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		mu.Lock()
		seen = append(seen, forkFieldCall{r.Method, r.URL.Path, string(body)})
		mu.Unlock()
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
		w.WriteHeader(200)
		_, _ = w.Write(forkFieldGRPCFrame(nil))
	}))
	rules, err := compileRuleConfigsForTest(cfg.Rules)
	if err != nil {
		t.Fatal(err)
	}
	handler := buildServeHandler(t, &cfg, newDiscardLogger(), nil, rules, newServeTestDeps())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = r.Header.Get("X-Test-Remote-Addr")
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	check := func(t *testing.T, remote, rpc string, payload []byte, want int) {
		t.Helper()
		mu.Lock()
		seen = nil
		mu.Unlock()
		code, response := forkFieldBuildkitCall(t, addr, remote, rpc, payload)
		mu.Lock()
		calls := append([]forkFieldCall(nil), seen...)
		mu.Unlock()
		if code != want {
			t.Fatalf("BuildKit policy status=%d want=%d calls=%v", code, want, calls)
		}
		if want != 0 {
			if len(calls) != 0 {
				t.Fatalf("denied BuildKit RPC forwarded: %v", calls)
			}
			return
		}
		if response != string(forkFieldGRPCFrame(nil)) {
			t.Fatalf("BuildKit forwarded response=%x want=%x", response, forkFieldGRPCFrame(nil))
		}
		if len(calls) != 1 || calls[0].uri != rpc || !bytes.Equal([]byte(calls[0].body), payload) {
			t.Fatalf("BuildKit forwarded bytes/calls=%v want path=%s bytes=%x", calls, rpc, payload)
		}
	}
	const ping = "/moby.buildkit.v1.frontend.LLBBridge/Ping"
	for _, remote := range []string{"192.0.2.10:4000", "198.51.100.10:4000"} {
		t.Run(remote, func(t *testing.T) {
			want := 7
			if remote == "192.0.2.10:4000" {
				want = 0
			}
			check(t, remote, ping, forkFieldGRPCFrame([]byte("sample-opaque-payload")), want)
		})
	}
	const solve = "/moby.buildkit.v1.Control/Solve"
	base := func(ref string) []byte {
		return append(forkFieldProtoString(1, ref), forkFieldProtoString(5, "sample-session")...)
	}
	attr := func(value string) string {
		return string(append(forkFieldProtoString(1, "name"), forkFieldProtoString(2, value)...))
	}
	exporter := func(typ, value string) string {
		return string(append(forkFieldProtoString(1, typ), forkFieldProtoString(2, attr(value))...))
	}
	for _, tc := range []struct {
		name  string
		extra []byte
		want  int
	}{
		{"plain", nil, 0},
		{"security_insecure", forkFieldProtoString(9, "security.insecure"), 7},
		{"host_network", forkFieldProtoString(9, "network.host"), 7},
		{"exporter_equal", append(append(forkFieldProtoString(13, exporter("moby", "sample")), forkFieldProtoString(3, "moby")...), forkFieldProtoString(4, attr("sample"))...), 0},
		{"exporter_type_mismatch", append(append(forkFieldProtoString(13, exporter("moby", "sample")), forkFieldProtoString(3, "image")...), forkFieldProtoString(4, attr("sample"))...), 9},
		{"exporter_attrs_mismatch", append(append(forkFieldProtoString(13, exporter("moby", "sample")), forkFieldProtoString(3, "moby")...), forkFieldProtoString(4, attr("other"))...), 9},
		{"deprecated_without_modern", forkFieldProtoString(3, "moby"), 9},
		{"deprecated_equals_second", append(append(append(forkFieldProtoString(13, exporter("moby", "sample")), forkFieldProtoString(13, exporter("image", "sample"))...), forkFieldProtoString(3, "image")...), forkFieldProtoString(4, attr("sample"))...), 9},
	} {
		t.Run(tc.name, func(t *testing.T) {
			check(t, "192.0.2.10:4000", solve, forkFieldGRPCFrame(base(tc.name+"-control")), 0)
			payload := append(base(tc.name), tc.extra...)
			check(t, "192.0.2.10:4000", solve, forkFieldGRPCFrame(payload), tc.want)
		})
	}
}
