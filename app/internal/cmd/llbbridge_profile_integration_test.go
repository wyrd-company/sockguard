package cmd

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"golang.org/x/net/http2"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/upstream"
)

// startH2CDaemonStub listens on socketPath and, per connection, answers the
// h2c upgrade with 101 and then serves handler over h2c, standing in for
// buildkitd behind POST /grpc.
func startH2CDaemonStub(t *testing.T, socketPath string, handler http.Handler) {
	t.Helper()
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen %s: %v", socketPath, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				req, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return
				}
				_ = req.Body.Close()
				if _, err := io.WriteString(conn, "HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"); err != nil {
					return
				}
				//nolint:staticcheck // SA1019: the same h2c stub the buildkitproxy tests use for buildkitd
				(&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{Handler: handler})
			}(conn)
		}
	}()
}

// bufferedNetConn reads through the bufio.Reader that consumed the 101
// response, so that no h2c bytes it buffered are lost.
type bufferedNetConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedNetConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// llbBridgeCallStatus upgrades POST /grpc on proxyAddr as a client from
// remoteAddr, sends one LLBBridge/Ping, and returns its gRPC status code.
func llbBridgeCallStatus(t *testing.T, proxyAddr, remoteAddr string) int {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	upgrade := "POST /grpc HTTP/1.1\r\nHost: docker\r\nConnection: Upgrade\r\nUpgrade: h2c\r\nX-Test-Remote-Addr: " + remoteAddr + "\r\nContent-Length: 0\r\n\r\n"
	if _, err := io.WriteString(conn, upgrade); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("upgrade status = %d, want 101; body: %s", resp.StatusCode, body)
	}

	//nolint:staticcheck // SA1019: an h2c client over the upgraded connection, as the BuildKit client does
	cc, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(&bufferedNetConn{Conn: conn, r: br})
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}
	t.Cleanup(func() { _ = cc.Close() })

	req, err := http.NewRequest(http.MethodPost, "http://buildkitd/moby.buildkit.v1.frontend.LLBBridge/Ping", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/grpc")
	grpcResp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	_, _ = io.Copy(io.Discard, grpcResp.Body)
	_ = grpcResp.Body.Close()
	status := grpcResp.Header.Get("Grpc-Status")
	if status == "" {
		status = grpcResp.Trailer.Get("Grpc-Status")
	}
	code, err := strconv.Atoi(status)
	if err != nil {
		t.Fatalf("Grpc-Status %q is not an integer", status)
	}
	return code
}

// The passthrough follows the profile a client is assigned to: profile
// "builder" sets it, profile "reader" does not, and both allow Solve.
func TestBuildkitMediatorLLBBridgePassthroughIsPerProfile(t *testing.T) {
	cfg := config.Defaults()
	cfg.Upstream.Socket = shortSocketPath(t, "llbbridge-upstream")
	solveOnly := config.BuildkitRequestBodyConfig{
		Control: config.BuildkitControlRequestBodyConfig{Solve: config.BuildkitSolveRequestBodyConfig{Allow: true}},
	}
	withPassthrough := solveOnly
	withPassthrough.LLBBridge.AllowUninspectedPassthrough = true
	cfg.Clients.Profiles = []config.ClientProfileConfig{
		{Name: "builder", RequestBody: config.RequestBodyConfig{Buildkit: withPassthrough}},
		{Name: "reader", RequestBody: config.RequestBodyConfig{Buildkit: solveOnly}},
	}
	cfg.Clients.SourceIPProfiles = []config.ClientSourceIPProfileAssignmentConfig{
		{Profile: "builder", CIDRs: []string{"192.0.2.0/24"}},
		{Profile: "reader", CIDRs: []string{"198.51.100.0/24"}},
	}

	var daemonCalls atomic.Int32
	startH2CDaemonStub(t, cfg.Upstream.Socket, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		daemonCalls.Add(1)
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
		w.WriteHeader(http.StatusOK)
	}))

	resolver := upstream.NewSingleSocket(cfg.Upstream.Socket)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("a BuildKit tunnel fell through to the plain proxy")
		w.WriteHeader(http.StatusTeapot)
	})
	handler := withClientACL(&cfg, resolver, newDiscardLogger())(
		withBuildkitMediator(&cfg, resolver, newDiscardLogger())(next),
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = r.Header.Get("X-Test-Remote-Addr")
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	proxyAddr := srv.Listener.Addr().String()

	if code := llbBridgeCallStatus(t, proxyAddr, "198.51.100.10:4000"); code != 7 {
		t.Fatalf("reader profile: LLBBridge/Ping Grpc-Status = %d, want 7 (PERMISSION_DENIED)", code)
	}
	if got := daemonCalls.Load(); got != 0 {
		t.Fatalf("reader profile: daemon calls = %d, want 0", got)
	}
	if code := llbBridgeCallStatus(t, proxyAddr, "192.0.2.10:4000"); code != 0 {
		t.Fatalf("builder profile: LLBBridge/Ping Grpc-Status = %d, want 0", code)
	}
	if got := daemonCalls.Load(); got != 1 {
		t.Fatalf("builder profile: daemon calls = %d, want 1", got)
	}
}
