/*
relationships:

	references: [upgrade.go]
*/
package buildkitproxy

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// These declarations have the pinned SDK's actual successful-write shape and
// order. Session identifiers and authentication payloads are not fixture data.
func producerSessionAdvertisement() []string {
	return []string{
		"/moby.filesync.v1.FileSync/DiffCopy",
		"/moby.filesync.v1.FileSync/TarStream",
		"/moby.filesync.v1.Auth/FetchToken",
		"/moby.filesync.v1.Auth/GetTokenAuthority",
		"/moby.filesync.v1.Auth/VerifyTokenAuthority",
		"/moby.filesync.v1.Auth/Credentials",
		"/grpc.health.v1.Health/Check",
		"/grpc.health.v1.Health/Watch",
	}
}

func TestSessionAdvertisementExactMethodsAndLegacyForms(t *testing.T) {
	const diffCopy = "/moby.filesync.v1.FileSync/DiffCopy"
	const credentials = "/moby.filesync.v1.Auth/Credentials"
	for _, tc := range []struct {
		name   string
		policy Policy
		want   []string
	}{
		{"disabled", Policy{}, nil},
		{"file sync only", Policy{Session: SessionPolicy{FileSync: FileSyncPolicy{Allow: true}}}, []string{diffCopy, " moby.filesync.v1.FileSync ", "\t" + diffCopy + "\t", diffCopy}},
		{"auth only", Policy{Session: SessionPolicy{Auth: AuthPolicy{Allow: true}}}, []string{credentials, "moby.filesync.v1.Auth"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			for _, value := range []string{
				diffCopy, "/moby.filesync.v1.FileSync/TarStream", "/moby.filesync.v1.FileSync/Unknown",
				credentials, "moby.filesync.v1.Auth", "/unknown.v1.Service/DiffCopy",
				" moby.filesync.v1.FileSync ", "\t" + diffCopy + "\t", diffCopy,
				"/moby.filesync.v1.FileSync", "moby.filesync.v1.FileSync/DiffCopy",
				diffCopy + "/extra", diffCopy + "?query=1", diffCopy + "#fragment",
				"/moby.filesync.v1.FileSync/", "//moby.filesync.v1.FileSync/DiffCopy",
				"/moby.filesync.v1.FileSync/diffcopy", "/Moby.filesync.v1.FileSync/DiffCopy",
				"/moby.filesync.v1.FileSync/%44iffCopy", diffCopy + "," + credentials,
				"", "  ", "/grpc.health.v1.Health/Check", "/moby.buildkit.v1.Control/Solve",
			} {
				// Add canonicalizes the supplied lower-case header key, as does
				// net/http's incoming HTTP/1 parser. Values are separate entries.
				h.Add("x-docker-expose-session-grpc-method", value)
			}
			h.Set("Other-Header", "unchanged")
			rewriteSessionAdvertisement(h, tc.policy)
			if got := h.Values(sessionGRPCMethodHeader); !slices.Equal(got, tc.want) {
				t.Fatalf("exact declaration filtering: got %q, want %q", got, tc.want)
			}
			if h.Get("Other-Header") != "unchanged" {
				t.Fatal("rewriting changed unrelated metadata")
			}
		})
	}
}

// Drive the real HTTP/1 upgrade, reverse HTTP/2 callback and FileSync relay.
// Denied callbacks are attempted even though their declarations were removed:
// advertising an enabled method must not authorize its siblings or Auth.
func TestSessionAdvertisementUpgradeAndCallbacks(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		name := "disabled"
		if enabled {
			name = "enabled"
		}
		t.Run(name, func(t *testing.T) {
			daemonSide, dialerSide := net.Pipe()
			clientSide, hijackSide := net.Pipe()
			m := NewMediator(&fakeDialer{conn: dialerSide}, noopLogger())
			p := Policy{Session: SessionPolicy{FileSync: FileSyncPolicy{Allow: enabled}}}
			r := newUpgradeRequest(t, "/session")
			for _, declaration := range producerSessionAdvertisement() {
				r.Header.Add(sessionGRPCMethodHeader, declaration)
			}
			// Repeated values retain their position after narrowing.
			r.Header.Add(sessionGRPCMethodHeader, producerSessionAdvertisement()[0])
			original := r.Header.Clone()
			serveDone, clientDone := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(serveDone)
				m.ServeSession(&fakeHijackResponseRecorder{ResponseRecorder: httptest.NewRecorder(), conn: hijackSide}, r, p, SessionKey{ClientIdentity: "test-client", Profile: "test-profile"})
			}()
			var calls atomic.Int32
			requestFrames := framedPackets(t, reqPacket(0), finPacket())
			responseFrames := framedPackets(t, statPacket("Dockerfile"), statTerminatorPacket(), dataPacket(0, []byte("FROM scratch\n")), dataEOFPacket(0), finPacket())
			requestSeen := make(chan []byte, 2)
			go func() {
				defer close(clientDone)
				br := bufio.NewReader(clientSide)
				if _, err := http.ReadResponse(br, r); err != nil {
					return
				}
				(&http2.Server{}).ServeConn(&bufferedConn{Conn: clientSide, r: br}, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					calls.Add(1)
					body, _ := io.ReadAll(req.Body)
					requestSeen <- body
					w.Header().Set("Content-Type", "application/grpc")
					w.Header().Set("Trailer", "Grpc-Status")
					_, _ = w.Write(responseFrames)
					w.Header().Set("Grpc-Status", "0")
				})})
			}()
			t.Cleanup(func() {
				for _, conn := range []net.Conn{daemonSide, dialerSide, clientSide, hijackSide} {
					_ = conn.Close()
				}
				for _, done := range []chan struct{}{serveDone, clientDone} {
					select {
					case <-done:
					case <-time.After(2 * time.Second):
						t.Error("advertisement tunnel producer did not settle")
					}
				}
				if m.Registry.Len() != 0 {
					t.Error("advertisement tunnel retained registry state after closure")
				}
			})
			br := bufio.NewReader(daemonSide)
			forwarded, err := http.ReadRequest(br)
			if err != nil {
				t.Fatal(err)
			}
			_ = forwarded.Body.Close()
			var want []string
			if enabled {
				want = []string{producerSessionAdvertisement()[0], producerSessionAdvertisement()[0]}
			}
			if got := forwarded.Header.Values(sessionGRPCMethodHeader); !slices.Equal(got, want) {
				t.Fatalf("daemon upgrade declarations: got %q, want %q", got, want)
			}
			if !slices.Equal(r.Header.Values(sessionGRPCMethodHeader), original.Values(sessionGRPCMethodHeader)) {
				t.Fatal("rewriting modified the original request")
			}
			if _, err := io.WriteString(daemonSide, "HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			cc, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(&bufferedConn{Conn: daemonSide, r: br})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cc.Close() }()
			for _, path := range []string{"/moby.filesync.v1.FileSync/TarStream", "/moby.filesync.v1.FileSync/Unknown", "/moby.filesync.v1.Auth/Credentials", "/moby.filesync.v1.FileSend/DiffCopy", "/moby.filesync.v1.FileSync/DiffCopy/extra"} {
				resp, err := cc.RoundTrip(newGRPCRequest(t, path, string(requestFrames)))
				if err != nil {
					t.Fatal(err)
				}
				if code, _ := grpcStatusOf(t, resp); code != grpcCodePermissionDenied && code != grpcCodeUnimplemented {
					t.Fatalf("denied callback %s returned %d", path, code)
				}
			}
			if calls.Load() != 0 {
				t.Fatal("unadvertised or disabled callback reached the session server")
			}
			for _, dir := range []string{fsutilDirNameDockerfile, "context"} {
				resp, err := cc.RoundTrip(newFileSyncGRPCRequest(t, dir, requestFrames))
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				code, _ := grpcStatusOf(t, resp)
				if !enabled {
					if code != grpcCodePermissionDenied || calls.Load() != 0 {
						t.Fatal("disabled FileSync callback was admitted")
					}
					continue
				}
				if code != 0 || !bytes.Equal(body, responseFrames) {
					t.Fatalf("%s response frames changed or denied: status %d, body %x", dir, code, body)
				}
				if got := <-requestSeen; !bytes.Equal(got, requestFrames) {
					t.Fatal("FileSync request frames changed")
				}
			}
			if enabled && calls.Load() != 2 {
				t.Fatalf("FileSync callback count = %d, want 2", calls.Load())
			}
		})
	}
}

func TestSessionAdvertisementProducerFullMethods(t *testing.T) {
	producer := producerSessionAdvertisement()
	for _, tc := range []struct {
		name   string
		policy Policy
		want   []string
	}{
		{"file sync", Policy{Session: SessionPolicy{FileSync: FileSyncPolicy{Allow: true}}}, producer[:1]},
		{"auth", Policy{Session: SessionPolicy{Auth: AuthPolicy{Allow: true}}}, producer[2:6]},
		{"all switches", allowAllPolicy, append([]string{producer[0]}, producer[2:6]...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			for _, declaration := range producer {
				h.Add(sessionGRPCMethodHeader, declaration)
			}
			rewriteSessionAdvertisement(h, tc.policy)
			if got := h.Values(sessionGRPCMethodHeader); !slices.Equal(got, tc.want) {
				t.Fatalf("enabled producer declaration lost or denied method retained: got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSessionAdvertisementClassifierDenial(t *testing.T) {
	// Keep this test serial: temporarily remove a registry entry to isolate
	// Classify from Allowed, which deliberately also denies unknown methods.
	key := method{EndpointSession, "moby.filesync.v1.FileSync", "DiffCopy"}
	original := registry[key]
	delete(registry, key)
	t.Cleanup(func() { registry[key] = original })
	h := http.Header{}
	h.Add(sessionGRPCMethodHeader, "/moby.filesync.v1.FileSync/DiffCopy")
	rewriteSessionAdvertisement(h, allowAllPolicy)
	if len(h.Values(sessionGRPCMethodHeader)) != 0 {
		t.Fatal("policy-enabled method bypassed classifier denial")
	}
}
