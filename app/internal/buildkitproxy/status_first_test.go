// relationships:
//
//	references: [bridge.go, session.go]
package buildkitproxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"

	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/net/http2"

	"github.com/codeswhat/sockguard/app/internal/buildkitproto/control"
)

// observedWaitContext identifies the actual cancellation-select boundary, not
// a goroutine launch or a completed socket write. No scheduling delay is used.
type observedWaitContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
	again   chan struct{}
	calls   atomic.Int64
}

func (c *observedWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	if c.calls.Add(1) > 1 && c.again != nil {
		select {
		case c.again <- struct{}{}:
		default:
		}
	}
	return c.Context.Done()
}

type statusFirstLeg struct {
	reads atomic.Int64
	frame []byte
}

func (l *statusFirstLeg) Close() error { return nil }
func (l *statusFirstLeg) RoundTrip(r *http.Request) (*http.Response, error) {
	frame, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	if r.URL.Path == "/moby.buildkit.v1.Control/Status" {
		l.frame = frame
		l.reads.Add(1)
	}
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(frame))}, nil
}

func statusFirstBridge(t *testing.T) (*bridge, *statusFirstLeg) {
	t.Helper()
	registry := NewSessionRegistry()
	session := registry.Open(SessionKey{ClientIdentity: "client-a", Profile: "profile-a"}, EndpointGRPC, "")
	limits := DefaultLimits()
	leg := &statusFirstLeg{}
	b := &bridge{session: session, registry: registry, legs: bridgeLegs{endpoint: EndpointGRPC}, policy: allowAllPolicy, limits: limits, logger: noopLogger(), guard: newStreamAbuseGuard(limits), clientLeg: leg}
	t.Cleanup(func() { registry.Close(session.ID) })
	return b, leg
}

func TestStatusFirstLaterSolveAdmission(t *testing.T) {
	b, leg := statusFirstBridge(t)
	ctx, cancel := context.WithCancel(context.Background())
	observed := &observedWaitContext{Context: ctx, entered: make(chan struct{})}
	// Duplicate known field encodings are valid protobuf and expose re-encoding.
	payload := append(mustMarshal(t, &control.StatusRequest{Ref: "earlier"}), mustMarshal(t, &control.StatusRequest{Ref: "build-ref"})...)
	frame := grpcFrame(payload)
	req := newGRPCRequest(t, "/moby.buildkit.v1.Control/Status", string(frame)).WithContext(observed)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { defer close(done); b.handleStream(rec, req) }()
	t.Cleanup(func() { cancel(); <-done })
	select {
	case <-observed.entered:
	case <-done:
		t.Fatalf("Status returned before matching Solve admission: grpc status %s", rec.Header().Get("Grpc-Status"))
	}
	if leg.reads.Load() != 0 {
		t.Fatal("upstream Status read before Solve admission")
	}
	if b.registry.OwnsRef(b.session.Key, "build-ref") {
		t.Fatal("waiting Status provisionally owned ref")
	}
	solve := newFramedGRPCRequest(t, "/moby.buildkit.v1.Control/Solve", &control.SolveRequest{Ref: "build-ref", Session: testBuildkitSessionID})
	b.registry.mu.Lock()
	generation := b.session.refChanged
	b.registry.mu.Unlock()
	b.handleStream(httptest.NewRecorder(), solve)
	b.registry.mu.Lock()
	notified := generation != b.session.refChanged
	b.registry.mu.Unlock()
	if !notified {
		t.Fatal("Solve admission did not notify waiting Status")
	}
	<-done
	if leg.reads.Load() != 1 {
		t.Fatalf("upstream Status reads=%d, want 1 after admitted Solve", leg.reads.Load())
	}
	if !bytes.Equal(leg.frame, frame) {
		t.Fatal("original Status frame changed")
	}
	if !bytes.Equal(rec.Body.Bytes(), frame) {
		t.Fatal("raw Status response changed")
	}
}

func TestStatusFirstNoAdmission(t *testing.T) {
	for _, name := range []string{"never Solve", "policy denied", "unknown Solve fields", "invalid session", "ref limit", "upload limit", "session limit", "different principal", "different profile", "different ref", "session closed", "caller canceled"} {
		t.Run(name, func(t *testing.T) {
			b, leg := statusFirstBridge(t)
			b.limits.MaxRefsPerSession = 1
			b.limits.MaxUploadKeysPerSession = 1
			ref := "pending-ref"
			solveReq := &control.SolveRequest{Ref: ref, Session: testBuildkitSessionID}
			if name == "ref limit" {
				if !b.registry.PutRef(b.session, "existing", 1) {
					t.Fatal("seed ref")
				}
			}
			if name == "upload limit" {
				b.policy.Control.Solve.AllowRemoteContext = true
				b.policy.Control.Solve.AllowRunInstructions = true
				solveReq.FrontendAttrs = map[string]string{"context": "http://buildkit-session/one", "context:extra": "http://buildkit-session/two"}
			}
			if name == "session limit" {
				for i := 0; i < maxBuildkitSessionIDsPerSession; i++ {
					if result := b.registry.admitSolve(b.session, fmt.Sprintf("session-%d", i), "existing", nil, 0, 1); result != solveAdmissionSucceeded {
						t.Fatalf("seed sessions: %v", result)
					}
				}
				b.limits.MaxRefsPerSession = 2
			}
			ctx, cancel := context.WithCancel(context.Background())
			observed := &observedWaitContext{Context: ctx, entered: make(chan struct{}), again: make(chan struct{}, 1)}
			req := newFramedGRPCRequest(t, "/moby.buildkit.v1.Control/Status", &control.StatusRequest{Ref: ref}).WithContext(observed)
			rec := httptest.NewRecorder()
			done := make(chan struct{})
			go func() { defer close(done); b.handleStream(rec, req) }()
			t.Cleanup(func() { cancel(); <-done })
			select {
			case <-observed.entered:
			case <-done:
				t.Fatal("Status did not wait at cancellation boundary")
			}
			if leg.reads.Load() != 0 {
				t.Fatal("upstream Status read before admission")
			}
			switch name {
			case "never Solve", "caller canceled":
			case "session closed":
				b.registry.mu.Lock()
				generation := b.session.refChanged
				b.registry.mu.Unlock()
				b.registry.Close(b.session.ID)
				select {
				case <-generation:
				default:
					t.Fatal("session closure did not notify pending Status")
				}
				<-done
			case "different principal", "different profile":
				key := b.session.Key
				if name == "different principal" {
					key.ClientIdentity = "client-b"
				} else {
					key.Profile = "profile-b"
				}
				other := b.registry.Open(key, EndpointGRPC, "")
				t.Cleanup(func() { b.registry.Close(other.ID) })
				if got := b.registry.admitSolve(other, testBuildkitSessionID, ref, nil, 1, 1); got != solveAdmissionSucceeded {
					t.Fatalf("foreign admission=%v", got)
				}
				if b.registry.OwnsRef(b.session.Key, ref) {
					t.Fatal("foreign Solve transferred ownership")
				}
				if b.registry.admitSolve(b.session, "unrelated-session", "unrelated-ref", nil, 1, 1) != solveAdmissionSucceeded {
					t.Fatal("same-key unrelated wake failed")
				}
				select {
				case <-observed.again:
				case <-done:
					t.Fatalf("foreign Solve released Status: upstream reads=%d", leg.reads.Load())
				}
			default:
				expected := grpcCodeResourceExhausted
				switch name {
				case "policy denied":
					solveReq.Entitlements = []string{"security.insecure"}
					expected = grpcCodePermissionDenied
				case "unknown Solve fields":
					solveReq.ProtoReflect().SetUnknown(unknownFieldBytes())
					expected = grpcCodeFailedPrecondition
				case "invalid session":
					solveReq.Session = "invalid/session"
					expected = grpcCodeInvalidArgument
				case "different ref":
					solveReq.Ref = "other-ref"
					expected = -1
				}
				result := httptest.NewRecorder()
				b.handleStream(result, newFramedGRPCRequest(t, "/moby.buildkit.v1.Control/Solve", solveReq))
				if expected != -1 {
					code, _ := grpcStatusOf(t, result.Result())
					if code != expected {
						t.Fatalf("Solve code=%d want %d", code, expected)
					}
				}
			}
			cancel()
			<-done
			if leg.reads.Load() != 0 {
				t.Fatalf("unadmitted Status reached upstream %d times", leg.reads.Load())
			}
			if name != "ref limit" && name != "session limit" && b.registry.HasAdmittedSolve(b.session.Key, testBuildkitSessionID) && name != "different ref" {
				t.Fatal("failed admission retained session ownership")
			}
			b.registry.Close(b.session.ID)
			if b.registry.OwnsRef(b.session.Key, ref) || b.registry.HasAdmittedSolve(b.session.Key, testBuildkitSessionID) {
				t.Fatal("closed session retained ownership")
			}
			if b.registry.ConsumeUploadKey(b.session.Key, testBuildkitSessionID, "one") || b.registry.ConsumeUploadKey(b.session.Key, testBuildkitSessionID, "two") {
				t.Fatal("rejected Solve published upload keys")
			}
			// The closed tunnel cannot retain ref/session capacity. Admission on its
			// replacement demonstrates reuse at the real atomic publication boundary.
			replacement := b.registry.Open(b.session.Key, EndpointGRPC, "")
			defer b.registry.Close(replacement.ID)
			if got := b.registry.admitSolve(replacement, testBuildkitSessionID, ref, []string{"one"}, 1, 1); got != solveAdmissionSucceeded {
				t.Fatalf("capacity not reusable: %v", got)
			}
			if !b.registry.ConsumeUploadKey(replacement.Key, testBuildkitSessionID, "one") {
				t.Fatal("reused upload capacity unavailable")
			}
			if b.registry.admitSolve(replacement, testBuildkitSessionID, ref, []string{"two"}, 1, 1) != solveAdmissionSucceeded {
				t.Fatal("consumed upload capacity not reusable")
			}
			if !b.registry.ConsumeUploadKey(replacement.Key, testBuildkitSessionID, "two") {
				t.Fatal("replacement upload token unavailable")
			}
		})
	}
}

func TestStatusFirstInvalidAndUnknownFrames(t *testing.T) {
	for _, name := range []string{"empty ref", "overlong ref", "unknown fields"} {
		t.Run(name, func(t *testing.T) {
			b, leg := statusFirstBridge(t)
			message := &control.StatusRequest{}
			if name == "overlong ref" {
				message.Ref = strings.Repeat("r", maxBuildkitRefBytes+1)
			}
			if name == "unknown fields" {
				message.Ref = "ref"
				message.ProtoReflect().SetUnknown(unknownFieldBytes())
			}
			rec := httptest.NewRecorder()
			b.handleStream(rec, newFramedGRPCRequest(t, "/moby.buildkit.v1.Control/Status", message))
			code, _ := grpcStatusOf(t, rec.Result())
			expected := grpcCodePermissionDenied
			if name == "unknown fields" {
				expected = grpcCodeFailedPrecondition
			}
			if code != expected {
				t.Fatalf("Status code=%d want %d", code, expected)
			}
			if leg.reads.Load() != 0 {
				t.Fatal("invalid Status reached upstream")
			}
		})
	}
}

// A real HTTP/2 connection runs the production stream dispatcher. The wrapper
// observes only entry into the Status wait; Solve remains a separate stream.
func TestStatusFirstSameConnection(t *testing.T) {
	for _, mode := range []string{"later Solve", "caller reset", "tunnel close", "same key reconnect"} {
		t.Run(mode, func(t *testing.T) {
			b, leg := statusFirstBridge(t)
			server, client := net.Pipe()
			entered := make(chan struct{})
			serverDone := make(chan struct{})
			serveCtx, cancelServe := context.WithCancel(context.Background())
			var observedOnce sync.Once
			var handlers sync.WaitGroup
			srv := &http2.Server{MaxConcurrentStreams: 2}
			go func() {
				defer close(serverDone)
				srv.ServeConn(server, &http2.ServeConnOpts{Context: serveCtx, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/moby.buildkit.v1.Control/Status" {
						observedOnce.Do(func() { r = r.WithContext(&observedWaitContext{Context: r.Context(), entered: entered}) })
					}
					b.handleStream(w, r)
				})})
			}()
			transport := &http2.Transport{AllowHTTP: true}
			driver, err := transport.NewClientConn(client)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			var response []byte
			var requestErr error
			req := newFramedGRPCRequest(t, "/moby.buildkit.v1.Control/Status", &control.StatusRequest{Ref: "ref"}).WithContext(ctx)
			go func() {
				defer close(done)
				resp, e := driver.RoundTrip(req)
				requestErr = e
				if e == nil {
					response, e = io.ReadAll(resp.Body)
					requestErr = e
					_ = resp.Body.Close()
				}
			}()
			t.Cleanup(func() {
				cancel()
				cancelServe()
				_ = driver.Close()
				_ = client.Close()
				_ = server.Close()
				b.registry.Close(b.session.ID)
				<-done
				<-serverDone
				handlers.Wait()
			})
			select {
			case <-entered:
			case <-done:
				t.Fatalf("Status ended before wait: %v", requestErr)
			}
			if leg.reads.Load() != 0 {
				t.Fatal("upstream Status read before admission")
			}
			switch mode {
			case "later Solve":
				resp, e := driver.RoundTrip(newFramedGRPCRequest(t, "/moby.buildkit.v1.Control/Solve", &control.SolveRequest{Ref: "ref", Session: testBuildkitSessionID}))
				if e != nil {
					t.Fatal(e)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				<-done
				if requestErr != nil {
					t.Fatal(requestErr)
				}
				if leg.reads.Load() != 1 || !bytes.Equal(response, grpcFrame(mustMarshal(t, &control.StatusRequest{Ref: "ref"}))) {
					t.Fatal("later Solve did not release exact raw Status")
				}
			case "same key reconnect":
				other := b.registry.Open(b.session.Key, EndpointGRPC, "")
				defer b.registry.Close(other.ID)
				if b.registry.admitSolve(other, testBuildkitSessionID, "ref", nil, 1, 1) != solveAdmissionSucceeded {
					t.Fatal("same key admission failed")
				}
				<-done
				b.registry.Close(b.session.ID)
				if !b.registry.OwnsRef(other.Key, "ref") {
					t.Fatal("Status tunnel closure removed another session's ownership")
				}
				if leg.reads.Load() != 1 {
					t.Fatal("same key reconnect did not release Status")
				}
			case "caller reset":
				cancel()
				<-done
				// A subsequent valid Solve and Status on the same transport prove that
				// the reset releases stream capacity and leaves no zombie forward.
				resp, e := driver.RoundTrip(newFramedGRPCRequest(t, "/moby.buildkit.v1.Control/Solve", &control.SolveRequest{Ref: "ref", Session: testBuildkitSessionID}))
				if e != nil {
					t.Fatal(e)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if leg.reads.Load() != 0 {
					t.Fatal("canceled Status reached upstream")
				}
				resp, e = driver.RoundTrip(newFramedGRPCRequest(t, "/moby.buildkit.v1.Control/Status", &control.StatusRequest{Ref: "ref"}))
				if e != nil {
					t.Fatal(e)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if leg.reads.Load() != 1 {
					t.Fatal("stream capacity not reusable")
				}
			case "tunnel close":
				_ = driver.Close()
				_ = client.Close()
				<-done
				b.registry.Close(b.session.ID)
				<-serverDone
				if leg.reads.Load() != 0 {
					t.Fatal("tunnel closure forwarded pending Status")
				}
				if b.registry.Len() != 0 {
					t.Fatal("closed tunnel retained session")
				}
			}
		})
	}
}

// Hold the actual ownership recheck after its notification. Cancellation wins
// before that admission can release any Status read.
type heldRecheckContext struct {
	*observedWaitContext
	calls      atomic.Int64
	rechecking chan struct{}
	release    chan struct{}
}

func (c *heldRecheckContext) Err() error {
	if c.calls.Add(1) == 2 {
		close(c.rechecking)
		<-c.release
	}
	return c.Context.Err()
}

func TestStatusFirstCancellationAtAdmission(t *testing.T) {
	b, leg := statusFirstBridge(t)
	ctx, cancel := context.WithCancel(context.Background())
	observed := &observedWaitContext{Context: ctx, entered: make(chan struct{})}
	held := &heldRecheckContext{observedWaitContext: observed, rechecking: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	done := make(chan struct{})
	go func() {
		defer close(done)
		b.handleStream(httptest.NewRecorder(), newFramedGRPCRequest(t, "/moby.buildkit.v1.Control/Status", &control.StatusRequest{Ref: "ref"}).WithContext(held))
	}()
	t.Cleanup(func() { cancel(); release.Do(func() { close(held.release) }); b.registry.Close(b.session.ID); <-done })
	select {
	case <-observed.entered:
	case <-done:
		t.Fatal("Status did not wait")
	}
	b.handleStream(httptest.NewRecorder(), newFramedGRPCRequest(t, "/moby.buildkit.v1.Control/Solve", &control.SolveRequest{Ref: "ref", Session: testBuildkitSessionID}))
	select {
	case <-held.rechecking:
	case <-done:
		t.Fatal("Status skipped ownership recheck")
	}
	cancel()
	release.Do(func() { close(held.release) })
	<-done
	if leg.reads.Load() != 0 {
		t.Fatal("canceled Status forwarded during admission")
	}
}
