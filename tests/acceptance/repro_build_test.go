//go:build sockguardacceptance && sockguardbuildrepro

// relationships:
//
//	references: [consumer_test.go, testdata/candidate.yaml]
package acceptance

import (
	"bytes"
	"context"
	"fmt"
	"github.com/moby/buildkit/api/services/control"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"google.golang.org/protobuf/proto"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	dockerclient "github.com/docker/docker/client"
	"github.com/wyrd-company/devcontainer-builder/pkg/builder"
)

// TestBuildDirectReproducer bypasses the provenance/HTTP observation relay.
// The only CLI override on the exact policy is log-level=debug, so successful
// Solve admissions as well as denials are observable in the retained log.
func TestBuildDirectReproducer(t *testing.T) {
	f := newFixture(t)
	p := f.startProxy(t, "baseline-observe")
	w := f.workspace("build-control")
	dc := loadSpec(t, w, `{"build":{"dockerfile":"Dockerfile"},"workspaceFolder":"/workspace"}`)
	write(t, filepath.Join(w, ".devcontainer", "Dockerfile"), []byte("FROM "+f.baseImage+"\nRUN printf control > /marker\n"))
	var wireMu sync.Mutex
	var wires []*wireConn
	c, e := dockerclient.NewClientWithOpts(dockerclient.WithHost("unix://"+p.socket), dockerclient.WithAPIVersionNegotiation(), dockerclient.WithDialContext(func(ctx context.Context, _, _ string) (net.Conn, error) {
		conn, e := (&net.Dialer{}).DialContext(ctx, "unix", p.socket)
		if e != nil {
			return nil, e
		}
		w := &wireConn{Conn: conn}
		wireMu.Lock()
		wires = append(wires, w)
		wireMu.Unlock()
		return w, nil
	}))
	must(t, e)
	defer c.Close()
	_, e = builder.New().Build(f.ctx, builder.Options{Spec: dc, Workspace: w, Docker: c, Tags: []string{"acceptance-control:" + f.run}, Labels: map[string]string{runLabel: f.run}, Load: true, NoCache: true, SkipFeatures: true, OmitSyntaxDirective: true, Progress: "plain", Stdout: os.Stdout, Stderr: os.Stderr, WorkDir: filepath.Join(w, "build-work")})
	wireMu.Lock()
	copied := append([]*wireConn(nil), wires...)
	wireMu.Unlock()
	var observed []wireRef
	for _, w := range copied {
		observed = append(observed, w.refs(t)...)
	}
	for _, r := range observed {
		t.Logf("GENERATED_REF method=%s stream=%d ref=%s profile=menagerie uid=10001", r.method, r.stream, r.ref)
	}
	if e != nil {
		t.Logf("REPRO_CONFIG raw hash and rendered hash above; only --log-level debug observability override")
		t.Fatalf("DIRECT_PINNED_CONSUMER_BUILD_FAILURE: %v", e)
	}
	f.recordImage("acceptance-control:" + f.run)
}

// Captures successful writes without delaying, replaying or changing them.
// Decode only generated Solve/Status refs; never log other payloads or auth.
type wireConn struct {
	net.Conn
	mu      sync.Mutex
	written bytes.Buffer
}

func (w *wireConn) Write(b []byte) (int, error) {
	n, e := w.Conn.Write(b)
	w.mu.Lock()
	_, _ = w.written.Write(b[:n])
	w.mu.Unlock()
	return n, e
}
func (w *wireConn) CloseWrite() error {
	if c, ok := w.Conn.(interface{ CloseWrite() error }); ok {
		return c.CloseWrite()
	}
	return fmt.Errorf("owned connection lacks CloseWrite")
}

type wireRef struct {
	method string
	stream uint32
	ref    string
}

func (w *wireConn) refs(t *testing.T) []wireRef {
	w.mu.Lock()
	raw := append([]byte(nil), w.written.Bytes()...)
	w.mu.Unlock()
	start := bytes.Index(raw, []byte(http2.ClientPreface))
	if start < 0 {
		return nil
	}
	fr := http2.NewFramer(io.Discard, bytes.NewReader(raw[start+len(http2.ClientPreface):]))
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	paths := map[uint32]string{}
	bodies := map[uint32][]byte{}
	var out []wireRef
	for {
		frame, e := fr.ReadFrame()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Logf("WIRE_PARSE_INCOMPLETE %v", e)
			break
		}
		switch v := frame.(type) {
		case *http2.MetaHeadersFrame:
			for _, h := range v.Fields {
				if h.Name == ":path" {
					paths[v.StreamID] = h.Value
				}
			}
		case *http2.DataFrame:
			path := paths[v.StreamID]
			if path != "/moby.buildkit.v1.Control/Solve" && path != "/moby.buildkit.v1.Control/Status" {
				continue
			}
			bodies[v.StreamID] = append(bodies[v.StreamID], v.Data()...)
			data := bodies[v.StreamID]
			if len(data) < 5 {
				continue
			}
			size := int(data[1])<<24 | int(data[2])<<16 | int(data[3])<<8 | int(data[4])
			if len(data) < 5+size {
				continue
			}
			payload := data[5 : 5+size]
			var ref string
			if strings.HasSuffix(path, "/Solve") {
				var req moby_buildkit_v1.SolveRequest
				must(t, proto.Unmarshal(payload, &req))
				ref = req.Ref
			} else {
				var req moby_buildkit_v1.StatusRequest
				must(t, proto.Unmarshal(payload, &req))
				ref = req.Ref
			}
			out = append(out, wireRef{path, v.StreamID, ref})
			delete(bodies, v.StreamID)
		}
	}
	return out
}
