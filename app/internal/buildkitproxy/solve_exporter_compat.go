// Fork: wyrd-company/sockguard. This file holds the fork's narrow
// compatibility rule for SolveRequest's deprecated exporter fields. Kept
// out of solve.go so upstream security releases rebase cleanly; solve.go's
// checkSolveCache calls checkSolveDeprecatedExporter in place of its own
// outright denial.
package buildkitproxy

import (
	"maps"

	"github.com/codeswhat/sockguard/app/internal/buildkitproto/control"
)

// checkSolveDeprecatedExporter admits SolveRequest.ExporterDeprecated (3)
// and ExporterAttrsDeprecated (4) only as an exact copy of Exporters[0].
//
// The BuildKit SDK (client/solve.go, v0.18.2) copies the first exporter
// into both deprecated fields on every Solve, so that an older daemon can
// still read it. A current daemon (control/control.go) reads the deprecated
// fields only when Exporters is empty. When they are an exact copy of
// Exporters[0], they carry nothing that checkSolveExporters did not
// already check, so the exporter allowlists cover them.
//
// Every other shape is denied with the same reason as before:
//   - deprecated fields with no Exporters: the daemon would export from the
//     deprecated fields, which no allowlist checks;
//   - a type or attrs that differ from Exporters[0]: the request is not the
//     SDK's mirror, and an older daemon could act on the copy that no
//     allowlist reads.
//
// Attrs compare with maps.Equal, so a missing map and an empty map are
// equal (protobuf does not distinguish them on the wire).
func checkSolveDeprecatedExporter(req *control.SolveRequest) *mediationDenial {
	deprecatedType := req.GetExporterDeprecated()
	deprecatedAttrs := req.GetExporterAttrsDeprecated()
	if deprecatedType == "" && len(deprecatedAttrs) == 0 {
		return nil
	}
	exporters := req.GetExporters()
	if len(exporters) == 0 || exporters[0] == nil {
		return deny(grpcCodeFailedPrecondition, "buildkit_schema_unsupported", "unsupported BuildKit schema")
	}
	if deprecatedType != exporters[0].GetType() {
		return deny(grpcCodeFailedPrecondition, "buildkit_schema_unsupported", "unsupported BuildKit schema")
	}
	if !maps.Equal(deprecatedAttrs, exporters[0].GetAttrs()) {
		return deny(grpcCodeFailedPrecondition, "buildkit_schema_unsupported", "unsupported BuildKit schema")
	}
	return nil
}
