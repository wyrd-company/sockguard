package metrics

import (
	"cmp"
	"fmt"
	"io"
	"slices"
)

// Fork-owned (wyrd-company/sockguard): the workspace exceptions load counter.

type workspaceExceptionsLoadLabels struct {
	result string
}

// ObserveWorkspaceExceptionsLoad counts one load of the workspace exceptions
// file. result is ok (valid, applied), missing (no file, no exceptions) or
// invalid (unreadable or invalid, no exceptions).
func (r *Registry) ObserveWorkspaceExceptionsLoad(result string) {
	if r == nil {
		return
	}
	addCounter(&r.workspaceExceptionsLoads, workspaceExceptionsLoadLabels{result: result})
}

// writeWorkspaceExceptionsMetrics writes the counter. The series is omitted
// until the first load, so a proxy without an exceptions file exposes nothing
// new.
func (r *Registry) writeWorkspaceExceptionsMetrics(w io.Writer) {
	loads := collectCounters[workspaceExceptionsLoadLabels](&r.workspaceExceptionsLoads)
	if len(loads) == 0 {
		return
	}
	keys := make([]workspaceExceptionsLoadLabels, 0, len(loads))
	for key := range loads {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b workspaceExceptionsLoadLabels) int { return cmp.Compare(a.result, b.result) })
	fmt.Fprintln(w, "# HELP sockguard_workspace_exceptions_loads_total Loads of the workspace exceptions file since startup. result is ok (valid file applied), missing (no file; no exceptions apply) or invalid (unreadable or invalid file; no exceptions apply until a valid file is loaded).")
	fmt.Fprintln(w, "# TYPE sockguard_workspace_exceptions_loads_total counter")
	for _, key := range keys {
		fmt.Fprintf(w, "sockguard_workspace_exceptions_loads_total{result=%s} %d\n", labelValue(key.result), loads[key])
	}
}
