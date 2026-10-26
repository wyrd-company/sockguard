package filter

// argvGateLifted reports whether an exec with no allowed_commands configured
// may pass the argv gate in denyReason. Two settings lift it:
//
//   - allowBlindWrites, the global insecure_allow_body_blind_writes
//     acknowledgment, which also covers other body-blind writes.
//   - allowAnyCommand, request_body.exec.allow_any_command, which is scoped
//     to exec and to one policy (the default or a client profile).
//
// Neither setting implies the other. Each lifts only the empty-allowlist gate:
// the privileged, root-user and env checks in denyReason still run, on exec
// create and again on exec start against the stored exec metadata. A
// non-empty allowedCommands is never widened by either setting.
func (p execPolicy) argvGateLifted() bool {
	return p.allowBlindWrites || p.allowAnyCommand
}
