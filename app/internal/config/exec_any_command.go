package config

// ArgvGateConfigured reports whether this exec block settles the exec argv
// gate without the global insecure_allow_body_blind_writes acknowledgment:
// either an allowed_commands allowlist is configured, or allow_any_command
// admits any argv. Startup blind-write validation reads it to decide whether
// exec allow rules need that acknowledgment. The root-user, privileged and
// env checks apply either way.
func (c ExecRequestBodyConfig) ArgvGateConfigured() bool {
	return len(c.AllowedCommands) > 0 || c.AllowAnyCommand
}
