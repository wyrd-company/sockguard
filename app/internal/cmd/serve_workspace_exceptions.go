package cmd

import (
	"context"
	"errors"
	"log/slog"
	"maps"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/reload"
)

// Fork-owned (wyrd-company/sockguard): the workspace exceptions store and its
// file watcher.
//
// The store is process-scoped, like the resolver: workspace_exceptions is
// reload-immutable, so every chain a config reload builds gets the same
// store. The file has its own reload.Reloader, which shares the config
// reloader's debounce, poll interval and SIGHUP, and swaps the store's
// snapshot without rebuilding the chain.

// loadWorkspaceExceptions builds the store when workspace_exceptions.file is
// set. A workspace root that is not canonical fails startup; a missing or
// invalid file does not.
func (r *serveRuntime) loadWorkspaceExceptions(cfg *config.Config, logger *slog.Logger) error {
	if !cfg.WorkspaceExceptions.Enabled() {
		return nil
	}
	store, err := filter.NewWorkspaceExceptionStore(filter.WorkspaceExceptionStoreOptions{
		Path:              cfg.WorkspaceExceptions.File,
		WorkspaceRoot:     cfg.WorkspaceExceptions.WorkspaceRoot,
		PerWorkspaceRoots: cfg.WorkspaceExceptions.PerWorkspaceRoots,
		MaxBytes:          config.MaxConfigFileBytes,
		Logger:            logger,
		ObserveLoad:       r.metrics.ObserveWorkspaceExceptionsLoad,
	})
	if err != nil {
		return err
	}
	r.workspaceExceptions = store
	return nil
}

// watchWorkspaceExceptions starts the file's reloader. It runs whether or not
// reload.enabled is set: the exceptions file is the policy that changes while
// the proxy runs. It returns a stop func.
func (r *serveRuntime) watchWorkspaceExceptions(ctx context.Context, cfg *config.Config, logger *slog.Logger) func() {
	if r == nil || r.workspaceExceptions == nil {
		return func() {}
	}
	debounce := reloadDuration(logger, "reload.debounce", cfg.Reload.Debounce, reload.DefaultDebounce)
	pollInterval := reloadDuration(logger, "reload.poll_interval", cfg.Reload.PollInterval, 0)
	store := r.workspaceExceptions
	rl, err := reload.New(reload.Options{
		Path:            store.Path(),
		Debounce:        debounce,
		PollInterval:    pollInterval,
		OnReload:        func() { store.Reload() },
		Logger:          logger,
		TriggerOnRemove: true,
	})
	if err != nil {
		logger.Error("workspace exceptions reload disabled: failed to start watcher", "error", err, "path", store.Path())
		return func() {}
	}
	// The store loaded the file before the watch existed. One reload queued
	// now runs after Run adds the watch, so a replace in between is not
	// missed.
	rl.Trigger()
	loopCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if runErr := rl.Run(loopCtx); runErr != nil && !errors.Is(runErr, context.Canceled) {
			logger.Error("workspace exceptions reloader stopped with error", "error", runErr, "path", store.Path())
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

// runtimeWorkspaceExceptions is the runtime's store, nil without one.
func runtimeWorkspaceExceptions(runtime *serveRuntime) *filter.WorkspaceExceptionStore {
	if runtime == nil {
		return nil
	}
	return runtime.workspaceExceptions
}

// attachWorkspaceExceptions gives the default policy and every client profile
// the store. A block reads it only when it sets apply_workspace_exceptions.
func attachWorkspaceExceptions(opts filter.Options, store *filter.WorkspaceExceptionStore) filter.Options {
	if store == nil {
		return opts
	}
	opts.ContainerCreate.WorkspaceExceptions = store
	profiles := maps.Clone(opts.Profiles)
	for name, profile := range profiles {
		profile.ContainerCreate.WorkspaceExceptions = store
		profiles[name] = profile
	}
	opts.Profiles = profiles
	return opts
}
