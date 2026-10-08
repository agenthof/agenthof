package engine

import "github.com/agenthof/agenthof/internal/origin"

// Origin is origin.Origin — where a run's request arrived from. Stamped on
// workflow_started and run_refused only (the config_hash pattern), never on
// Binding. The type lives in the leaf package internal/origin so the
// control ledger can carry the same shape; the alias keeps every engine
// caller and the JSON byte-identical.
type Origin = origin.Origin
