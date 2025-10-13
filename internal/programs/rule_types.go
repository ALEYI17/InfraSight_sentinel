package programs

import "github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"

type Rule interface {
    Name() string
    Evaluate(ev *pb.EbpfEvent) *RuleResult
    Type() string
    Source() string
}

type RuleResult struct {
    Matched      bool
    RuleName     string
    Message      string
    SyscallType  string
    ProcessName  string
    PID          int64
    User         string
    ContainerID  string
    ContainerImg string
    Extra        map[string]string // for flexible metadata
}

const BuiltinSource = "builtin"

const (
	OpEquals          = "equals"
	OpDoubleEquals    = "=="
	OpNotEquals       = "not_equals"
	OpNotEqualsAlt    = "!="
	OpGreaterThan     = "greater_than"
	OpGreaterThanAlt  = ">"
	OpGreaterEqual    = "greater_or_equal"
	OpGreaterEqualAlt = ">="
	OpLessThan        = "less_than"
	OpLessThanAlt     = "<"
	OpLessEqual       = "less_or_equal"
	OpLessEqualAlt    = "<="
	OpContains        = "contains"
	OpNotContains     = "not_contains"
	OpStartsWith      = "starts_with"
	OpEndsWith        = "ends_with"
	OpRegex           = "regex"
	OpIn              = "in"
	OpNotIn           = "not_in"
)

func ValidOperators() map[string]struct{} {
	return map[string]struct{}{
		OpEquals:          {},
		OpDoubleEquals:    {},
		OpNotEquals:       {},
		OpNotEqualsAlt:    {},
		OpGreaterThan:     {},
		OpGreaterThanAlt:  {},
		OpGreaterEqual:    {},
		OpGreaterEqualAlt: {},
		OpLessThan:        {},
		OpLessThanAlt:     {},
		OpLessEqual:       {},
		OpLessEqualAlt:    {},
		OpContains:        {},
		OpNotContains:     {},
		OpStartsWith:      {},
		OpEndsWith:        {},
		OpRegex:           {},
		OpIn:              {},
		OpNotIn:           {},
	}
}

var EventTypeToPayload = map[string]string{
    "connect": "network",
    "accept":  "network",
    "open":    "snoop",
    "execve":  "snoop",
    "chmod":   "snoop",
    "ptrace":  "ptrace",
    "mount":   "mount",
    "umount":  "mount",
    // etc.
}

var AllowedFieldsByEventType = map[string][]string{
	"snoop": {
		"pid", "ppid", "user", "comm", "container.id", "container.image", "event_type",
		"snoop.filename",
	},
	"network": {
		"pid", "ppid", "user", "comm", "container.id", "container.image", "event_type",
		"network.Saddrv4", "network.Daddrv4", "network.Saddrv6", "network.Daddrv6",
		"network.Sport", "network.Dport", "network.SaFamily", "network.ResolvedDomain",
	},
	"ptrace": {
		"pid", "ppid", "user", "comm", "container.id", "container.image", "event_type",
		"ptrace.Request", "ptrace.TargetPid", "ptrace.Addr", "ptrace.Data",
		"ptrace.ReturnCode", "ptrace.RequestName",
	},
	"mount": {
		"pid", "ppid", "user", "comm", "container.id", "container.image", "event_type",
		"mount.DevName", "mount.DirName", "mount.Type", "mount.Flags", "mount.ReturnCode",
	},
}

