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
