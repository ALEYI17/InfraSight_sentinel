package ptrace

import (
	"fmt"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
	"github.com/ALEYI17/InfraSight_sentinel/internal/programs"
)

type CodeInjection struct{}

func (r *CodeInjection) Name() string { return "PtraceCodeInjection" }

func (r *CodeInjection) Evaluate(ev *pb.EbpfEvent)  *programs.RuleResult{
	pt, ok := ev.Payload.(*pb.EbpfEvent_Ptrace)
	if !ok {
		return &programs.RuleResult{
      Matched: false,
      RuleName: r.Name(),
    }
	}

	// Example: suspicious requests
	if pt.Ptrace.RequestName == "PTRACE_POKETEXT" || pt.Ptrace.RequestName == "PTRACE_POKEDATA" {
		msg := fmt.Sprintf(
			"Process %s (pid=%d) attempted ptrace code injection into pid=%d using %s",
			ev.Comm, ev.Pid, pt.Ptrace.TargetPid, pt.Ptrace.RequestName,
		)
		return &programs.RuleResult{
      Matched: true,
      RuleName:     r.Name(),
      Message:      msg,
      SyscallType:  ev.EventType,
      ProcessName:  ev.Comm,
      PID:          int64(ev.Pid),
      User:         ev.User,
      ContainerID:  ev.ContainerId,
      ContainerImg: ev.ContainerImage,
      Extra: map[string]string{
        "RequestName": pt.Ptrace.RequestName,
        "TargetPid": fmt.Sprint(ev.Ppid),
      },
    }
	}
	return &programs.RuleResult{
      Matched: false,
      RuleName: r.Name(),
  }
}
