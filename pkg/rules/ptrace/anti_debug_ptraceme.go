package ptrace

import (
	"fmt"
	"strings"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
	"github.com/ALEYI17/InfraSight_sentinel/internal/programs"
)

type AntiDebugPtrace struct{}

func (r *AntiDebugPtrace) Name() string { return "AntiDebugPtrace" }

func (r *AntiDebugPtrace) Type() string { return programs.LoaderPtrace }

func (r *AntiDebugPtrace) Source() string {return programs.BuiltinSource}

func (r *AntiDebugPtrace) Evaluate(ev *pb.EbpfEvent) *programs.RuleResult{
  pt, ok := ev.Payload.(*pb.EbpfEvent_Ptrace)
	if !ok || pt.Ptrace == nil {
		return &programs.RuleResult{
      Matched: false,
      RuleName: r.Name(),
    }
	}

  reqName := strings.ToUpper(strings.TrimSpace(pt.Ptrace.RequestName))

  if reqName == "PTRACE_TRACEME" || reqName == "PTRACE_ATTACH" && pt.Ptrace.TargetPid == int64(ev.Ppid) {
		msg := fmt.Sprintf("Process %s (pid=%d, user=%s) invoked ptrace request=%s target_pid=%d",
			ev.Comm, ev.Pid, ev.User, pt.Ptrace.RequestName, pt.Ptrace.TargetPid)
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
        "RequestName": reqName,
        "TargetPid": fmt.Sprint(ev.Ppid),
      },
    }
	}

  return &programs.RuleResult{
    Matched: false,
    RuleName: r.Name(),
  }
}
