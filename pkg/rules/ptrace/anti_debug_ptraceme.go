package ptrace

import (
	"fmt"
	"strings"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
)

type AntiDebugPtrace struct{}

func (r *AntiDebugPtrace) Name() string { return "AntiDebugPtrace" }

func (r *AntiDebugPtrace) Evaluate(ev *pb.EbpfEvent) (bool, string){
  pt, ok := ev.Payload.(*pb.EbpfEvent_Ptrace)
	if !ok || pt.Ptrace == nil {
		return false, ""
	}

  reqName := strings.ToUpper(strings.TrimSpace(pt.Ptrace.RequestName))

  if reqName == "PTRACE_TRACEME" || reqName == "PTRACE_ATTACH" && pt.Ptrace.TargetPid == int64(ev.Ppid) {
		msg := fmt.Sprintf("Process %s (pid=%d, user=%s) invoked ptrace request=%s target_pid=%d",
			ev.Comm, ev.Pid, ev.User, pt.Ptrace.RequestName, pt.Ptrace.TargetPid)
		return true, msg
	}

  return false, ""
}
