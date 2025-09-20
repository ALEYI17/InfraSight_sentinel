package ptrace

import (
	"fmt"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
)

type CodeInjection struct{}

func (r *CodeInjection) Name() string { return "PtraceCodeInjection" }

func (r *CodeInjection) Evaluate(ev *pb.EbpfEvent) (bool, string) {
	pt, ok := ev.Payload.(*pb.EbpfEvent_Ptrace)
	if !ok {
		return false, ""
	}

	// Example: suspicious requests
	if pt.Ptrace.RequestName == "PTRACE_POKETEXT" || pt.Ptrace.RequestName == "PTRACE_POKEDATA" {
		msg := fmt.Sprintf(
			"Process %s (pid=%d) attempted ptrace code injection into pid=%d using %s",
			ev.Comm, ev.Pid, pt.Ptrace.TargetPid, pt.Ptrace.RequestName,
		)
		return true, msg
	}
	return false, ""
}
