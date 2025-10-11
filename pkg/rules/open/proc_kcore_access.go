package open

import (
	"fmt"
	"strings"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
	"github.com/ALEYI17/InfraSight_sentinel/internal/programs"
)

type ProcKcoreAccess struct{}

func (r *ProcKcoreAccess) Name() string { return "ProcKcoreAccess" }

func (r *ProcKcoreAccess) Type() string { return programs.LoaderOpen }

func (r *ProcKcoreAccess) Source() string {return programs.BuiltinSource}

func (r *ProcKcoreAccess) Evaluate(ev *pb.EbpfEvent) *programs.RuleResult {
	// Only consider events coming from containers
	if !programs.IsContainerEvent(ev) {
		return &programs.RuleResult{
      Matched: false,
      RuleName: r.Name(),
    }
	}

	snoop, ok := ev.Payload.(*pb.EbpfEvent_Snoop)
	if !ok || snoop.Snoop == nil {
		return &programs.RuleResult{
      Matched: false,
      RuleName: r.Name(),
    }
	}

	path := strings.TrimSpace(strings.ToLower(snoop.Snoop.Filename))
	if path == "/proc/kcore" {
		msg := fmt.Sprintf(
			"Container process %s (pid=%d, image=%s) attempted to open /proc/kcore (possible host memory access)",
			ev.Comm, ev.Pid, ev.ContainerImage,
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
        "Filename": snoop.Snoop.Filename,
      },
    }
	}

	return &programs.RuleResult{
    Matched: false,
    RuleName: r.Name(),
  }
}
