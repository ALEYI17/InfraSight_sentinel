package execve

import (
	"fmt"
	"strings"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
	"github.com/ALEYI17/InfraSight_sentinel/internal/programs"
)

type FilelessExecution struct{}

func (r *FilelessExecution) Name() string { return "FilelessExecution" }

func (r *FilelessExecution) Evaluate(ev *pb.EbpfEvent) *programs.RuleResult {
	snoop, ok := ev.Payload.(*pb.EbpfEvent_Snoop)
	if !ok || snoop.Snoop == nil {
		return &programs.RuleResult{
      Matched: false,
      RuleName: r.Name(),
    }
	}

	path := snoop.Snoop.Filename
	if isMemoryPath(path) {
		msg := fmt.Sprintf(
			"Fileless execution detected: process %s (pid=%d, user=%s, image=%s) executed binary from memory path: %s",
			ev.Comm, ev.Pid, ev.User, ev.ContainerImage, path,
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
        "path": path,
      },
    }
	}

	return &programs.RuleResult{
    Matched: false,
    RuleName: r.Name(),
  }
}

func isMemoryPath(path string) bool {
	if strings.HasPrefix(path, "memfd:") ||
		strings.HasPrefix(path, "/run/shm/") ||
		strings.HasPrefix(path, "/dev/shm/") {
		return true
	}
	return false
}
