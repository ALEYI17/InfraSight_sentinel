package open

import (
	"fmt"
	"strings"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
	"github.com/ALEYI17/InfraSight_sentinel/internal/programs"
)

type DockerSockAccess struct{}

func (r *DockerSockAccess) Name() string { return "DockerSockAccess" }

func (r *DockerSockAccess) Type() string { return programs.LoaderOpen }

func (r *DockerSockAccess) Source() string {return programs.BuiltinSource}

func (r *DockerSockAccess) Evaluate(ev *pb.EbpfEvent) *programs.RuleResult {
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
	// common docker socket locations
	if path == "/var/run/docker.sock" || path == "/run/docker.sock" || strings.HasSuffix(path, "/docker.sock") {
		msg := fmt.Sprintf(
			"Container process %s (pid=%d, image=%s) attempted to open docker socket: %s",
			ev.Comm, ev.Pid, ev.ContainerImage, snoop.Snoop.Filename,
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
        "filename": snoop.Snoop.Filename,
      },
    }
	}
	return &programs.RuleResult{
    Matched: false,
    RuleName: r.Name(),
  }
}
