package mount

import (
	"fmt"
	"strings"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
	"github.com/ALEYI17/InfraSight_sentinel/internal/programs"
)

type UnexpectedMount struct{}

func (r *UnexpectedMount) Name() string { return "UnexpectedMount" }

func (r *UnexpectedMount) Type() string { return programs.LoaderMount }

func (r *UnexpectedMount) Source() string {return programs.BuiltinSource}

func (r *UnexpectedMount) Evaluate(ev *pb.EbpfEvent) *programs.RuleResult {
	// Only consider mounts originating from containers
	if !programs.IsContainerEvent(ev) {
		return &programs.RuleResult{
      Matched: false,
      RuleName: r.Name(),
    }
	}

	mnt, ok := ev.Payload.(*pb.EbpfEvent_Mount)
	if !ok || mnt.Mount == nil {
		return &programs.RuleResult{
      Matched: false,
      RuleName: r.Name(),
    }
	}

	dir := strings.TrimSpace(mnt.Mount.DirName)
	src := strings.TrimSpace(mnt.Mount.DevName)
	typ := strings.TrimSpace(mnt.Mount.Type)

	// Suspicious mount targets inside containers (examples)
	suspiciousTargets := []string{"/proc", "/sys", "/dev", "/etc", "/var/run"}

	for _, t := range suspiciousTargets {
		if strings.HasPrefix(dir, t) {
			msg := fmt.Sprintf(
				"Container process %s (pid=%d, image=%s) mounted %s -> %s (type=%s)",
				ev.Comm, ev.Pid, ev.ContainerImage, src, dir, typ,
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
          "src": src,
          "dir": dir,
          "typ": typ,
        },

      }
		}
	}

	// Example: binding host root inside container (dev name "/" or similar)
	if src == "/" || src == "/host" {
		msg := fmt.Sprintf(
			"Container process %s (pid=%d, image=%s) may be bind-mounting host: %s -> %s",
			ev.Comm, ev.Pid, ev.ContainerImage, src, dir,
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
          "src": src,
          "dir": dir,
          "typ": typ,
        },

      }
	}

	return &programs.RuleResult{
    Matched: false,
    RuleName: r.Name(),
  }
}
