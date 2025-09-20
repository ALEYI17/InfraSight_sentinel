package mount

import (
	"fmt"
	"strings"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
	"github.com/ALEYI17/InfraSight_sentinel/internal/programs"
)

type UnexpectedMount struct{}

func (r *UnexpectedMount) Name() string { return "UnexpectedMount" }

func (r *UnexpectedMount) Evaluate(ev *pb.EbpfEvent) (bool, string) {
	// Only consider mounts originating from containers
	if !programs.IsContainerEvent(ev) {
		return false, ""
	}

	mnt, ok := ev.Payload.(*pb.EbpfEvent_Mount)
	if !ok || mnt.Mount == nil {
		return false, ""
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
			return true, msg
		}
	}

	// Example: binding host root inside container (dev name "/" or similar)
	if src == "/" || src == "/host" {
		msg := fmt.Sprintf(
			"Container process %s (pid=%d, image=%s) may be bind-mounting host: %s -> %s",
			ev.Comm, ev.Pid, ev.ContainerImage, src, dir,
		)
		return true, msg
	}

	return false, ""
}
