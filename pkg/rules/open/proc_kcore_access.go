package open

import (
	"fmt"
	"strings"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
	"github.com/ALEYI17/InfraSight_sentinel/internal/programs"
)

type ProcKcoreAccess struct{}

func (r *ProcKcoreAccess) Name() string { return "ProcKcoreAccess" }

func (r *ProcKcoreAccess) Evaluate(ev *pb.EbpfEvent) (bool, string) {
	// Only consider events coming from containers
	if !programs.IsContainerEvent(ev) {
		return false, ""
	}

	snoop, ok := ev.Payload.(*pb.EbpfEvent_Snoop)
	if !ok || snoop.Snoop == nil {
		return false, ""
	}

	path := strings.TrimSpace(strings.ToLower(snoop.Snoop.Filename))
	if path == "/proc/kcore" {
		msg := fmt.Sprintf(
			"Container process %s (pid=%d, image=%s) attempted to open /proc/kcore (possible host memory access)",
			ev.Comm, ev.Pid, ev.ContainerImage,
		)
		return true, msg
	}

	return false, ""
}
