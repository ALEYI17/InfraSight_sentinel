package open

import (
	"fmt"
	"strings"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
	"github.com/ALEYI17/InfraSight_sentinel/internal/programs"
)

type DockerSockAccess struct{}

func (r *DockerSockAccess) Name() string { return "DockerSockAccess" }

func (r *DockerSockAccess) Evaluate(ev *pb.EbpfEvent) (bool, string) {
	// Only consider events coming from containers
	if !programs.IsContainerEvent(ev) {
		return false, ""
	}

	snoop, ok := ev.Payload.(*pb.EbpfEvent_Snoop)
	if !ok || snoop.Snoop == nil {
		return false, ""
	}

	path := strings.TrimSpace(strings.ToLower(snoop.Snoop.Filename))
	// common docker socket locations
	if path == "/var/run/docker.sock" || path == "/run/docker.sock" || strings.HasSuffix(path, "/docker.sock") {
		msg := fmt.Sprintf(
			"Container process %s (pid=%d, image=%s) attempted to open docker socket: %s",
			ev.Comm, ev.Pid, ev.ContainerImage, snoop.Snoop.Filename,
		)
		return true, msg
	}
	return false, ""
}
