package execve

import (
	"fmt"
	"strings"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
)

type FilelessExecution struct{}

func (r *FilelessExecution) Name() string { return "FilelessExecution" }

func (r *FilelessExecution) Evaluate(ev *pb.EbpfEvent) (bool, string) {
	snoop, ok := ev.Payload.(*pb.EbpfEvent_Snoop)
	if !ok || snoop.Snoop == nil {
		return false, ""
	}

	path := snoop.Snoop.Filename
	if isMemoryPath(path) {
		msg := fmt.Sprintf(
			"Fileless execution detected: process %s (pid=%d, user=%s, image=%s) executed binary from memory path: %s",
			ev.Comm, ev.Pid, ev.User, ev.ContainerImage, path,
		)
		return true, msg
	}

	return false, ""
}

func isMemoryPath(path string) bool {
	if strings.HasPrefix(path, "memfd:") ||
		strings.HasPrefix(path, "/run/shm/") ||
		strings.HasPrefix(path, "/dev/shm/") {
		return true
	}
	return false
}
