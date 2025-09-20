package open

import (
	"fmt"
	"strings"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
)

type SudoersOpen struct{}

func (r *SudoersOpen) Name() string { return "SudoersOpen" }

func isSudoersFile(pth string) bool {
	if pth == "" {
		return false
	}
	p := strings.TrimSpace(pth)
	// normalize
	if !strings.HasPrefix(p, "/") {
		return false
	}
	if p == "/etc/sudoers" {
		return true
	}
	// files under /etc/sudoers.d/
	if strings.HasPrefix(p, "/etc/sudoers.d/") {
		return true
	}
	// sometimes editors pass paths like "/tmp/.../sudoers" - ignore those
	return false
}

func (r *SudoersOpen) Evaluate(ev *pb.EbpfEvent) (bool, string){

  if snoop, ok := ev.Payload.(*pb.EbpfEvent_Snoop); ok && snoop.Snoop != nil {
		filename := strings.TrimSpace(snoop.Snoop.Filename)
		if isSudoersFile(filename) {
			msg := fmt.Sprintf("Process %s (pid=%d, user=%s, image=%s) opened sudoers file: %s (rc=%d)",
				ev.Comm, ev.Pid, ev.User, ev.ContainerImage, filename, snoop.Snoop.ReturnCode)
			return true, msg
		}
	}

  return false, ""
}
