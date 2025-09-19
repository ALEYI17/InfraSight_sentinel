package open

import (
	"fmt"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
)

type SensitiveFileRead struct{}

func (r *SensitiveFileRead) Name() string { return "SensitiveFileRead" }

func (r *SensitiveFileRead) Evaluate(ev *pb.EbpfEvent) (bool, string){
  
  snoop, ok := ev.Payload.(*pb.EbpfEvent_Snoop)
	if !ok {
		return false, ""
	}

  if snoop.Snoop.Filename == "/etc/shadow" {
		msg := fmt.Sprintf(
			"Process %s (pid=%d, user=%s) attempted to open %s with return_code=%d",
			ev.Comm, ev.Pid, ev.User, snoop.Snoop.Filename, snoop.Snoop.ReturnCode,
		)
		return true, msg
	}
	return false, ""
}
