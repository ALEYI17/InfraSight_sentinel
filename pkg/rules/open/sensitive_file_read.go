package open

import (
	"fmt"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
)

type SensitiveFileRead struct{}

var sensitiveFiles = []string{
	"/etc/shadow",
	"/etc/passwd",
	"/proc/kcore",
	"/dev/mem",
}

func (r *SensitiveFileRead) Name() string { return "SensitiveFileRead" }

func (r *SensitiveFileRead) Evaluate(ev *pb.EbpfEvent) (bool, string){
  
  snoop, ok := ev.Payload.(*pb.EbpfEvent_Snoop)
	if !ok {
		return false, ""
	}

  for _, f := range sensitiveFiles{
    if snoop.Snoop.Filename == f {
		  msg := fmt.Sprintf("Process %s (pid=%d, user=%s) opened sensitive file %s",
				ev.Comm, ev.Pid, ev.User, f)		

      return true, msg
	  }
  }

  
	return false, ""
}
