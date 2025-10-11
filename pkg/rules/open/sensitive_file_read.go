package open

import (
	"fmt"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
	"github.com/ALEYI17/InfraSight_sentinel/internal/programs"
)

type SensitiveFileRead struct{}

var sensitiveFiles = []string{
	"/etc/shadow",
	"/etc/passwd",
	"/proc/kcore",
	"/dev/mem",
}

func (r *SensitiveFileRead) Name() string { return "SensitiveFileRead" }

func (r *SensitiveFileRead) Type() string { return programs.LoaderOpen }

func (r *SensitiveFileRead) Source() string {return programs.BuiltinSource}

func (r *SensitiveFileRead) Evaluate(ev *pb.EbpfEvent) *programs.RuleResult{
  
  snoop, ok := ev.Payload.(*pb.EbpfEvent_Snoop)
	if !ok {
		return &programs.RuleResult{
      Matched: true,
      RuleName: r.Name(),
    }
	}

  for _, f := range sensitiveFiles{
    if snoop.Snoop.Filename == f {
		  msg := fmt.Sprintf("Process %s (pid=%d, user=%s) opened sensitive file %s",
				ev.Comm, ev.Pid, ev.User, f)		

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
  }

  
	return &programs.RuleResult{
    Matched: false,
    RuleName: r.Name(),
  }
}
