package engine

import (
	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
	"github.com/ALEYI17/InfraSight_sentinel/pkg/logutil"
	"github.com/ALEYI17/InfraSight_sentinel/pkg/rules"
	"go.uber.org/zap"
)


func HandleEvent(ev *pb.EbpfEvent) {
  logger := logutil.GetLogger()
  applicablerules,ok := rules.Registry[ev.EventType]

  if len(applicablerules) == 0 || !ok{
    return
  }

  for _,rule := range applicablerules{
    if res := rule.Evaluate(ev); res.Matched {
			// Build zap fields for structured logging
			fields := []zap.Field{
				zap.String("rule", res.RuleName),
				zap.String("message", res.Message),
				zap.String("syscall_type", res.SyscallType),
				zap.String("process", res.ProcessName),
				zap.Int64("pid", res.PID),
				zap.String("user", res.User),
				zap.String("container_id", res.ContainerID),
				zap.String("container_image", res.ContainerImg),
			}

			// Add any extra metadata dynamically
			for k, v := range res.Extra {
				fields = append(fields, zap.String("extra."+k, v))
			}

			logger.Info("alert", fields...)
		}
  }
}
