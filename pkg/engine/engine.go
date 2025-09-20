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
    if ok,msg := rule.Evaluate(ev);ok{
      logger.Info("alert", zap.String("alert from", rule.Name()),zap.String("msg", msg), zap.String("syscall_type", ev.EventType))
    }
  }
}
