package programs

import "github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"

type Rule interface {
    Name() string
    Evaluate(ev *pb.EbpfEvent) (bool, string)
}
