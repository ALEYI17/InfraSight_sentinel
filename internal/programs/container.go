package programs

import "github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"

func IsContainerEvent(ev *pb.EbpfEvent) bool {
	if ev == nil {
		return false
	}
	if ev.ContainerId != "" {
		return true
	}
	if ev.ContainerImage != "" {
		return true
	}
	if ev.ContainerLabelsJson != nil && len(ev.ContainerLabelsJson) > 0 {
		return true
	}
	return false
}
