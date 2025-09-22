package connect

import (
	"testing"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
)

func TestKubernetesAPIConnection(t *testing.T) {
	rule := &KubernetesAPIConnection{}

	tests := []struct {
		name     string
		event    *pb.EbpfEvent
		expected bool
	}{
		{
			name: "non-container event",
			event: &pb.EbpfEvent{
				EventType: "connect",
				Pid:       123,
				Comm:      "nginx",
				Payload: &pb.EbpfEvent_Network{
					Network: &pb.NetworkEvent{
						Daddrv4: "10.0.0.1",
						Dport:   "443",
					},
				},
				// No container fields set
			},
			expected: false,
		},
		{
			name: "container connecting to private API on 443",
			event: &pb.EbpfEvent{
				EventType:      "connect",
				Pid:            456,
				Comm:           "curl",
				ContainerId:    "abc123",
				ContainerImage: "alpine:latest",
				Payload: &pb.EbpfEvent_Network{
					Network: &pb.NetworkEvent{
						Daddrv4: "10.96.0.1",
						Dport:   "443",
					},
				},
			},
			expected: true,
		},
		{
			name: "container connecting to random port",
			event: &pb.EbpfEvent{
				EventType:      "connect",
				Pid:            789,
				Comm:           "wget",
				ContainerId:    "def456",
				ContainerImage: "busybox:latest",
				Payload: &pb.EbpfEvent_Network{
					Network: &pb.NetworkEvent{
						Daddrv4: "10.0.0.5",
						Dport:   "8080",
					},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := rule.Evaluate(tt.event)
			if res.Matched != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, res.Matched)
			}
		})
	}
}
