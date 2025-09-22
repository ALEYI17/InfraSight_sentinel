package execve

import (
	"testing"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
)

func TestFilelessExecution(t *testing.T) {
	rule := &FilelessExecution{}

	tests := []struct {
		name     string
		event    *pb.EbpfEvent
		expected bool
	}{
		{
			name: "Fileless execution via memfd",
			event: &pb.EbpfEvent{
				Comm:           "evil",
				Pid:            1234,
				User:           "root",
				ContainerImage: "nginx:latest",
				Payload: &pb.EbpfEvent_Snoop{
					Snoop: &pb.SnooperEvent{
						Filename: "memfd:malware",
					},
				},
			},
			expected: true,
		},
		{
			name: "Normal execve binary",
			event: &pb.EbpfEvent{
				Comm:           "bash",
				Pid:            5678,
				User:           "alice",
				ContainerImage: "ubuntu:22.04",
				Payload: &pb.EbpfEvent_Snoop{
					Snoop: &pb.SnooperEvent{
						Filename: "/usr/bin/bash",
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
				t.Errorf("expected %v, got %v (msg=%s)", tt.expected, res.Matched, res.Message)
			}
		})
	}
}

