package mount

import (
	"testing"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
)

func TestUnexpectedMount(t *testing.T) {
	rule := &UnexpectedMount{}

	tests := []struct {
		name     string
		event    *pb.EbpfEvent
		expected bool
	}{
		{
			name: "Mount /proc inside container",
			event: &pb.EbpfEvent{
				Comm:           "nginx",
				Pid:            111,
				ContainerId:    "abc123",
				ContainerImage: "nginx:latest",
				Payload: &pb.EbpfEvent_Mount{
					Mount: &pb.MountEvent{
						DirName: "/proc/sysrq-trigger",
						DevName: "tmpfs",
						Type:    "bind",
					},
				},
			},
			expected: true,
		},
		{
			name: "Bind mount host root",
			event: &pb.EbpfEvent{
				Comm:           "alpine",
				Pid:            222,
				ContainerId:    "def456",
				ContainerImage: "alpine:3.18",
				Payload: &pb.EbpfEvent_Mount{
					Mount: &pb.MountEvent{
						DirName: "/mnt/host",
						DevName: "/",
						Type:    "bind",
					},
				},
			},
			expected: true,
		},
		{
			name: "Normal container mount",
			event: &pb.EbpfEvent{
				Comm:           "worker",
				Pid:            333,
				ContainerId:    "ghi789",
				ContainerImage: "busybox",
				Payload: &pb.EbpfEvent_Mount{
					Mount: &pb.MountEvent{
						DirName: "/app/data",
						DevName: "tmpfs",
						Type:    "tmpfs",
					},
				},
			},
			expected: false,
		},
		{
			name: "Non-container event ignored",
			event: &pb.EbpfEvent{
				Comm:           "systemd",
				Pid:            444,
				ContainerId:    "", // <- not a container
				ContainerImage: "",
				Payload: &pb.EbpfEvent_Mount{
					Mount: &pb.MountEvent{
						DirName: "/etc/resolv.conf",
						DevName: "tmpfs",
						Type:    "bind",
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

