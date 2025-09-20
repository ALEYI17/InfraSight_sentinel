package open

import (
	"testing"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
)

func TestDockerSockAccess(t *testing.T) {
	rule := &DockerSockAccess{}

	tests := []struct {
		name     string
		filename string
		isContainer bool
		expected bool
	}{
		{"Docker sock in /var/run", "/var/run/docker.sock", true, true},
		{"Docker sock in /run", "/run/docker.sock", true, true},
		{"Docker sock nested", "/custom/path/docker.sock", true, true},
		{"Normal file", "/var/run/app.sock", true, false},
		{"Not a container", "/var/run/docker.sock", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &pb.EbpfEvent{
				Comm:           "testproc",
				Pid:            100,
			}
			if tt.isContainer {
				ev.ContainerId = "abc123"
        ev.ContainerImage = "nginx"
			}
			ev.Payload = &pb.EbpfEvent_Snoop{Snoop: &pb.SnooperEvent{Filename: tt.filename}}

			got, _ := rule.Evaluate(ev)
			if got != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, got)
			}
		})
	}
}

