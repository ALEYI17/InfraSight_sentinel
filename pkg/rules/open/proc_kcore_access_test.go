package open

import (
	"testing"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
)

func TestProcKcoreAccess(t *testing.T) {
	rule := &ProcKcoreAccess{}

	tests := []struct {
		name     string
		filename string
		isContainer bool
		expected bool
	}{
		{"Access /proc/kcore inside container", "/proc/kcore", true, true},
		{"Other file inside container", "/etc/passwd", true, false},
		{"/proc/kcore but not container", "/proc/kcore", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &pb.EbpfEvent{
				Comm: "testproc",
				Pid:  200,
			}
			if tt.isContainer {
				ev.ContainerId = "cid123"
				ev.ContainerImage = "alpine"
			}
			ev.Payload = &pb.EbpfEvent_Snoop{Snoop: &pb.SnooperEvent{Filename: tt.filename}}

			got, _ := rule.Evaluate(ev)
			if got != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, got)
			}
		})
	}
}

