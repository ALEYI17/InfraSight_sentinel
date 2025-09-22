package open

import (
	"testing"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
)

func TestSensitiveFileRead(t *testing.T) {
	rule := &SensitiveFileRead{}

	tests := []struct {
		name     string
		filename string
		expected bool
	}{
		{"Read shadow", "/etc/shadow", true},
		{"Read passwd", "/etc/passwd", true},
		{"Read non-sensitive", "/app/config.yaml", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &pb.EbpfEvent{
				Comm: "testproc",
				Pid:  300,
				User: "root",
				Payload: &pb.EbpfEvent_Snoop{
					Snoop: &pb.SnooperEvent{Filename: tt.filename},
				},
			}

			res := rule.Evaluate(ev)
			if res.Matched != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, res.Matched)
			}
		})
	}
}

