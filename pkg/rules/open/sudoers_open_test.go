package open

import (
	"testing"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
)

func TestSudoersOpen(t *testing.T) {
	rule := &SudoersOpen{}

	tests := []struct {
		name     string
		filename string
		expected bool
	}{
		{"Edit main sudoers", "/etc/sudoers", true},
		{"Edit sudoers.d file", "/etc/sudoers.d/custom", true},
		{"Edit temp file not sudoers", "/tmp/sudoers", false},
		{"Other file", "/etc/passwd", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &pb.EbpfEvent{
				Comm:           "vi",
				Pid:            400,
				User:           "root",
				ContainerImage: "debian",
				Payload: &pb.EbpfEvent_Snoop{
					Snoop: &pb.SnooperEvent{Filename: tt.filename, ReturnCode: 0},
				},
			}

			res := rule.Evaluate(ev)
			if res.Matched != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, res.Matched)
			}
		})
	}
}

