package ptrace

import (
	"testing"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
)

func TestCodeInjection(t *testing.T) {
	rule := &CodeInjection{}

	tests := []struct {
		name      string
		request   string
		expected  bool
	}{
		{"Poketext triggers", "PTRACE_POKETEXT", true},
		{"Pokedata triggers", "PTRACE_POKEDATA", true},
		{"Other request ignored", "PTRACE_GETREGS", false},
		{"Empty request ignored", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &pb.EbpfEvent{
				Comm: "injector",
				Pid:  200,
				Payload: &pb.EbpfEvent_Ptrace{
					Ptrace: &pb.PtraceEvent{
						RequestName: tt.request,
						TargetPid:   999,
					},
				},
			}

			res := rule.Evaluate(ev)
			if res.Matched != tt.expected {
				t.Errorf("expected %v, got %v (req=%s)", tt.expected, res.Matched, tt.request)
			}
		})
	}
}

