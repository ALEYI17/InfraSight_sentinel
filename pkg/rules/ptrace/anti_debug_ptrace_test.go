package ptrace

import (
	"testing"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
)

func TestAntiDebugPtrace(t *testing.T) {
	rule := &AntiDebugPtrace{}

	tests := []struct {
		name       string
		request    string
		targetPid  int64
		ppid       uint32
		expected   bool
	}{
		{"PTRACE_TRACEME always flags", "PTRACE_TRACEME", 0, 10, true},
		{"PTRACE_ATTACH to parent pid flags", "PTRACE_ATTACH", 20, 20, true},
		{"PTRACE_ATTACH to non-parent", "PTRACE_ATTACH", 30, 10, false},
		{"Other request ignored", "PTRACE_CONT", 10, 10, false},
		{"Empty request", "", 0, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &pb.EbpfEvent{
				Comm: "testproc",
				Pid:  100,
				Ppid: tt.ppid,
				User: "root",
				Payload: &pb.EbpfEvent_Ptrace{
					Ptrace: &pb.PtraceEvent{
						RequestName: tt.request,
						TargetPid:   tt.targetPid,
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

