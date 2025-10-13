package dynamic

import (
	"testing"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
)

func TestYAMLRule_Evaluate(t *testing.T) {
	rule := YAMLRule{
		RuleName:    "Root SSH Connection (Simple OR)",
		EventType:   "connect",
		Description: "Triggers when the user is root OR the destination port is 22",
		Logic:       "or",
		Conditions: []Condition{
			{Field: "user", Operator: "equals", Value: "root"},
			{Field: "network.Dport", Operator: "equals", Value: "22"},
		},
		Message: "Possible SSH connection or root activity detected",
	}

	tests := []struct {
		name     string
		event    *pb.EbpfEvent
		expected bool
	}{
		{
			name: "Matches root user",
			event: &pb.EbpfEvent{
				User: "root",
        EventType: "connect",
				Payload: &pb.EbpfEvent_Network{
					Network: &pb.NetworkEvent{Dport: "8080"},
				},
			},
			expected: true,
		},
		{
			name: "Matches port 22",
			event: &pb.EbpfEvent{
				User: "alice",
        EventType: "connect",
				Payload: &pb.EbpfEvent_Network{
					Network: &pb.NetworkEvent{Dport: "22"},
				},
			},
			expected: true,
		},
		{
			name: "No match",
			event: &pb.EbpfEvent{
				User: "bob",
        EventType: "connect",
				Payload: &pb.EbpfEvent_Network{
					Network: &pb.NetworkEvent{Dport: "80"},
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

func TestYAMLRule_Evaluate_subcondition(t *testing.T){
  rule := YAMLRule{
    RuleName:    "Root SSH or Port 22 Activity",
    EventType:   "connect",
    Description: "Triggers when root user connects and (port 22 or ssh process)",
    Logic:       "and",
    Conditions: []Condition{
        {
            Field:    "user",
            Operator: "equals",
            Value:    "root",
        },
        {
            Logic: "or",
            Subconditions: []Condition{
                {Field: "network.Dport", Operator: "equals", Value: "22"},
                {Field: "comm", Operator: "contains", Value: "ssh"},
            },
        },
    },
    Message: "Root user SSH-related connection detected",
  }

  tests := []struct {
    name     string
    event    *pb.EbpfEvent
    expected bool
  }{
    {
        name: "root user and port 22 → match",
        event: &pb.EbpfEvent{
            User:      "root",
            EventType: "connect",
            Comm:      "curl",
            Payload: &pb.EbpfEvent_Network{
                Network: &pb.NetworkEvent{Dport: "22"},
            },
        },
        expected: true,
    },
    {
        name: "root user and ssh process → match",
        event: &pb.EbpfEvent{
            User:      "root",
            EventType: "connect",
            Comm:      "ssh-agent",
            Payload: &pb.EbpfEvent_Network{
                Network: &pb.NetworkEvent{Dport: "8080"},
            },
        },
        expected: true,
    },
    {
        name: "root user but unrelated port/process → no match",
        event: &pb.EbpfEvent{
            User:      "root",
            EventType: "connect",
            Comm:      "nginx",
            Payload: &pb.EbpfEvent_Network{
                Network: &pb.NetworkEvent{Dport: "443"},
            },
        },
        expected: false,
    },
    {
        name: "non-root user even if port 22 → no match",
        event: &pb.EbpfEvent{
            User:      "alice",
            EventType: "connect",
            Comm:      "ssh",
            Payload: &pb.EbpfEvent_Network{
                Network: &pb.NetworkEvent{Dport: "22"},
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

func TestYAMLRule_compare(t *testing.T){

  tests := []struct {
	name     string
	actual   string
	op       string
	expected string
	want     bool
  }{
    // ====== Equals / == ======
    {"equals string match", "root", "equals", "root", true},
    {"equals string mismatch", "root", "equals", "admin", false},
    {"equals numeric match", "22", "equals", "22", true},
    {"equals numeric mismatch", "22", "equals", "80", false},

    // ====== Not Equals / != ======
    {"not equals string match", "root", "!=", "admin", true},
    {"not equals string mismatch", "root", "!=", "root", false},
    {"not equals numeric match", "22", "!=", "80", true},
    {"not equals numeric mismatch", "22", "!=", "22", false},

    // ====== Greater Than / > ======
    {"greater than valid", "5", ">", "3", true},
    {"greater than invalid", "2", ">", "5", false},
    {"greater than non-numeric", "foo", ">", "bar", false},

    // ====== Greater Equal / >= ======
    {"greater equal valid equal", "5", ">=", "5", true},
    {"greater equal valid greater", "6", ">=", "5", true},
    {"greater equal invalid", "3", ">=", "5", false},

    // ====== Less Than / < ======
    {"less than valid", "3", "<", "5", true},
    {"less than invalid", "7", "<", "5", false},
    {"less than non-numeric", "foo", "<", "bar", false},

    // ====== Less Equal / <= ======
    {"less equal valid equal", "5", "<=", "5", true},
    {"less equal valid less", "3", "<=", "5", true},
    {"less equal invalid", "8", "<=", "5", false},

    // ====== Contains ======
    {"contains valid", "hello world", "contains", "world", true},
    {"contains invalid", "hello", "contains", "bye", false},

    // ====== Not Contains ======
    {"not contains valid", "hello world", "not_contains", "bye", true},
    {"not contains invalid", "hello world", "not_contains", "world", false},

    // ====== Starts With ======
    {"starts with valid", "foobar", "starts_with", "foo", true},
    {"starts with invalid", "foobar", "starts_with", "bar", false},

    // ====== Ends With ======
    {"ends with valid", "foobar", "ends_with", "bar", true},
    {"ends with invalid", "foobar", "ends_with", "foo", false},

    // ====== Regex ======
    {"regex valid", "abc123", "regex", "^[a-z]+[0-9]+$", true},
    {"regex invalid", "abc123", "regex", "^[0-9]+$", false},
    {"regex bad pattern", "abc", "regex", "[invalid", false},

    // ====== In ======
    {"in valid", "22", "in", "22,80,443", true},
    {"in invalid", "21", "in", "22,80,443", false},

    // ====== Not In ======
    {"not in valid", "21", "not_in", "22,80,443", true},
    {"not in invalid", "22", "not_in", "22,80,443", false},

    // ====== Double Equals & Alt Variants ======
    {"double equals valid", "root", "==", "root", true},
    {"double equals invalid", "root", "==", "admin", false},
  }

  for _, tt := range tests {
	t.Run(tt.name, func(t *testing.T) {
		got := compare(tt.actual, tt.op, tt.expected)
		if got != tt.want {
			t.Errorf("compare(%q, %q, %q) = %v; want %v",
				tt.actual, tt.op, tt.expected, got, tt.want)
		}
	})
}
}


