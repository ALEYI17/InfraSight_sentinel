package dynamic

import (
	"testing"
)

func TestYAMLRule_Validate(t *testing.T) {
	tests := []struct {
		name    string
		rule    YAMLRule
		wantErr bool
	}{
		{
			name: "valid connect rule",
			rule: YAMLRule{
				RuleName:    "Root SSH Connection",
				EventType:   "connect",
				Description: "Valid rule for SSH connections",
				Logic:       "or",
				Conditions: []Condition{
					{Field: "user", Operator: "equals", Value: "root"},
					{Field: "network.Dport", Operator: "equals", Value: "22"},
				},
				Message: "Possible SSH connection",
			},
			wantErr: false,
		},
		{
			name: "invalid event type",
			rule: YAMLRule{
				RuleName:    "Invalid Event Type",
				EventType:   "foo", // not in validEventTypes
				Description: "This should fail",
				Logic:       "or",
				Conditions: []Condition{
					{Field: "user", Operator: "equals", Value: "root"},
				},
				Message: "Should not pass",
			},
			wantErr: true,
		},
		{
			name: "empty condition value",
			rule: YAMLRule{
				RuleName:    "Empty Condition Value",
				EventType:   "connect",
				Description: "Missing value should fail",
				Logic:       "or",
				Conditions: []Condition{
					{Field: "user", Operator: "equals", Value: ""},
				},
				Message: "Should not pass",
			},
			wantErr: true,
		},
    {
      name: "missing description",
      rule: YAMLRule{
        RuleName:  "Missing Description",
        EventType: "connect",
        Logic:     "and",
        Conditions: []Condition{
          {Field: "user", Operator: "equals", Value: "root"},
        },
        Message: "Missing description should fail",
      },
		  wantErr: true,
	  },
    {
      name: "missing message",
      rule: YAMLRule{
        RuleName:    "Missing Message",
        EventType:   "connect",
        Description: "Missing message validation",
        Logic:       "and",
        Conditions: []Condition{
          {Field: "user", Operator: "equals", Value: "root"},
        },
      },
      wantErr: true,
    },
    {
      name: "invalid logic operator",
      rule: YAMLRule{
        RuleName:    "Invalid Logic",
        EventType:   "connect",
        Description: "Logic must be 'and' or 'or'",
        Logic:       "xor",
        Conditions: []Condition{
          {Field: "user", Operator: "equals", Value: "root"},
        },
        Message: "Should fail due to invalid logic",
      },
      wantErr: true,
    },
    {
      name: "empty conditions list",
      rule: YAMLRule{
        RuleName:    "No Conditions",
        EventType:   "connect",
        Description: "Must have at least one condition",
        Logic:       "and",
        Message:     "Should fail with empty conditions",
      },
      wantErr: true,
    },
    {
      name: "invalid field for event type",
      rule: YAMLRule{
        RuleName:    "Invalid Field",
        EventType:   "execve",
        Description: "Uses non-existent field",
        Logic:       "and",
        Conditions: []Condition{
          {Field: "invalid_field", Operator: "equals", Value: "foo"},
        },
        Message: "Should fail due to invalid field",
      },
      wantErr: true,
    },
    {
      name: "valid field but for wrong event type",
      rule: YAMLRule{
        RuleName:    "Wrong Event Field",
        EventType:   "connect",
        Description: "Field not applicable to connect events",
        Logic:       "and",
        Conditions: []Condition{
          {Field: "filename", Operator: "contains", Value: "/etc/passwd"},
        },
        Message: "Should fail since 'filename' isn't valid for connect events",
      },
      wantErr: true,
    },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

