package dynamic

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
	"github.com/ALEYI17/InfraSight_sentinel/internal/programs"
)


type Condition struct {
	Field    string `yaml:"field"`
	Operator string `yaml:"operator"`
	Value    string `yaml:"value"`
}

type YAMLRule struct {
	RuleName    string        `yaml:"rule_name"`
	EventType   string            `yaml:"event_type"`
	Description string            `yaml:"description"`
	Match       map[string]string `yaml:"match"`
  Conditions  []Condition       `yaml:"conditions"`
	Message     string            `yaml:"message"`
}

func eventToMap(ev *pb.EbpfEvent) map[string]string{

  m := map[string]string{
		"pid":             fmt.Sprintf("%d", ev.Pid),
		"ppid":            fmt.Sprintf("%d", ev.Ppid),
		"user":            ev.User,
		"comm":            ev.Comm,
		"container.id":    ev.ContainerId,
		"container.image": ev.ContainerImage,
		"event_type":      ev.EventType,
	}

  switch p := ev.Payload.(type){
  case *pb.EbpfEvent_Snoop:
    if p.Snoop != nil{
      m["snoop.filename"] = p.Snoop.Filename
    }
  case *pb.EbpfEvent_Network:
    if p.Network !=nil{
      m["network.saddrv4"]= p.Network.Saddrv4
      m["network.Daddrv4"]= p.Network.Daddrv4
      m["network.Saddrv6"]= p.Network.Saddrv6
      m["network.Daddrv6"]= p.Network.Daddrv6
      m["network.Sport"]= p.Network.Sport
      m["network.Dport"]= p.Network.Dport
      m["network.SaFamily"]= p.Network.SaFamily
      m["network.ResolvedDomain"]= p.Network.ResolvedDomain
    }
  case *pb.EbpfEvent_Ptrace:
    if p.Ptrace != nil{
      m["ptrace.request"] = fmt.Sprintf("%d",p.Ptrace.Request)
      m["ptrace.TargetPid"] = fmt.Sprintf("%d",p.Ptrace.TargetPid)
      m["ptrace.Addr"] = fmt.Sprintf("%d",p.Ptrace.Addr)
      m["ptrace.Data"] = fmt.Sprintf("%d",p.Ptrace.Data)
      m["ptrace.ReturnCode"] = fmt.Sprintf("%d",p.Ptrace.ReturnCode)
      m["ptrace.RequestName"] = p.Ptrace.RequestName
    } 
  case *pb.EbpfEvent_Mount:
    if p.Mount !=nil{
      m["mount.DevName"] = p.Mount.DevName
      m["mount.DirName"] = p.Mount.DirName
      m["mount.Type"] = p.Mount.Type
      m["mount.Flags"] = fmt.Sprintf("%d",p.Mount.Flags)
      m["mount.ReturnCode"] = fmt.Sprintf("%d",p.Mount.ReturnCode)
    }
  }

  return m
}

func (r *YAMLRule) Name() string { return r.RuleName }

func (r *YAMLRule) Type() string {
	return r.EventType
}

func (r *YAMLRule) Evaluate(ev *pb.EbpfEvent) *programs.RuleResult{

  if strings.ToLower(ev.EventType) != strings.ToLower(r.EventType){
    return &programs.RuleResult{Matched: false,RuleName: r.RuleName}
  }

  Values := eventToMap(ev)
  for _,cond := range r.Conditions{
    fieldVal := Values[cond.Field]
    if !compare(fieldVal, cond.Operator, cond.Value){
      return &programs.RuleResult{Matched: false, RuleName: r.RuleName}
    }
  }

  msg := r.Message
	if msg == "" {
		msg = fmt.Sprintf("Rule %s triggered on %s", r.RuleName, ev.EventType)
	}

  return &programs.RuleResult{
		Matched:      true,
		RuleName:     r.RuleName,
		Message:      msg,
		SyscallType:  ev.EventType,
		ProcessName:  ev.Comm,
		PID:          int64(ev.Pid),
		User:         ev.User,
		ContainerID:  ev.ContainerId,
		ContainerImg: ev.ContainerImage,
	}

}


func compare(actual, op, expected string) bool {
	actual = strings.ToLower(strings.TrimSpace(actual))
	expected = strings.ToLower(strings.TrimSpace(expected))
	switch op {
	case "equals":
		return actual == expected
	case "contains":
		return strings.Contains(actual, expected)
	case "starts_with":
		return strings.HasPrefix(actual, expected)
	case "ends_with":
		return strings.HasSuffix(actual, expected)
	case "regex":
		re, err := regexp.Compile(expected)
		if err != nil {
			return false
		}
		return re.MatchString(actual)
	default:
		return false
	}
}
