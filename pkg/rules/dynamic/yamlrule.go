package dynamic

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
	"github.com/ALEYI17/InfraSight_sentinel/internal/programs"
)


type Condition struct {
	Field    string `yaml:"field"`
	Operator string `yaml:"operator"`
	Value    string `yaml:"value"`
  Logic    string `yaml:"logic,omitempty"`
  Subconditions []Condition  `yaml:"subconditions,omitempty"`
}

type YAMLRule struct {
	RuleName    string            `yaml:"rule_name"`
	EventType   string            `yaml:"event_type"`
	Description string            `yaml:"description"`
  Logic       string            `yaml:"logic,omitempty"`
  Conditions  []Condition       `yaml:"conditions"`
	Message     string            `yaml:"message"`

  sourcePath string
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

func (r *YAMLRule) Type() string { return r.EventType }

func (r *YAMLRule) Source() string {return r.sourcePath}

func (r *YAMLRule) Evaluate(ev *pb.EbpfEvent) *programs.RuleResult{

  if strings.ToLower(ev.EventType) != strings.ToLower(r.EventType){
    return &programs.RuleResult{Matched: false,RuleName: r.RuleName}
  }

  Values := eventToMap(ev)
  if !evaluateConditionsWithLogic(r.Conditions, Values,r.Logic){
    return &programs.RuleResult{Matched: false, RuleName: r.RuleName}
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

func evaluateConditionsWithLogic(conds []Condition, values map[string]string, logic string) bool{
  if len(conds) == 0 {
		return true
	}

  results := make([]bool, 0, len(conds))
  for _, cond := range conds {
		results = append(results, evaluateCondition(cond, values))
	}

  logic = strings.ToLower(strings.TrimSpace(logic))
	if logic == "" {
		logic = "and"
	}

	if logic == "or" {
		for _, r := range results {
			if r {
				return true
			}
		}
		return false
	}

  for _, r := range results {
		if !r {
			return false
		}
	}
	return true
}

func evaluateCondition(c Condition, values map[string]string) bool {
	if len(c.Subconditions) > 0 {
		return evaluateConditionsWithLogic(c.Subconditions, values, c.Logic)
	}

	//actual := values[c.Field]
  var actual string
	for k, v := range values {
		if strings.EqualFold(k, c.Field) {
			actual = v
			break
		}
	}
	return compare(actual, c.Operator, c.Value)
}

func compare(actual, op, expected string) bool {
	actual = strings.TrimSpace(actual)
	expected = strings.TrimSpace(expected)
  op = strings.ToLower(strings.TrimSpace(op))

  aNum, aErr := strconv.ParseFloat(actual, 64)
	eNum, eErr := strconv.ParseFloat(expected, 64)
	isNumeric := aErr == nil && eErr == nil
	switch op {
	case programs.OpEquals, programs.OpDoubleEquals:
    if isNumeric{
      return aNum == eNum
    }
		return strings.EqualFold(actual, expected)
  case programs.OpNotEqualsAlt, programs.OpNotEquals:
    if isNumeric {
			return aNum != eNum
		}
    return !strings.EqualFold(actual, expected)
  case programs.OpGreaterThanAlt,programs.OpGreaterThan:
    return isNumeric && aNum > eNum
  case programs.OpGreaterEqualAlt , programs.OpGreaterEqual:
    return isNumeric && aNum >= eNum
  case programs.OpLessThanAlt, programs.OpLessThan:
    return isNumeric && aNum < eNum
  case programs.OpLessEqualAlt, programs.OpLessEqual:
    return isNumeric && aNum <= eNum
	case programs.OpContains:
		return strings.Contains(actual, expected)
  case programs.OpNotContains:
    return !strings.Contains(strings.ToLower(actual), strings.ToLower(expected))
	case programs.OpStartsWith:
		return strings.HasPrefix(actual, expected)
	case programs.OpEndsWith:
		return strings.HasSuffix(actual, expected)
	case programs.OpRegex:
		re, err := regexp.Compile(expected)
		if err != nil {
			return false
		}
		return re.MatchString(actual)
  case programs.OpIn:
    values := strings.Split(expected, ",")
    for _,v := range values{
      if strings.EqualFold(strings.TrimSpace(v),strings.TrimSpace(actual)){
        return true
      }
    }
    return false
  case programs.OpNotIn:
    values := strings.Split(expected, ",")
    for _,v := range values{
      if strings.EqualFold(strings.TrimSpace(v), strings.TrimSpace(actual)){
        return false
      }
    }
    return true
	default:
		return false
	}
}



