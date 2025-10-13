package dynamic

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ALEYI17/InfraSight_sentinel/internal/programs"
)

func (r *YAMLRule) Validate() error{

  if err := r.validateRuleName(); err!=nil{
    return err
  }

  if err := r.validateEventType(); err!=nil{
    return err
  }

  if err := r.validateDescription(); err!=nil{
    return err
  }

  if err := r.validateMessage(); err!=nil{
    return err
  }

  return nil
}

func(r *YAMLRule) validateRuleName() error{
  if r.RuleName ==""{
    return fmt.Errorf("rule name cannot be empty")
  }
  return nil
}

func (r *YAMLRule) validateEventType() error{
  
  et := r.Type()
  validEventTypes := map[string]bool{
		programs.LoaderOpen:        true,
		programs.Loaderexecve:      true,
		programs.LoaderChmod:       true,
		programs.LoaderConnect:     true,
		programs.LoaderAccept:      true,
		programs.LoaderPtrace:      true,
		programs.LoaderMmap:        true,
		programs.LoaderMount:       true,
		programs.LoadUmount:        true,
		programs.LoadResource:      true,
		programs.LoadSyscallFreq:   true,
	}

  if !validEventTypes[et]{
    return fmt.Errorf("rule event type cannot be empty")
  }else if et == ""{
    return fmt.Errorf("rule event type cannot be empty")
  }

  return nil

}

func (r *YAMLRule) validateMessage() error{

  if r.Message == ""{
    return fmt.Errorf("rule message cannot be empty")
  }

  return nil
}

func (r *YAMLRule) validateDescription() error{

  if r.Description == ""{
    return fmt.Errorf("rule description cannot be empty")
  }

  return nil
}

func (r *YAMLRule) validateCondition() error{

  if len(r.Conditions) == 0{
    return fmt.Errorf("rule conditions cannot be empty")
  }

  for i := range r.Conditions{
    if err := r.validateSubConditions(&r.Conditions[i],&r.EventType); err !=nil{
      return err
    }
  }
  return nil
}

func (r *YAMLRule) validateSubConditions(c *Condition, et *string) error{

  if len(c.Subconditions) == 0 { 
    if c.Field == "" {
      return fmt.Errorf(" field cannot be empty in a condition")
    }

    if err := r.validateConditionField(&c.Field, et); err !=nil{
      return err
    }

    if err := r.validateConditionOperator(c);err !=nil{
      return err
    }

    return nil
  }

  for i := range c.Subconditions{
    if err := r.validateSubConditions(&c.Subconditions[i], et);err !=nil{
      return err
    }
  }

  return nil
}

func (r *YAMLRule) validateConditionOperator(c *Condition) error{

  validOperators := programs.ValidOperators()

  if _,ok := validOperators[strings.ToLower(c.Operator)];!ok{
    return fmt.Errorf("invalid operator %q",  c.Operator)
  }

  if c.Operator == "regex" && c.Value != ""{
    if _, err := regexp.Compile(c.Value); err != nil {
				return fmt.Errorf("invalid regex pattern %q: %v", c.Value, err)
			}
  }

  return nil
}

func (r *YAMLRule) validateConditionField(field *string, et *string) error{

}
