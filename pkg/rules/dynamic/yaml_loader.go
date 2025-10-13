package dynamic

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/ALEYI17/InfraSight_sentinel/internal/programs"
	"github.com/ALEYI17/InfraSight_sentinel/pkg/logutil"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

type RuleFile struct {
	Rules []YAMLRule `yaml:"rules"`
}


func LoadYAMLRules(dir string) ([]programs.Rule, error){
  logger := logutil.GetLogger()
  var all []programs.Rule

  err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
    if err != nil {
			return err
		}

		if d.IsDir() || !(filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml") {
			return nil
		}

    data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", path, err)
		}

    var rf RuleFile
		if err := yaml.Unmarshal(data, &rf); err != nil {
			return fmt.Errorf("failed to parse YAML %s: %w", path, err)
		}


    for i := range rf.Rules{
      rf.Rules[i].sourcePath = path
      if err := rf.Rules[i].Validate(); err !=nil{
        logger.Warn("Skipping invalid rule",
          zap.String("file", path),
          zap.String("rule", rf.Rules[i].RuleName),
          zap.Error(err),
        )
        continue
      }
      all = append(all, &rf.Rules[i])
    }

    return nil
  })

  
  if err !=nil{
    return nil,err
  }

  logger.Info("Loaded YAML rules", zap.Int("count", len(all)), zap.String("dir", dir))
  return all,nil
}

func LoadYAMLRulesFromFile(path string) ([]programs.Rule, error) {
  logger := logutil.GetLogger()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	var rf RuleFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("failed to parse YAML %s: %w", path, err)
	}

	var all []programs.Rule
	for i := range rf.Rules {
    rf.Rules[i].sourcePath=path
    if err := rf.Rules[i].Validate();err !=nil{
      logger.Warn("Skipping invalid rule",
        zap.String("file", path),
        zap.String("rule", rf.Rules[i].RuleName),
        zap.Error(err),
      )
      continue
    }
    all = append(all, &rf.Rules[i])
	}
  logger.Info("Loaded YAML rules", zap.Int("count", len(all)), zap.String("file", path))
	return all, nil
}

