package dynamic

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/ALEYI17/InfraSight_sentinel/internal/programs"
	"gopkg.in/yaml.v3"
)

type RuleFile struct {
	Rules []YAMLRule `yaml:"rules"`
}


func LoadYAMLRules(dir string) ([]programs.Rule, error){
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

    for _, r := range rf.Rules{
      all = append(all, &r)
    }

    return nil
  })

  
  if err !=nil{
    return nil,err
  }

  return all,nil
}
