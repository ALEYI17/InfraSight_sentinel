package rules

import (
	"path/filepath"

	"github.com/ALEYI17/InfraSight_sentinel/internal/programs"
	"github.com/ALEYI17/InfraSight_sentinel/pkg/logutil"
	"github.com/ALEYI17/InfraSight_sentinel/pkg/rules/connect"
	"github.com/ALEYI17/InfraSight_sentinel/pkg/rules/dynamic"
	"github.com/ALEYI17/InfraSight_sentinel/pkg/rules/mount"
	"github.com/ALEYI17/InfraSight_sentinel/pkg/rules/open"
	"github.com/ALEYI17/InfraSight_sentinel/pkg/rules/ptrace"
	"go.uber.org/zap"
)


var Registry = map[string][]programs.Rule{}


func InitRules() {
  logger := logutil.GetLogger()
  Registry[programs.LoaderOpen] = open.Register()
	Registry[programs.LoaderMount] = mount.Register()
	Registry[programs.LoaderConnect] = connect.Register()
	Registry[programs.LoaderPtrace] = ptrace.Register()

  yamlDir := filepath.Join("rules")

  yamlRules, err := dynamic.LoadYAMLRules(yamlDir)

  if err != nil {
		logger.Warn("Failed to load YAML rules", zap.Error(err))
		return
	}

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

  for _, r := range yamlRules {
		et := r.Type()
    if !validEventTypes[et]{
      logger.Warn("Skipping YAML rule, for invalid event type", zap.String("name", r.Name()),zap.String("eventType", et))
      continue
    }
		Registry[et] = append(Registry[et], r)
    logger.Info("Load rule", zap.String("name", r.Name()))
	}

  
}
