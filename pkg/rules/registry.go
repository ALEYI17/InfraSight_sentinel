package rules

import (
	"path/filepath"
	"sync"
	"time"

	"github.com/ALEYI17/InfraSight_sentinel/internal/programs"
	"github.com/ALEYI17/InfraSight_sentinel/pkg/logutil"
	"github.com/ALEYI17/InfraSight_sentinel/pkg/rules/connect"
	"github.com/ALEYI17/InfraSight_sentinel/pkg/rules/dynamic"
	"github.com/ALEYI17/InfraSight_sentinel/pkg/rules/mount"
	"github.com/ALEYI17/InfraSight_sentinel/pkg/rules/open"
	"github.com/ALEYI17/InfraSight_sentinel/pkg/rules/ptrace"
	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

type RuleRegister struct{
  mu sync.RWMutex
  Registry map[string][]programs.Rule
  path     string
  watcher *fsnotify.Watcher
  stopCh  chan struct{}
}

func NewRuleRegister(path string) (*RuleRegister,error){
  w,err := fsnotify.NewWatcher()
  if err !=nil{
    return nil,err
  }

  r := &RuleRegister{
		Registry: make(map[string][]programs.Rule),
		path:     path,
    watcher: w,
    stopCh:   make(chan struct{}),
	}
  
  r.InitRules()

  err = r.addWatch()
  if err !=nil{
    return nil,err
  }

  go r.watch()
  
  return r,nil
}


func (r *RuleRegister) InitRules() {
  logger := logutil.GetLogger()

  r.mu.Lock()
  defer r.mu.Unlock()

  r.Registry = map[string][]programs.Rule{}
  r.Registry[programs.LoaderOpen] = open.Register()
	r.Registry[programs.LoaderMount] = mount.Register()
	r.Registry[programs.LoaderConnect] = connect.Register()
	r.Registry[programs.LoaderPtrace] = ptrace.Register()

  yamlDir := filepath.Join(r.path)

  logger.Info("Loading YAML rules from", zap.String("path", yamlDir))

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

  for _, rule := range yamlRules {
		et := rule.Type()
    if !validEventTypes[et]{
      logger.Warn("Skipping YAML rule, for invalid event type", zap.String("name", rule.Name()),zap.String("eventType", et))
      continue
    }
		r.Registry[et] = append(r.Registry[et], rule)
    logger.Info("Load rule", zap.String("name", rule.Name()))
	}

  
}

func (r *RuleRegister) Add(eventType string, rule programs.Rule) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Registry[eventType] = append(r.Registry[eventType], rule)
}

func (r *RuleRegister) Delete(eventType, ruleName string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	rules := r.Registry[eventType]
	for i, rule := range rules {
		if rule.Name() == ruleName {
			r.Registry[eventType] = append(rules[:i], rules[i+1:]...)
			return true
		}
	}
	return false
}

func (r *RuleRegister) Get(eventType string) []programs.Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.Registry[eventType]
}

func (r *RuleRegister) Reload() {
	r.InitRules()
}

func (r *RuleRegister) addWatch() error {
  logger := logutil.GetLogger()

  dir := filepath.Clean(r.path)

  if err := r.watcher.Add(dir); err != nil {
		
		return err
	}

	logger.Info("watching for rule file changes", zap.String("dir", dir))

  return nil
}

func (r *RuleRegister) watch(){

  logger := logutil.GetLogger()
  debounce := time.NewTimer(0)
	if !debounce.Stop() {
		<-debounce.C
	}

  for{
    select{

    case event,ok:= <- r.watcher.Events:
      if !ok {
				return
			}
      
      if (filepath.Ext(event.Name) != ".yaml" && filepath.Ext(event.Name) != ".yml") ||
        (event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove) == 0) {
        continue
      }

      
      logger.Info("detected rule file change",
				zap.String("file", event.Name),
				zap.String("op", event.Op.String()))

			debounce.Reset(1 * time.Second)

    case <- debounce.C:
      time.Sleep(100 * time.Millisecond)
      logger.Info("reloading rules due to change")
			r.Reload()
    case err,ok := <- r.watcher.Errors:
      if !ok {
				return
			}
			logger.Warn("watcher error", zap.Error(err))

    case <-r.stopCh:
			logger.Info("stopping rule watcher")
			_ = r.watcher.Close()
			return
    }
  }
}


func (r *RuleRegister) StopWatcher() {
	close(r.stopCh)
}
