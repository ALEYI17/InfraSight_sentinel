package connect

import "github.com/ALEYI17/InfraSight_sentinel/internal/programs"

func Register() []programs.Rule{
  return []programs.Rule{
    &KubernetesAPIConnection{},
  }
}
