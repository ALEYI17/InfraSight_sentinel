package ptrace

import "github.com/ALEYI17/InfraSight_sentinel/internal/programs"

func register() []programs.Rule{
  return []programs.Rule{
    &CodeInjection{},
  }
}
