package rules

import (
	"github.com/ALEYI17/InfraSight_sentinel/internal/programs"
	"github.com/ALEYI17/InfraSight_sentinel/pkg/rules/connect"
	"github.com/ALEYI17/InfraSight_sentinel/pkg/rules/mount"
	"github.com/ALEYI17/InfraSight_sentinel/pkg/rules/open"
	"github.com/ALEYI17/InfraSight_sentinel/pkg/rules/ptrace"
)


var Registry = map[string][]programs.Rule{
  programs.LoaderOpen: open.Register(),
  programs.LoaderMount: mount.Register(),
  programs.LoaderConnect: connect.Register(),
  programs.LoaderPtrace: ptrace.Register(),
}
