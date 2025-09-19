package rules

import (
	"github.com/ALEYI17/InfraSight_sentinel/internal/programs"
	"github.com/ALEYI17/InfraSight_sentinel/pkg/rules/open"
)


var Registry = map[string][]programs.Rule{
  programs.LoaderOpen: open.Register(),
}
