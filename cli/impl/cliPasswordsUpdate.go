package impl

import (
	"ffsyncclient/cli"
	"github.com/joomcode/errorx"
)

type CLIArgumentsPasswordsUpdate struct {
}

func NewCLIArgumentsPasswordsUpdate() *CLIArgumentsPasswordsUpdate {
	return &CLIArgumentsPasswordsUpdate{}
}

func (a *CLIArgumentsPasswordsUpdate) Mode() cli.Mode {
	return cli.ModePasswordsUpdate
}

func (a *CLIArgumentsPasswordsUpdate) ShortHelp() [][]string {
	return nil //TODO
}

func (a *CLIArgumentsPasswordsUpdate) FullHelp() []string {
	return nil //TODO
}

func (a *CLIArgumentsPasswordsUpdate) Init(positionalArgs []string, optionArgs []cli.ArgumentTuple) error {
	if len(positionalArgs) > 0 {
		return errorx.InternalError.New("Unknown argument: " + positionalArgs[0])
	}

	for _, arg := range optionArgs {
		return errorx.InternalError.New("Unknown argument: " + arg.Key)
	}

	return nil
}

func (a *CLIArgumentsPasswordsUpdate) Execute(ctx *cli.FFSContext) int {
	panic("implement me") //TODO implement me
}
