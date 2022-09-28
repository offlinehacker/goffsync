package impl

import (
	"encoding/json"
	"ffsyncclient/cli"
	"ffsyncclient/consts"
	"ffsyncclient/fferr"
	"ffsyncclient/langext"
	"ffsyncclient/models"
	"ffsyncclient/syncclient"
	"github.com/joomcode/errorx"
	"strconv"
	"time"
)

type CLIArgumentsBookmarksCreateSeparator struct {
	ParentID string
	Position int

	CLIArgumentsBookmarksUtil
}

func NewCLIArgumentsBookmarksCreateSeparator() *CLIArgumentsBookmarksCreateSeparator {
	return &CLIArgumentsBookmarksCreateSeparator{
		ParentID:                  "unfiled",
		Position:                  -1,
		CLIArgumentsBookmarksUtil: CLIArgumentsBookmarksUtil{},
	}
}

func (a *CLIArgumentsBookmarksCreateSeparator) Mode() cli.Mode {
	return cli.ModeBookmarksCreateSeparator
}

func (a *CLIArgumentsBookmarksCreateSeparator) PositionArgCount() (*int, *int) {
	return langext.Ptr(0), langext.Ptr(0)
}

func (a *CLIArgumentsBookmarksCreateSeparator) ShortHelp() [][]string {
	return [][]string{
		{"ffsclient bookmarks create separator", "Insert a new bookmark-separator"},
		{"          [--parent <id>]", "Specify the ID of the parent folder (if not specified the entry lives under `unfiled`)"},
		{"          [--position=<idx>]", "The position of the entry in the parent (0 = first, default is last). Can use negative indizes."},
	}
}

func (a *CLIArgumentsBookmarksCreateSeparator) FullHelp() []string {
	return []string{
		"$> ffsclient bookmarks create separator [--parent <id>] [--position <idx>]",
		"",
		"Create a new bookmark with the type [separator]",
		"",
		"With --parent you can specify the ID of the parent folder. Throws an error if the parent does not exist or is not an folder. The default value is `unfiled`",
		"With --position you can specify the position in the parent folder. The left-most position is 0 and the last position is len(folder.children). You can also use negative indizes: -1 is the last position and -2 the second-last etc. An invalid position throws an error.",
		"If the position is negative you _have_ to use the --position=XX syntax. (Writing `--position XX` will result in a parser error)",
		"",
		"Outputs the RecordID of the newly created entry on success.",
	}
}

func (a *CLIArgumentsBookmarksCreateSeparator) Init(positionalArgs []string, optionArgs []cli.ArgumentTuple) error {
	for _, arg := range optionArgs {
		if arg.Key == "parent" && arg.Value != nil {
			a.ParentID = *arg.Value
			continue
		}
		if arg.Key == "position" && arg.Value != nil {
			if v, err := strconv.ParseInt(*arg.Value, 10, 32); err == nil {
				a.Position = int(v)
				continue
			}
			return fferr.DirectOutput.New("Failed to parse number argument '--position': '" + *arg.Value + "'")
		}
		return fferr.DirectOutput.New("Unknown argument: " + arg.Key)
	}

	return nil
}

func (a *CLIArgumentsBookmarksCreateSeparator) Execute(ctx *cli.FFSContext) int {
	ctx.PrintVerbose("[Create Bookmark<Separator>]")
	ctx.PrintVerbose("")

	// ========================================================================

	cfp, err := ctx.AbsSessionFilePath()
	if err != nil {
		ctx.PrintFatalError(err)
		return consts.ExitcodeError
	}

	if !langext.FileExists(cfp) {
		ctx.PrintFatalMessage("Sessionfile does not exist.")
		ctx.PrintFatalMessage("Use `ffsclient login <email> <password>` first")
		return consts.ExitcodeNoLogin
	}

	// ========================================================================

	client := syncclient.NewFxAClient(ctx.Opt.AuthServerURL)

	ctx.PrintVerbose("Load existing session from " + cfp)
	session, err := syncclient.LoadSession(ctx, cfp)
	if err != nil {
		ctx.PrintFatalError(err)
		return consts.ExitcodeError
	}

	session, err = client.AutoRefreshSession(ctx, session)
	if err != nil {
		ctx.PrintFatalError(err)
		return consts.ExitcodeError
	}

	// ========================================================================

	recordID := a.newBookmarkID()

	now := time.Now()

	ctx.PrintVerboseHeader("[1] Search for parent")

	parent, newParentPayload, realChildPos, err, excode := a.calculateParent(ctx, client, session, recordID, a.ParentID, a.Position)
	if err != nil {
		ctx.PrintFatalError(errorx.Decorate(err, "failed to find+calculate parent"))
		return excode
	}

	ctx.PrintVerbose("Found Record Parent record: '" + parent.ID + "'")

	ctx.PrintVerboseHeader("[2] Create new record")

	bso := models.BookmarkCreatePayloadSchema{
		ID:         recordID,
		Type:       string(models.BookmarkTypeSeparator),
		DateAdded:  now.UnixMilli(),
		ParentID:   parent.ID,
		ParentName: parent.Title,

		SeparatorPosition: langext.Ptr(realChildPos),
	}

	plainPayload, err := json.Marshal(bso)
	if err != nil {
		ctx.PrintFatalError(errorx.Decorate(err, "failed to marshal BSO json"))
		return consts.ExitcodeError
	}

	payloadNewRecord, err := client.EncryptPayload(ctx, session, consts.CollectionBookmarks, string(plainPayload))
	if err != nil {
		ctx.PrintFatalError(err)
		return consts.ExitcodeError
	}

	update := models.RecordUpdate{
		ID:      recordID,
		Payload: langext.Ptr(payloadNewRecord),
	}

	err = client.PutRecord(ctx, session, consts.CollectionBookmarks, update, true, false)
	if err != nil {
		ctx.PrintFatalError(err)
		return consts.ExitcodeError
	}

	ctx.PrintVerboseHeader("[3] Update parent record")

	payloadParent, err := client.EncryptPayload(ctx, session, consts.CollectionBookmarks, newParentPayload)
	if err != nil {
		ctx.PrintFatalError(err)
		return consts.ExitcodeError
	}

	updateParent := models.RecordUpdate{
		ID:      parent.ID,
		Payload: langext.Ptr(payloadParent),
	}

	err = client.PutRecord(ctx, session, consts.CollectionBookmarks, updateParent, false, false)
	if err != nil {
		ctx.PrintFatalError(err)
		return consts.ExitcodeError
	}

	// ========================================================================

	if langext.Coalesce(ctx.Opt.Format, cli.OutputFormatText) != cli.OutputFormatText {
		ctx.PrintFatalMessage("Unsupported output-format: " + ctx.Opt.Format.String())
		return consts.ExitcodeUnsupportedOutputFormat
	}

	ctx.PrintPrimaryOutput(recordID)
	return 0
}
