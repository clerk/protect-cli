package cli

import (
	"net/http"

	"github.com/spf13/cobra"

	"github.com/clerk/protect-cli/internal/api"
)

func (a *app) getAndPrint(cmd *cobra.Command, path string) error {
	c, _, err := a.client()
	if err != nil {
		return err
	}
	resp, err := c.Do(ctxOf(cmd), http.MethodGet, path, nil, nil)
	if err != nil {
		return err
	}
	return a.printRaw(resp.Body)
}

func (a *app) schemaCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "schema [event-type]",
		Short: "The fields a rule expression can use, for every event type or one",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 1 {
				return usageError("expected at most one event type")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				return a.getAndPrint(cmd, api.Path("schema", "events", args[0]))
			}
			return a.getAndPrint(cmd, api.Path("schema"))
		},
	}
}

func (a *app) fieldsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "fields",
		Short: "The full rule-field reference: types, operators and functions",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.getAndPrint(cmd, api.Path("fields"))
		},
	}
}
