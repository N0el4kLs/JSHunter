package headless

import (
	"context"
	"os"
	"path/filepath"

	"js-hunter/pkg/types"
	"js-hunter/pkg/util"
)

// PrepareRouterCheck is the function to prepare the router check.Preparation include:
// 1. create folder to save screenshot
// 2. create context to save screenshot location
// 3. get all the router items
func PrepareRouterCheck(t *types.Task) (context.Context, []types.VueRouterItem) {
	// create folder to save screenshot
	folder := util.URL2FileName(t.URL)
	screenshotDir := filepath.Join(util.WorkDir, "reports", "vue_reports", folder, "resources")
	os.MkdirAll(screenshotDir, 0777)
	ctx := context.WithValue(context.Background(), "screenshotLocation", screenshotDir)

	var (
		checkItem   types.CheckItem
		routerItems []types.VueRouterItem
		uniqueTmp   = make(map[string]struct{})
	)
	checkItem.URL = t.URL
	checkItem.FirstVisitURL = t.IndexURL
	for _, sub := range t.Subs {
		if _, ok := uniqueTmp[sub]; !ok {
			uniqueTmp[sub] = struct{}{}
			routerItems = append(routerItems, types.VueRouterItem{
				URL:       sub,
				ParentURL: checkItem,
			})
		}
	}

	return ctx, routerItems
}
