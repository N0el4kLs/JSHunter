package headless

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"js-hunter/pkg/httpx"
	"js-hunter/pkg/util"

	"github.com/PuerkitoBio/goquery"
	"github.com/imroc/req/v3"
	"github.com/projectdiscovery/gologger"
	"github.com/remeh/sizedwaitgroup"
)

type Sign struct{}

var (
	MAX_CONNECTION = make(chan Sign, 600) // max http connection using client
)

type VueTargetInfo struct {
	BaseURL   string
	BaseHref  string
	BaseToken string

	// index url when first visit target
	IndexURL string

	Subs     []*VuePathDetail // all endpoint
	JsonSubs []*VuePathDetail // all endpoint return json content
	HtmlSubs []*VuePathDetail // all endpoint return html content
	Brokens  []*BrokenItem
}

type VuePathDetail struct {
	URL           string        // url of endpoint
	Title         string        // title of endpoint
	ContentType   string        // content-type of endpoint
	Body          string        // body of endpoint
	StatusCode    int           // status code of endpoint
	ContentLength int64         // content-length of endpoint
	HomeHref      string        // home page href
	Href          string        // window.location.href of endpoint
	HrefToken     string        // token of window.location.href of endpoint
	ParentURL     string        // where the URL comes from
	Response      *req.Response // http response
}

// BrokenItem is a struct to store broken access information
type BrokenItem struct {
	URL           string
	Title         string
	ContentLength int64
	BrokenType    string   // json or html
	KeyWords      []string // keywords in body
	Comment       string   // additional comment
}

type CheckItem struct {
	URL string // inputted target url

	// FirstVisitURL first visit url, this field will be used to check the broken access.
	// for example:
	// when visited target: http://example.com
	// the first visit url is http://example.com/index.html
	FirstVisitURL string
}

type VueRouterItem struct {
	URL string // vue router url

	// Href actual href of the vue router url, this field will be used to check the broken access.
	// for example:
	// when visit router: http://example.com/#/home
	// there is a redirect to http://example.com/#/login, so the href is http://example.com/#/login
	Href string

	// BaseURL base url of the vue router url without any frag or query
	Base string

	// Token tokenized url
	Token string

	ParentURL CheckItem // where the vue router url comes from
}

// CategoryReqType This function is deprecated
// seems the path can not be loading properly since it needs javascript to render
func CategoryReqType(t *Task) *VueTargetInfo {
	result := &VueTargetInfo{
		BaseURL:   t.URL,
		BaseHref:  t.BaseURI,
		BaseToken: t.BaseToken,
		IndexURL:  t.IndexURL,
	}
	lengthMap := make(map[int64]uint)

	wg := sizedwaitgroup.New(50)

	for _, endp := range t.Subs {
		wg.Add()
		MAX_CONNECTION <- Sign{}
		go func(sub string) {
			defer func() {
				wg.Done()
				<-MAX_CONNECTION
			}()

			gologger.Debug().Msgf("Try to analysis %s\n", sub)
			reqClient := httpx.NewGetClient("", 10)
			rsp, err := reqClient.DoRequest(result.BaseURL + sub)
			if rsp.Err == nil && rsp.ContentLength == -1 {
				rsp.ContentLength = int64(len(rsp.Bytes()))
			}
			resultItem := &VuePathDetail{
				Response:      rsp.Response,
				URL:           sub,
				Body:          rsp.String(),
				StatusCode:    rsp.StatusCode,
				ContentLength: rsp.ContentLength,
				ParentURL:     t.URL,
			}
			//gologger.Debug().Msgf("Get response content-length: %v\n", rsp.ContentLength)
			doc, err := goquery.NewDocumentFromReader(rsp.Body)
			if err != nil {
				gologger.Error().Msgf("goquery.NewDocumentFromReader for url %s, error:%s",
					sub,
					err.Error(),
				)
				return
			}
			title := doc.Find("title").Text()
			//gologger.Debug().Msgf("Get title %s for url %s\n", title, sub)
			resultItem.Title = title
			ct := rsp.GetHeader("Content-Type")
			if strings.Contains(ct, "json") {
				lengthMap[rsp.ContentLength]++
				result.JsonSubs = append(result.JsonSubs, resultItem)
			} else if strings.Contains(ct, "html") {
				result.HtmlSubs = append(result.HtmlSubs, resultItem)
			} else {
				gologger.Debug().
					Msgf("Content-Type is %s, url is %s\n", ct, sub)
			}
		}(endp)
	}

	wg.Wait()

	var (
		maxCL     int64
		maxRemark uint
	)
	// find which content-length is the most
	for k, v := range lengthMap {
		if v > maxRemark {
			maxRemark = v
			maxCL = k
		}
	}

	for _, i := range result.JsonSubs {
		if i.ContentLength == maxCL {
			continue
		}
		if i.StatusCode != 404 {
			keywords := make([]string, 0)
			brokenItem := &BrokenItem{
				Title:         i.Title,
				URL:           i.URL,
				ContentLength: i.ContentLength,
				BrokenType:    "JSON",
				KeyWords:      keywords,
			}
			result.Brokens = append(result.Brokens, brokenItem)
		}
	}

	return result
}

func PrepareRouterCheck(t *Task) (context.Context, []VueRouterItem) {
	// create folder to save screenshot
	folder := util.URL2FileName(t.URL)
	screenshotDir := filepath.Join(util.WorkDir, "reports", "vue_reports", folder, "resources")
	os.MkdirAll(screenshotDir, 0777)
	ctx := context.WithValue(context.Background(), "screenshotLocation", screenshotDir)

	var (
		checkItem   CheckItem
		routerItems []VueRouterItem
		uniqueTmp   = make(map[string]struct{})
	)
	checkItem.URL = t.URL
	checkItem.FirstVisitURL = t.IndexURL
	for _, sub := range t.Subs {
		if _, ok := uniqueTmp[sub]; !ok {
			uniqueTmp[sub] = struct{}{}
			routerItems = append(routerItems, VueRouterItem{
				URL:       sub,
				ParentURL: checkItem,
			})
		}
	}

	return ctx, routerItems
}
