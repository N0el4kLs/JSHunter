package headless

import (
	"strings"

	"js-hunter/pkg/httpx"

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
