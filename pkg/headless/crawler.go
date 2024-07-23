package headless

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"js-hunter/pkg/httpx"
	"js-hunter/pkg/types"

	"github.com/PuerkitoBio/goquery"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/projectdiscovery/gologger"
	"github.com/remeh/sizedwaitgroup"
)

const (
	DEFALUT_TABS = 10
	BLANKPAGE    = "about:blank"
	REDIRECT     = "{REDIRECT}"
	NO_REDIRECT  = "{NO_REDIRECT}"
)

var (
	// COUNTER This number was used to generate unique screenshot file name.
	COUNTER uint32 = 1
)

// Crawler is the headless engine for vue path broken access check
type Crawler struct {
	BrowserInstance *rod.Browser
	injectionJS     map[string]string

	maxTabWg *sizedwaitgroup.SizedWaitGroup
	lock     sync.Mutex
}

// NewCrawler is the construct function of initializing
func NewCrawler(isHeadless bool) *Crawler {
	chromeOptions := launcher.New().
		NoSandbox(true).
		Devtools(false)

	chromeOptions.Headless(!isHeadless) // true meaning do not display the chromium while running

	// Disable all prompts to prevent blocking the browser
	chromeOptions = chromeOptions.Append("disable-infobars", "")
	chromeOptions = chromeOptions.Append("disable-extensions", "")
	chromeOptions.Set("disable-web-security")
	chromeOptions.Set("allow-running-insecure-content")
	chromeOptions.Set("reduce-security-for-testing")

	browser := rod.New()
	err := browser.
		ControlURL(chromeOptions.MustLaunch()).
		Connect()
	if err != nil {
		gologger.Fatal().Msgf("Could not connect to chrome instance: %s\n", err)
	}

	// Todo Injection manually, wrapper it into a function
	c, _ := os.ReadFile("pkg/headless/js/vue_info.js")
	injections := make(map[string]string, 1)
	injections["vueinfo"] = string(c)
	injections["href"] = `()=>window.location.href`

	wg := sizedwaitgroup.New(DEFALUT_TABS)
	return &Crawler{
		BrowserInstance: browser,
		injectionJS:     injections,
		maxTabWg:        &wg,
		lock:            sync.Mutex{},
	}
}

// GetAllVueRouters use chromium to load target and inject javascript to get all vue routers
func (c *Crawler) GetAllVueRouters(t *Task) (*Task, *rod.Page) {
	defer func() {
		// handle navigation failed: net::ERR_NAME_NOT_RESOLVED
		if err := recover(); err != nil {
			gologger.Error().Msgf("URL %s error: %s\n", t.URL, err)
		}
	}()

	page := c.BrowserInstance.MustPage(t.URL).
		MustWaitLoad().
		MustWaitDOMStable()

	// sleep 2 second to ensure the page load completely
	time.Sleep(2 * time.Second)
	href := page.MustEval(c.injectionJS["href"]).Str()
	t.IndexURL = href
	baseURL := c.foundBaseURL(page)
	gologger.Info().Msgf("found base ulr: %s\n", baseURL)

	baseURI, token := tokenizerURL(href)
	t.BaseURI = baseURI
	t.BaseToken = func() string {
		if token == NO_REDIRECT {
			return baseURL
		}
		return token
	}()

	// find vue path
	page.MustEval(c.injectionJS["vueinfo"])

	// retrieve vue path
	rst := page.MustEval(`()=>vueinfo`).Arr()
	// if not router path found, return
	if len(rst) == 0 {
		return t, page
	}

	var (
		tmp  []string
		subs []string
	)
	for _, i := range rst {
		path := i.Map()["path"].Str()
		if strings.Contains(path, "*") || strings.Contains(path, ":") {
			continue
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		router := fmt.Sprintf("%s%s", baseURL, path)
		tmp = append(tmp, router)
	}

	// unique tmp
	var uniqueMap = make(map[string]bool, len(tmp))
	for _, v := range tmp {
		if _, ok := uniqueMap[v]; !ok {
			uniqueMap[v] = true
			subs = append(subs, v)
		}
	}

	t.Subs = append(t.Subs, subs...)
	return t, page
}

// RouterBrokenAnalysis is a function to analysis if the vue router has broken access
func (c *Crawler) RouterBrokenAnalysis(ctx context.Context, items []VueRouterItem) chan types.Result {
	var (
		vueRouterRstChan = make(chan types.Result)
	)

	go func() {
		defer close(vueRouterRstChan)

		for _, routerItem := range items {
			c.maxTabWg.Add()

			go c.accessRouterWithChan(ctx, routerItem, vueRouterRstChan)
		}

		c.maxTabWg.Wait()
	}()

	return vueRouterRstChan
}

func (c *Crawler) foundBaseURL(p *rod.Page) string {
	var baseURL string
	href := p.MustEval(c.injectionJS["href"]).Str()
	if strings.Contains(href, "#") {
		baseURL = fixBaseURl(href)
	} else {
		// visit js file to ensure the base url
		html := p.MustHTML()
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
		if err != nil {
			gologger.Warning().Msgf("cannot parse html from %s\n", href)
		}

		// Find the first script tag with a "src" attribute
		var (
			firstScriptSrc string
			subPathLists   []string
		)
		doc.Find("script").Each(func(i int, s *goquery.Selection) {
			// Get the src attribute
			src, exists := s.Attr("src")
			if exists {
				if strings.HasSuffix(src, ".js") && !strings.HasPrefix(src, "http") {
					if !strings.HasPrefix(src, "/") {
						firstScriptSrc = "/" + src
					} else {
						firstScriptSrc = src
					}
					return
				}
			}
		})

		uu, err := url.Parse(href)
		if err != nil {
			gologger.Error().Msgf("Can not parse url: %s \n", href)
		}
		tmpBaseURL := fmt.Sprintf("%s://%s", uu.Scheme, uu.Host)
		subPah := strings.Split(uu.Path, "/")
		for i := 0; i < len(subPah); i++ {
			subPathLists = append(subPathLists, strings.Join(subPah[:i+1], "/"))
		}
		tmpU := tmpBaseURL + firstScriptSrc
		reqClient := httpx.NewGetClient("", 10)
		resp, err := reqClient.DoRequest(tmpU)
		if resp.StatusCode == 200 && strings.Contains(resp.GetHeader("Content-Type"), "javascript") {
			baseURL = tmpBaseURL
		} else {
			for _, subPath := range subPathLists {
				if subPath == "" {
					continue
				}
				tmpU = tmpBaseURL + subPath + firstScriptSrc
				resp, err = reqClient.DoRequest(tmpU)
				if err != nil {
					continue
				}
				if resp.StatusCode == 200 && resp.ContentLength > 0 {
					baseURL = tmpBaseURL
					break
				}
			}
		}
	}

	return baseURL
}

func (c *Crawler) accessRouterWithChan(ctx context.Context, item VueRouterItem, rstChannel chan types.Result) {
	defer func() {
		if err := recover(); err != nil {
			gologger.Error().Msgf("Access %s error: %s\n", item.URL, err)
		}
	}()
	defer c.maxTabWg.Done()

	tabDoneSign := make(chan struct{})
	p := c.BrowserInstance.MustPage()
	go func() {
		defer func() {
			if err := recover(); err != nil {
				c.lock.Unlock()
				gologger.Error().
					Msgf("Access %s error: %s\n", item.URL, err)
			}
		}()
		err := p.Timeout(10 * time.Second).
			MustNavigate(item.URL).
			WaitLoad()

		if err != nil {
			gologger.Error().Msgf("connection to %s error: %s\n", item.URL, err)
			tabDoneSign <- struct{}{}
			return
		}

		// sleep 3 second to ensure the page is stable
		time.Sleep(3 * time.Second)
		//gologger.Debug().Msgf("Start injection js for url: %s\n", item.URL)
		item.IndexURL = p.MustEval(c.injectionJS["href"]).Str()
		item.Base, item.Token = tokenizerURL(item.IndexURL)

		if isBrokenAccess(item) {
			//gologger.Debug().Msgf("Start screenshot for url: %s\n", item.URL)
			c.lock.Lock()
			screenshotFolder := ctx.Value("screenshotLocation").(string)
			screenshotLocation := filepath.Join(screenshotFolder, fmt.Sprintf("%d.png", COUNTER))
			// use timeout to control MustScreenshot action
			p.MustScreenshot(screenshotLocation)
			//gologger.Debug().Msgf("Screenshot over for url: %s\n", item.URL)
			atomic.AddUint32(&COUNTER, 1)
			rstChannel <- types.NewVuePathRst(item.ParentURL.URL, item.IndexURL, screenshotLocation)
			c.lock.Unlock()
		}
		tabDoneSign <- struct{}{}
	}()

	select {
	case <-tabDoneSign:
		p.Close()
	case <-time.After(20 * time.Second):
		gologger.Error().Msgf("connection to %s error: %s\n", item.URL, "timeout")
		p.Close()
	}
}

func (c *Crawler) Close() {
	c.BrowserInstance.Close()
}

// Fix base url with frag, for example:
// input domain url: http://example.com/#/login
// output the base url: http://example.com/#/
func fixBaseURl(s string) string {
	index := strings.IndexAny(s, "#")
	if index == -1 {
		if !strings.HasSuffix(s, "/") {
			s = fmt.Sprintf("%s/", s)
		}
		return s
	} else {
		return s[:index+2]
	}
}

// tokenizer the current URL, for example:
// input: https://examle.com/#/login?redirect=%2FauditDetail
// output:
// baseURL: https://examle.com/#/login
// uriToken: https://examle.com/#/login?redirect={REDIRECT}
//
// Todo need to handle uri without frag like: http://example.com/login
// If uri has no frag, then uriToken is NO_REDIRECT
func tokenizerURL(s string) (string, string) {
	var (
		cleanURI string // url removed frag(#)
		redirect string // redirect in url
		baseURI  string
		uriToken string
	)
	if strings.Contains(s, "%2F") {
		s = strings.Replace(s, "%2F", "/", -1)
	}

	if indexFrag := strings.IndexAny(s, "/#/"); indexFrag != -1 {
		cleanURI = strings.Replace(s, "/#/", "/", 1)
	} else {
		cleanURI = s
	}
	u, err := url.Parse(cleanURI)
	if err != nil {
		gologger.Debug().Msgf("Parse url %s error: %s\n", s, err)
		return "", ""
	}
	queries := u.Query()
	if len(queries) > 0 && queries.Get("redirect") != "" {
		redirect = queries.Get("redirect")
		st := strings.Replace(s, redirect, REDIRECT, 1)

		index := strings.Index(st, "?")
		baseURI = st[:index]
		uriToken = st
	} else {
		if index := strings.Index(s, "?"); index != -1 {
			baseURI = s[:index]
		} else {
			baseURI = s
		}
		uriToken = NO_REDIRECT
	}

	return baseURI, uriToken
}

func isBrokenAccess(item VueRouterItem) bool {
	// if satisfy the following conditions at the same time, regard it as a broken access
	// 1. token contains NO_REDIRECT
	// 2. base url is not blank page
	// 3. current href is not equal to the first visit url
	return strings.Contains(item.Token, NO_REDIRECT) &&
		!strings.Contains(item.Base, BLANKPAGE) &&
		item.ParentURL.FirstVisitURL != item.IndexURL
}
