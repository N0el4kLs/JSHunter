package headless

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"js-hunter/pkg/types"

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

// Crawler is the headless engine for vue path broken access check
type Crawler struct {
	BrowserInstance *rod.Browser
	injectionJS     map[string]string

	wg *sizedwaitgroup.SizedWaitGroup
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
		wg:              &wg,
	}
}

// RunHeadless use chromium to load target and inject javascript code
// Return:
func (c *Crawler) RunHeadless(t *Task) (*Task, *rod.Page) {
	defer func() {
		// handle navigation failed: net::ERR_NAME_NOT_RESOLVED
		if err := recover(); err != nil {
			gologger.Error().Msgf("URL %s error: %s\n", t.URL, err)
		}
	}()

	page := c.BrowserInstance.MustPage(t.URL).
		MustWaitLoad().
		MustWaitDOMStable()

	href := page.MustEval(c.injectionJS["href"]).Str()
	t.IndexURL = href
	baseURL := fixBaseURl(href)
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
		if strings.HasPrefix(path, "/") {
			path = path[1:]
		}
		url := fmt.Sprintf("%s%s", baseURL, path)
		tmp = append(tmp, url)
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

// HtmlBrokenAnalysis is a function to analysis the html result
func (c *Crawler) HtmlBrokenAnalysis(t *VueTargetInfo) chan types.Result {
	var (
		vuePathRstChan = make(chan types.Result)
	)

	go func() {
		defer close(vuePathRstChan)

		for _, htmlSub := range t.HtmlSubs {
			c.wg.Add()

			//go c.accessURL(htmlSub)
			go c.accessURLWithChan(htmlSub, vuePathRstChan)
		}

		c.wg.Wait()
	}()

	return vuePathRstChan
}

func (c *Crawler) accessURL(item *VuePathDetail) {
	defer c.wg.Done()

	p := c.BrowserInstance.MustPage(item.URL).
		MustWaitDOMStable().
		MustWaitLoad()

	if err := p.WaitLoad(); err != nil {
		gologger.Error().Msgf("Wait load url %s , error:%s\n",
			item.URL,
			err.Error(),
		)
	}

	href := p.MustEval(c.injectionJS["href"]).Str()
	base, token := tokenizerURL(href)

	item.Href = href
	item.HrefToken = token
	item.URL = base
	p.MustClose()
}

func (c *Crawler) accessURLWithChan(item *VuePathDetail, rstChannel chan types.Result) {
	defer c.wg.Done()

	p := c.BrowserInstance.MustPage(item.URL).
		MustWaitDOMStable().
		MustWaitLoad()

	defer p.MustClose()

	if err := p.WaitLoad(); err != nil {
		gologger.Error().Msgf("Wait load url %s , error:%s\n",
			item.URL,
			err.Error(),
		)
	}

	href := p.MustEval(c.injectionJS["href"]).Str()
	base, token := tokenizerURL(href)
	if strings.Contains(token, NO_REDIRECT) && !strings.Contains(base, BLANKPAGE) {
		rstChannel <- types.NewVuePathRst(href)
	}

	//item.Href = href
	//item.HrefToken = token
	//item.URL = base

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
// uriToken: https://examle.com/#/login?redirect={REDIRECT} -> base64
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

	indexFrag := strings.IndexAny(s, "/#/")
	if indexFrag != -1 {
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
		//uriToken = base64.StdEncoding.EncodeToString([]byte(st))
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

type TokenRemark struct {
	TokenType bool   // true: with redirect, false: without redirect
	Token     string // token string
}
