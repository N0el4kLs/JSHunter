package analyze

import (
	"errors"
	"io"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/projectdiscovery/gologger"
)

type JavascriptType int

const (
	UnKnowType JavascriptType = iota
	Webpack
	Ajax
)

func GetJavascriptType(body string) JavascriptType {
	if isWebpack(body) {
		return Webpack
	} else if isAjax(body) {
		return Ajax
	}
	return UnKnowType
}

func ParseJS(uu string, bodyBytes io.Reader) ([]string, string) {
	// remote comment in html file
	byteBody, _ := io.ReadAll(bodyBytes)
	body := string(byteBody)
	body = strings.ReplaceAll(body, "<!--", "")
	body = strings.ReplaceAll(body, "-->", "")

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		errors.New("fail to parse html")
	}

	var (
		completeURL   string
		jsPaths       = []string{}
		uniqueJSPaths = make(map[string]struct{})
	)
	// load src from script tag
	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		// Get the src attribute
		src, exists := s.Attr("src")
		if !exists {
			return
		}
		if strings.HasSuffix(src, ".js") {
			if completeURL == "" && strings.HasPrefix(src, "http") && !inBlockDomain(src) {
				// make sure the complete url has the same domain with the target
				u1, _ := url.Parse(uu)
				u2, _ := url.Parse(src)
				if u1.Host == u2.Host {
					completeURL = src
				}
			}
			if _, ok := uniqueJSPaths[src]; !ok {
				uniqueJSPaths[src] = struct{}{}
				jsPaths = append(jsPaths, src)
			}
		}
		gologger.Debug().Msgf("Script %d: src=%sn", i, src)
	})

	// load javascript from link tag
	doc.Find("link").Each(func(i int, s *goquery.Selection) {
		// Get the src attribute
		src, exists := s.Attr("href")
		if exists {
			if strings.HasSuffix(src, ".js") {
				if _, ok := uniqueJSPaths[src]; !ok {
					uniqueJSPaths[src] = struct{}{}
					jsPaths = append(jsPaths, src)
				}
			}
			gologger.Debug().Msgf("Link %d: href=%s\n", i, src)
		}
	})

	return jsPaths, completeURL
}

func inBlockDomain(s string) bool {
	for _, domain := range BlackDomain {
		if strings.Contains(s, domain) {
			return true
		}
	}
	return false
}
