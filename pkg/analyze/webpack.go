package analyze

import (
	"errors"
	"io"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/projectdiscovery/gologger"
)

func CheckWebpack(body string) bool {
	htmlFeatures := []string{"<noscript",
		"webpackJsonp",
		"<script id=\"__NEXT_DATA__",
		"webpack-",
		"<style id=\"gatsby-inlined-css",
		"<div id=\"___gatsby",
		"<meta name=\"generator\" content=\"phoenix",
		"<meta name=\"generator\" content=\"Gatsby",
		"<meta name=\"generator\" content=\"Docusaurus",
	}

	for _, feature := range htmlFeatures {
		if strings.Contains(body, feature) {
			return true
		}
	}

	return false
}

func ParseJS(body string, bodyBytes io.Reader) []string {
	// remote comment in html file
	body = strings.ReplaceAll(body, "<!--", "")
	body = strings.ReplaceAll(body, "-->", "")
	doc, err := goquery.NewDocumentFromReader(bodyBytes)
	if err != nil {
		errors.New("fail to parse html")
	}

	jsPaths := []string{}
	uniqueJSPaths := map[string]struct{}{}

	// load src from script tag
	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		// Get the src attribute
		src, exists := s.Attr("src")
		if exists {
			if strings.HasSuffix(src, ".js") {
				if _, ok := uniqueJSPaths[src]; !ok {
					uniqueJSPaths[src] = struct{}{}
					jsPaths = append(jsPaths, src)
				}
			}
			gologger.Debug().Msgf("Script %d: src=%sn", i, src)
		}
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

	return jsPaths
}
