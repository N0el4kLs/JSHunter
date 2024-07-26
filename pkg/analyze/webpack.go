package analyze

import (
	"strings"
)

func isWebpack(body string) bool {
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
