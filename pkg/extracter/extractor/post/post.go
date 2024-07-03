package post

import (
	"regexp"
	"strings"

	"js-hunter/pkg/extracter"
)

func init() {
	extracter.ResigterExtractor(Extractor{})
}

type Extractor struct {
}

func (e Extractor) Type() string {
	return extracter.PATH
}

func (e Extractor) Extract(body string) []string {
	var (
		endpoints []string
		regex     = `(?s)\w\.post\(\"(.*?)\".*?\)[;|\.then|,]`
	)

	pattern, _ := regexp.Compile(regex)
	matches := pattern.FindAllString(body, -1)
	for _, match := range matches {
		match = strings.Replace(match, "\n", "", -1)
		match = strings.Replace(match, " ", "", -1)
		endpoints = append(endpoints, match)
	}

	return endpoints
}
