package api_key

import (
	"fmt"
	"regexp"

	"js-hunter/pkg/extracter"
)

func init() {
	extracter.ResigterExtractor(Extractor{})
}

// https://wiki.teamssix.com/cloudservice/more/
var (
	KeyDict = map[string]string{
		"Amazon Web Services":   `^AKIA[A-Za-z0-9]{16}$`,
		"Google Cloud Platform": `^GOOG[\w\W]{10,30}$`,
		"Microsoft Azure":       `^AZ[A-Za-z0-9]{34,40}$`,
		"Alibaba Cloud)":        `^LTAI[A-Za-z0-9]{12,20}$`,
		"Tencent Cloud":         `^AKID[A-Za-z0-9]{13,20}$`,
		"JD Cloud":              `^JDC_[A-Z0-9]{28,32}`,
		"Volcengine":            `^AKLT[a-zA-Z0-9-_]{0,252}`,
		"Wechat Corpsecret Key": `(?i)corpsecret(\\")?[:=](\\")?["']?([a-z0-9\-]+){10,}["']?`,
	}
)

type Extractor struct {
}

func (e Extractor) Type() string {
	return extracter.SENSITIVE
}

func (e Extractor) Extract(body string) []string {
	var (
		sensitive []string
	)

	for key, regex := range KeyDict {
		pattern, _ := regexp.Compile(regex)
		matches := pattern.FindAllString(body, -1)
		for _, match := range matches {
			match = fmt.Sprintf("%s: %s", key, match)
			sensitive = append(sensitive, match)
		}
	}
	return sensitive
}
