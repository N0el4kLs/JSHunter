package analyze

import "strings"

func isAjax(body string) bool {
	ajaxFutures := []string{
		`$.ajax({`,
		"jquery.js",
	}
	for _, future := range ajaxFutures {
		if strings.Contains(body, future) {
			return true
		}
	}
	return false
}
