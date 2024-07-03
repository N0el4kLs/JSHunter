package types

import "github.com/imroc/req/v3"

type Result struct {
	// URL
	URL           string
	Path          string
	Method        string
	ContentLength int
	StatusCode    int

	// tmp record resp
	*req.Response
}
