package types

import (
	"js-hunter/pkg/httpx"

	"github.com/imroc/req/v3"
)

type CheckType int

const (
	EndpointCheckType CheckType = 1 << iota
	VuePathCheckType  CheckType = 1 << iota
	SensitiveCheckType
)

var (
	labels = map[CheckType]string{
		EndpointCheckType:  "ENDPOINT",
		VuePathCheckType:   "VUEPATH",
		SensitiveCheckType: "SENSITIVE",
	}
)

// Result output handler
type Result struct {
	// TypeOfRst output which type of result
	TypeOfRst CheckType

	// endpoint Checked result
	EndpointRst InspectEndpointRst

	//SensitiveRst sensitive information
	SensitiveRst InspectSensitiveRst

	// vue Checked result
	VuePathRst InspectVuePathRst

	// tmp record resp
	*req.Response
}

// InspectEndpointRst the result of inspecting endpoint
type InspectEndpointRst struct {
	URL           string
	Path          string
	Method        string
	ContentLength int
	StatusCode    int
}

// InspectVuePathRst the result of inspecting vue path
type InspectVuePathRst struct {
	// URI of the broken access vue path
	URI string

	// ParentURL which the current URI comes from
	ParentURL string

	// ScreenshotName the screenshot name of the current vue path
	ScreenshotName string
}

// InspectSensitiveRst the result of inspect senstive
type InspectSensitiveRst struct {
	URL string
	Msg string
}

func NewEdRst(resp *httpx.Response) Result {
	detail := InspectEndpointRst{
		URL:           resp.Request.URL.String(),
		Method:        resp.Request.Method,
		StatusCode:    resp.StatusCode,
		ContentLength: len(resp.String()),
	}

	return Result{
		TypeOfRst:   EndpointCheckType,
		EndpointRst: detail,
	}
}

func NewVuePathRst(parent, u, screenshot string) Result {
	detail := InspectVuePathRst{
		URI:            u,
		ParentURL:      parent,
		ScreenshotName: screenshot,
	}

	return Result{
		TypeOfRst:  VuePathCheckType,
		VuePathRst: detail,
	}
}

func WithLabel(checkType CheckType) string {
	return labels[checkType]
}
