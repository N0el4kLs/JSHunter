package types

import "github.com/imroc/req/v3"

type CheckType int

const (
	EndpointCheckType CheckType = 1 << iota
	VuePathCheckType  CheckType = 1 << iota
)

var (
	labels = map[CheckType]string{
		EndpointCheckType: "ENDPOINT",
		VuePathCheckType:  "VUEPATH",
	}
)

type Result struct {
	// TypeOfRst output which type of result
	TypeOfRst CheckType

	// endpoint Checked result
	EndpointRst InspectEndpointRst

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

func NewEdRst() Result {
	detail := InspectEndpointRst{}

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
