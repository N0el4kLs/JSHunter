package types

import (
	"crypto/md5"
	"encoding/hex"

	"js-hunter/pkg/httpx"
)

// EndPoint is the struct that represents an endpoint
type EndPoint struct {
	// Hash is the hash of the endpoint, used to identify it
	Hash string
	// Path is the path of the endpoint
	Path string `json:"path"`
	// Method is the request method of the endpoint
	Method string `json:"method"`
	// QueryString is the parameter of the endpoint
	QueryString string `json:"query"`
	// Data is the post data of the endpoint
	Data string `json:"data"`
}

// NewEndPoint creates a new endpoint
func NewEndPoint(path, method, parameter, data string) *EndPoint {
	ed := &EndPoint{Path: path, Method: method, QueryString: parameter, Data: data}
	ed.SetHash()
	return ed
}

// NewGetEndPoint creates a new get endpoint
func NewGetEndPoint(path, parameter string) *EndPoint {
	return &EndPoint{Path: path, Method: "GET", QueryString: parameter}
}

// NewPostEndPoint creates a new post endpoint
func NewPostEndPoint(path, data string) *EndPoint {
	return &EndPoint{Path: path, Method: "POST", Data: data}
}

func (e *EndPoint) SetHash() {
	h := md5.New()
	h.Write([]byte(e.Path + e.Method + e.QueryString + e.Data))
	e.Hash = hex.EncodeToString(h.Sum(nil))
}

func Endpoint2Client(point EndPoint) *httpx.Client {
	// Todo endpoint proxy and timeout parameter should follow the global options
	c := httpx.NewClient(point.Method, "", 10)
	if point.QueryString != "" {
		c.SetQuery(point.QueryString)
	}

	if point.Data != "" {
		c.SetPostBody(point.Data)
	}

	return c
}
