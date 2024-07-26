package httpx

import (
	"errors"
	"net/url"
	"strings"
	"time"

	"golang.org/x/exp/rand"

	"github.com/imroc/req/v3"
)

const (
	GET  = "GET"
	POST = "POST"
)

// Client is a struct for storing http client
type Client struct {
	// C is a http client
	*req.Client
	*req.Request

	// Timeout for http request
	Timeout int

	// MaxRedirect for http request
	MaxRedirect int

	// Proxy for http request
	Proxy string

	// Method for http request
	Method string

	// Headers for http request
	Headers map[string]string
}

// NewClient returns a new http client
func NewClient(method, proxy string, timeout int) *Client {
	c := req.C().EnableInsecureSkipVerify()
	c.SetTimeout(time.Duration(timeout) * time.Second)
	if proxy != "" && checkProxyURL(proxy) {
		c.SetProxyURL(proxy)
	}

	headers := make(map[string]string)
	headers["User-Agent"] = getRandomUserAgent()
	headers["Accept-Charset"] = "utf-8"

	return &Client{
		Client:      c,
		Request:     c.R(),
		Timeout:     timeout,
		MaxRedirect: 3,
		Proxy:       proxy,
		Method:      method,
		Headers:     headers,
	}
}

// NewGetClient returns a new http client with GET method
func NewGetClient(proxy string, timeout int) *Client {
	return NewClient(GET, proxy, timeout)
}

// NewPostClient returns a new http client with POST method
func NewPostClient(proxy string, timeout int) *Client {
	c := NewClient(POST, proxy, timeout)
	c.SetHeader("Content-Type", "application/x-www-form-urlencoded")
	return c
}

// DoRequest do http request with corresponding method
func (c *Client) DoRequest(u string) (*Response, error) {
	var (
		url_     string // use _ to avoid collide with imported package name
		response Response
		resp     *req.Response
		err      error
	)
	url_ = u

	c.Request.SetRetryCount(c.MaxRedirect).
		SetRetryBackoffInterval(1*time.Second, 5*time.Second).
		SetRetryFixedInterval(2 * time.Second)

	for k, v := range c.Headers {
		c.Request.SetHeader(k, v)
	}

	switch c.Method {
	case GET:
		resp, err = c.Request.Get(url_)
	case POST:
		resp, err = c.Request.Post(url_)
	}

	if err != nil {
		return nil, err
	}
	response.Response = resp

	return &response, nil
}

// SetQuery set query string for http request
func (c *Client) SetQuery(query string) *Client {
	//c.SetCommonQueryString(query)
	c.Request.SetQueryString(query)
	return c
}

// SetHeader set header for http request
func (c *Client) SetHeader(key, value string) *Client {
	c.Headers[key] = value
	return c
}

// SetPostBody set body for post http request
func (c *Client) SetPostBody(body interface{}) *Client {
	if _, ok := c.Headers["Content-Type"]; !ok {
		c.SetHeader("Content-Type", "application/x-www-form-urlencoded")
	}
	c.Request.SetBody(body)
	return c
}

// checkProxyURL check if the proxy url is valid
func checkProxyURL(u string) bool {
	var (
		isValid = true
		err     error
	)
	uu, err := url.Parse(u)
	if err != nil {
		isValid = false
	}

	if !strings.Contains(uu.Scheme, "http") && strings.Contains(uu.Scheme, "socks") {
		isValid = false
		err = errors.New("unsupported proxy scheme, use http, https or socks5")
	}
	if uu.Host == "" {
		isValid = false
		err = errors.New("invalid proxy host")
	}

	// Todo check connection to proxy
	//_, err = net.DialTimeout("tcp", uu.Host, 5*time.Second)

	return isValid
}

// getRandomUserAgent get random user agent
func getRandomUserAgent() string {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36",
	}
	rand.Seed(uint64(time.Now().UnixNano()))

	return userAgents[rand.Intn(len(userAgents))]
}
