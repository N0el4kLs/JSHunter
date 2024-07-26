package gemini

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"js-hunter/pkg/types"

	"google.golang.org/api/option"

	"github.com/google/generative-ai-go/genai"
	"github.com/projectdiscovery/gologger"
)

const (
	GEMINI      = "Gemini"
	GeminiUser  = "user"
	GeminiBot   = "model"
	GenerateTag = "---END_OF_GENERATE---"
)

type callBack func(ctx context.Context, client *genai.Client) (interface{}, error)

var (
	EmptyKeyError  = errors.New("gemini api key can not empty")
	ValidKeyError  = errors.New("gemini api key can't work, please make sure the key is still alive")
	PromptTemplate = `As a bug bounty hunter, your task is to analyze a JavaScript file from front-end and extract endpoints, parameters,and secret keys to explore potential threats and vulnerabilities in a website. So you should:
1. Carefully examine the provided JavaScript file or snippet of Javascript code.
2. Identify and extract all endpoints mentioned within the file or Javascript Code.
3. Locate and extract parameters associated with each endpoint.

Please take into consideration the examples attached below:
<example 1>
<input>
i.get("/api/stripe/save").
</input>
<output>
{
"path":"/api/stripe/save", 
"method": "GET", 
"query": "", 
"data": ""
}
</output>
</example 1>
<example 2>
<input>
i.get("/api/public/trainingcard/type/get",{ids:C.product_id}).
</input>
<output>
{
"path":"/api/public/trainingcard/type/get", 
"method": "GET", 
"query": "ids=11234", 
"data": ""
}
</output>
</example 2>
<example 3>
<input>
i.get("/api/homepage/revision/get",{homepage_id:this.$root.homepage_id,id:t}).
</input>
<output>
{
"path":"/api/homepage/revision/get", 
"method": "GET", 
"query": "homepage_id=1&id=123123", 
"data": ""
}
</output>
</example 3>

As you can see, some parameter in input like "homepage_id:this.$root.homepage_id" or "id:t" or "ids:C.product_id",
you should replace the parameter with specific value based on develop experience or bug bounty experience.
Maybe sometimes the input is not like a request operation, you should recognize it and bypass it.

You should provide results in Json Array format with the following structure:
[{
"path":"", 
"method": ", 
"query": "", 
"data": ""
}]
key explain:
1. "path": means the endpoint path, it is a string, required.
2. "method": means the request method of the endpoint, it is a string, required.
3. "parameter": means the parameter of the endpoint, it is a string, optional.\
Note: parameter should be specified with the value which based on the develop experience and bug bounty hunter's experience.
4. "data": means the post data of the endpoint, it is a string, optional.

Sometimes maybe there are some same endpoints, you just need to keep one item which has query or data.
Please provide the extracted endpoints and parameters as an array of json and just return the json data only, no other comment or recommendation or stuff.
Output '---END_OF_GENERATE---' as the end signal.

Here are the snippets of JavaScript code needed to analyze, delimited by input tags:
<input>
%s
</input>
`
)

type Provider struct {
}

func (p Provider) Name() string {
	return GEMINI
}

func (p Provider) Auth() error {
	var err error
	if key := os.Getenv("Gemini_API_KEY"); key == "" {
		return EmptyKeyError
	}

	_, err = generate("This is a api connection test.", authCallback)
	return err
}

func (p Provider) Generate(input string) ([]types.EndPoint, error) {
	res, err := generate(input, handleEndpointCallback)
	return res.([]types.EndPoint), err
}

func generate(input string, back callBack) (interface{}, error) {
	// Is it a good way to save the input value in the context?
	ctx := context.WithValue(context.Background(), "input", input)
	client, err := genGeminiClient()
	if err != nil {
		return client, err
	}
	defer client.Close()

	return back(ctx, client)
}

func authCallback(ctx context.Context, client *genai.Client) (interface{}, error) {
	model := client.GenerativeModel("gemini-1.5-pro")
	prompt := ctx.Value("input").(string)

	return model.GenerateContent(ctx, genai.Text(prompt))
}

func handleEndpointCallback(ctx context.Context, client *genai.Client) (interface{}, error) {
	var endpoints []types.EndPoint

	model := client.GenerativeModel("gemini-1.5-flash")
	// This setting is used to solve error: blocked: candidate: FinishReasonSafety
	// https://ai.google.dev/gemini-api/docs/safety-settings?hl=zh-cn
	model.SafetySettings = []*genai.SafetySetting{
		{
			Category:  genai.HarmCategoryHarassment,
			Threshold: genai.HarmBlockNone,
		},
		{
			Category:  genai.HarmCategoryHateSpeech,
			Threshold: genai.HarmBlockNone,
		},
		{
			Category:  genai.HarmCategoryDangerousContent,
			Threshold: genai.HarmBlockNone,
		},
		{
			Category:  genai.HarmCategorySexuallyExplicit,
			Threshold: genai.HarmBlockNone,
		},
	}
	prompt := fmt.Sprintf(PromptTemplate, ctx.Value("input").(string))
	promptParts := strings.SplitAfter(prompt, "as the end signal")
	cs := model.StartChat()
	cs.History = []*genai.Content{
		&genai.Content{
			Parts: []genai.Part{
				genai.Text(promptParts[0]),
			},
			Role: GeminiUser,
		},
	}

	var (
		allGeneratedContents string
		currentPrompt        string
	)
	currentPrompt = promptParts[1]
	for {
		resp, err := cs.SendMessage(ctx, genai.Text(currentPrompt))
		if err != nil {
			break
		}
		if resp.Candidates[0].Content == nil {
			gologger.Warning().Msgf("Gemini generate no content\n")
			break
		}
		text := fmt.Sprintf("%v", resp.Candidates[0].Content.Parts[0])
		unFormatText := text
		//gologger.Debug().Msgf("%s\n", unFormatText)
		if strings.HasPrefix(text, "```json") {
			text = strings.TrimPrefix(text, "```json")
		}
		if strings.HasSuffix(text, "```") {
			text = strings.TrimSuffix(text, "```")
		}
		if !strings.HasSuffix(text, GenerateTag) {
			allGeneratedContents += text
			cs.History = append(cs.History,
				&genai.Content{
					Parts: []genai.Part{
						genai.Text(unFormatText),
					},
					Role: GeminiBot,
				},
			)
			currentPrompt = "Continue generate"
			continue
		}
		text = strings.ReplaceAll(text, GenerateTag, "")
		allGeneratedContents += text
		break
	}

	gologger.Debug().Msgf("All generatedContents is %s\n", allGeneratedContents)
	err := json.Unmarshal([]byte(allGeneratedContents), &endpoints)

	return endpoints, err
}

type ProxyRoundTripper struct {
	// APIKey is the API Key to set on requests.
	APIKey string

	// Transport is the underlying HTTP transport.
	// If nil, http.DefaultTransport is used.
	Transport http.RoundTripper

	ProxyURL string
}

func (t *ProxyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt := t.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}

	if t.ProxyURL != "" {
		proxyURL, err := url.Parse(t.ProxyURL)

		if err != nil {
			return nil, err
		}
		if transport, ok := rt.(*http.Transport); ok {
			transport.Proxy = http.ProxyURL(proxyURL)
			transport.TLSClientConfig = &tls.Config{
				InsecureSkipVerify: true,
			}
		} else {
			rt = &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			}
		}
	}

	newReq := *req
	args := newReq.URL.Query()
	args.Set("key", t.APIKey)
	newReq.URL.RawQuery = args.Encode()

	resp, err := rt.RoundTrip(&newReq)
	if err != nil {
		return nil, fmt.Errorf("error during round trip: %v", err)
	}

	return resp, nil
}

func genGeminiClient() (*genai.Client, error) {
	var (
		client *genai.Client
		err    error
	)
	// https://github.com/google/generative-ai-go/pull/101/files#diff-8fbd919ed011e2c50e66043f0a337fe2ac487636628539eee55f51a15053a4a5
	if os.Getenv("Gemini_PROXY") != "" {
		c := &http.Client{Transport: &ProxyRoundTripper{
			APIKey:   os.Getenv("Gemini_API_KEY"),
			ProxyURL: os.Getenv("Gemini_PROXY"),
		}}
		client, err = genai.NewClient(context.Background(), option.WithHTTPClient(c), option.WithAPIKey(os.Getenv("Gemini_API_KEY")))
	} else {
		client, err = genai.NewClient(context.Background(), option.WithAPIKey(os.Getenv("Gemini_API_KEY")))
	}

	return client, err
}
