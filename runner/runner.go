package runner

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"js-hunter/pkg/analyze"
	"js-hunter/pkg/extracter"
	_ "js-hunter/pkg/extracter/extractor/get"
	_ "js-hunter/pkg/extracter/extractor/post"
	"js-hunter/pkg/headless"
	"js-hunter/pkg/httpx"
	"js-hunter/pkg/llm"
	"js-hunter/pkg/llm/gemini"
	"js-hunter/pkg/types"
	"js-hunter/pkg/util"
	"js-hunter/pkg/writer"

	"github.com/joho/godotenv"
	"github.com/projectdiscovery/gologger"
	"github.com/remeh/sizedwaitgroup"
)

type Runner struct {
	options *Options

	// URLs
	URLs []string

	// AIEngine which ai source will be used for helping to analyze
	AIEngine llm.AIProvider

	// MaxGoroutines to limit the max number of URLs while handling
	MaxGoroutines *sizedwaitgroup.SizedWaitGroup

	// outChannel all result should send to this channel
	outChannel chan types.Result

	// outputOver sign that output process is over
	outputOver chan struct{}

	// writer retrieve the results from outChannel and handle them with different option
	writer *writer.Writer

	// extractors all regexp extract operations to match detail and needed inform from front-end page
	extractors []extracter.Extracter

	// crawlerEngine is chromium engine for checking broken access vue path
	crawlerEngine *headless.Crawler

	// endpointTaskChan endpoint check task queue
	endpointTaskChan chan string

	// vueTaskChan vue path check task queue
	vueTaskChan chan *headless.Task

	// processWg endpoint and vue check task wait group to end the process
	processWg sync.WaitGroup
}

func NewRunner(option *Options) (*Runner, error) {
	runner := &Runner{
		options: option,
	}

	// load target(s) from CLI or file
	if option.URL != "" {
		// Google hacking grammar:
		// intext:"without JavaScript enabled. Please enable it to continue." inurl:"login"
		runner.URLs = append(runner.URLs, option.URL)
	}

	if option.URLFile != "" {
		urls, err := util.LoadTargets(option.URLFile)
		if err != nil {
			return runner, err
		}
		runner.URLs = append(runner.URLs, urls...)
	}

	if option.IsCheckAll || option.IsEndpointCheck {
		err := godotenv.Load(option.EnvPath)
		if err != nil {
			return runner, fmt.Errorf("Error loading .env file: %v", err)
		}
		// Todo When you add new ai source engines, add new "case" condition to init ai engine
		switch option.AiSource {
		case gemini.GEMINI:
			gemini := gemini.Provider{}
			err = gemini.Auth()
			if err != nil {
				return runner, err
			}
			runner.AIEngine = gemini
			//case gpt.Gpt:
			//	runner.AIEngine = gpt.Provider{}
		}
	}

	// load extractors
	if len(extracter.Extractors) == 0 {
		return runner, errors.New("not regexp extractor loaded")
	}
	runner.extractors = extracter.Extractors

	// initialize option for vue path check
	if option.IsVuePathCheck || option.IsCheckAll {
		runner.crawlerEngine = headless.NewCrawler(option.IsHeadless)
		runner.vueTaskChan = make(chan *headless.Task, 30)
	}

	if option.IsEndpointCheck || option.IsCheckAll {
		runner.endpointTaskChan = make(chan string)
	}

	// Max goroutines to handle urls
	sw := sizedwaitgroup.New(30)
	runner.MaxGoroutines = &sw
	runner.outChannel = make(chan types.Result)
	runner.outputOver = make(chan struct{})

	runner.writer = &writer.Writer{}
	runner.processWg = sync.WaitGroup{}

	return runner, nil
}

func (r *Runner) Run() error {
	// start result handle process
	go func() {
		defer func() {
			r.outputOver <- struct{}{}
			gologger.Debug().Msgf("Output channel over.\n")
		}()

		for rst := range r.outChannel {
			r.writer.DefaultWriter(rst)
		}
	}()

	// start corresponding job
	if r.vueTaskChan != nil {
		r.processWg.Add(1)

		go r.runVueCheck()
	}

	if r.endpointTaskChan != nil {
		r.processWg.Add(1)

		go r.checkEndpoint()
	}

	for _, u := range r.URLs {
		// Todo there is problem that endpoint has two analysis method, regexp and ai source
		// In this condition, judge ai source only, need improve later
		if r.AIEngine != nil {
			r.endpointTaskChan <- u
		}

		if r.vueTaskChan != nil {
			t := headless.NewTask(u)
			r.vueTaskChan <- t
		}
	}

	// producer is over
	r.closeTaskQueue()

	// wait vue path check process and endpoint check process done
	r.processWg.Wait()
	r.Close()

	return nil
}

func (r *Runner) Close() {
	close(r.outChannel)
	<-r.outputOver
}

// closeTaskQueue
func (r *Runner) closeTaskQueue() {
	if r.endpointTaskChan != nil {
		close(r.endpointTaskChan)
	}
	if r.vueTaskChan != nil {
		close(r.vueTaskChan)
	}
}

func (r *Runner) runEndpointCheck(u string) {
	defer r.MaxGoroutines.Done()

	// 1. check target connection
	reqClient := httpx.NewGetClient(r.options.Proxy, 10)
	resp, err := reqClient.DoRequest(u)
	if err != nil || resp.StatusCode == 404 {
		gologger.Error().Msgf("URL: %s can not access \n", u)
		return
	}

	// Todo 2. choose corresponding extractor to analyze javascript file
	// ajax or webpack

	// 3. find available js paths and extract javascript
	// Todo haven't consider if the javascript path is a completed URL
	jsPaths := analyze.ParseJS(resp.String(), resp.Body)
	gologger.Info().Msgf("Find %d Javascript file in %s \n", len(jsPaths), u)

	var (
		subPathLists []string
		baseURL      string
		jsURIs       []string
	)

	// locate the base url
	uu, err := url.Parse(u)
	if err != nil {
		gologger.Error().Msgf("Can not parse url: %s \n", u)
		return
	}
	tmpBaseURL := fmt.Sprintf("%s://%s", uu.Scheme, uu.Host)

	subPah := strings.Split(uu.Path, "/")
	for i := 0; i < len(subPah); i++ {
		subPathLists = append(subPathLists, strings.Join(subPah[:i+1], "/"))
	}
	tmpU := tmpBaseURL + jsPaths[0]

	resp, err = reqClient.DoRequest(tmpU)
	if err != nil {
		gologger.Error().Msgf("URL: %s can not access \n", tmpU)
		gologger.Debug().
			Msgf("Get base url error: %s\n", err)
		return
	}
	// Content-Encoding: gzip can not get the content length field directly
	//if resp.StatusCode == 200 && resp.ContentLength > 0 {
	if resp.StatusCode == 200 {
		baseURL = tmpBaseURL
	} else {
		for _, subPath := range subPathLists {
			tmpU = tmpBaseURL + subPath
			resp, err = reqClient.DoRequest(tmpU)
			if err != nil {
				continue
			}
			if resp.StatusCode == 200 && resp.ContentLength > 0 {
				baseURL = tmpBaseURL
				break
			}
		}
	}

	if baseURL == "" {
		gologger.Error().Msgf("Can not get base url: %s\n", u)
		return
	}

	for _, jsPath := range jsPaths {
		jsURIs = append(jsURIs, baseURL+jsPath)
	}

	// 4. find endpoints from javascript file and
	var endpoints []string
	for _, jsUrl := range jsURIs {
		resp, err = reqClient.DoRequest(jsUrl)
		if err != nil {
			continue
		}

		stringBody := resp.String()

		for _, ector := range r.extractors {
			if ector.Type() == extracter.PATH {
				ed := ector.Extract(stringBody)
				endpoints = append(endpoints, ed...)
			}
		}
	}

	endpoints = util.UniqueSlice(endpoints)
	// Todo somethings the input is too long, need optimize prompt or input
	input := strings.Join(endpoints, "\n")
	if input == "" {
		return
	}
	endpointsFromAI, err := r.AIEngine.Generate(input)
	if err != nil {
		gologger.Error().Msgf("%s\n", err)
		return
	}

	for _, ep := range endpointsFromAI {
		epClient := httpx.Endpoint2Client(ep)
		epURI := baseURL + ep.Path
		resp, err = epClient.DoRequest(epURI)
		if err != nil {
			continue
		}

		// Todo transfer response into VueTargetInfo and send it to outChannel
		r.outChannel <- types.Result{
			Response: resp.Response,
		}
	}
}

func (r *Runner) runVueCheck() {
	defer func() {
		r.processWg.Done()
		gologger.Debug().Msgf("Vue path task done.")
	}()

	gologger.Info().Msgf("Start vue check...\n")

	for vueCheckTask := range r.vueTaskChan {
		rst, page := r.crawlerEngine.RunHeadless(vueCheckTask)

		if len(rst.Subs) > 0 {
			rs := headless.CategoryReqType(rst)
			rets := r.crawlerEngine.HtmlBrokenAnalysis(rs)
			for ret := range rets {
				r.outChannel <- ret
			}
		}
		page.MustClose()
	}
}

func (r *Runner) checkEndpoint() {
	defer func() {
		r.processWg.Done()
		gologger.Debug().Msgf("Endpoint task done.")
	}()

	gologger.Info().Msgf("Start endpoint check...\n")

	for endpointCheckTask := range r.endpointTaskChan {
		r.MaxGoroutines.Add()
		go r.runEndpointCheck(endpointCheckTask)
	}

	r.MaxGoroutines.Wait()
}
