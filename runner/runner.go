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
	"js-hunter/pkg/llm/gpt"
	"js-hunter/pkg/types"
	"js-hunter/pkg/util"
	"js-hunter/pkg/writer"

	"github.com/projectdiscovery/gologger"
	"github.com/remeh/sizedwaitgroup"
)

type Runner struct {
	options *Options

	// URLs
	URLs []string

	AIEngine llm.AIProvider

	// MaxGoroutines to limit the max number of URLs while handling
	MaxGoroutines *sizedwaitgroup.SizedWaitGroup

	// output channel
	outChannel chan types.Result

	// writer
	writer *writer.Writer

	// extractors all regexp extract Operations to match detail needed inform
	extractors []extracter.Extracter

	// crawlerEngine is chromium engine for checking vue path
	crawlerEngine *headless.Crawler

	// vueTaskChan vue path check task channel
	vueTaskChan chan *headless.Task

	// vueTaskEndSignChan
	vueTaskEndSignChan chan struct{}

	// processWg endpoint and vue check task wait group to end the process
	processWg sync.WaitGroup
}

func NewRunner(option *Options) (*Runner, error) {
	runner := &Runner{
		options: option,
	}

	// load target(s) from CLI or file
	if option.URL != "" {
		// Two test urls
		// https://cloudvse.com/login
		// https://studiosansa.se/login

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
		// Todo init ai source engine
		switch option.AiSource {
		case gemini.GEMINI:
			runner.AIEngine = gemini.Provider{}
		case gpt.Gpt:
			runner.AIEngine = gpt.Provider{}
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

	// Max goroutines to handle urls
	sw := sizedwaitgroup.New(30)
	runner.MaxGoroutines = &sw
	runner.outChannel = make(chan types.Result)

	runner.writer = &writer.Writer{}
	runner.processWg = sync.WaitGroup{}
	runner.processWg.Add(2)

	return runner, nil
}

func (r *Runner) Run() error {
	go func() {
		for rst := range r.outChannel {
			// Todo use writer to handle rst
			r.writer.StdWriter(rst)
		}
	}()

	if r.vueTaskChan != nil {
		// Todo handle vue max worker control
		go r.runVueCheck("")
	}

	for _, u := range r.URLs {
		if r.AIEngine != nil {
			r.MaxGoroutines.Add()
			go r.runEnumerate(u)
		}

		//if r.vueTaskChan != nil {
		//	// Todo handle vue max worker control
		//	go r.runVueCheck(u)
		//}

		if r.vueTaskChan != nil {
			t := headless.NewTask(u)
			r.vueTaskChan <- t
		}

	}
	close(r.vueTaskChan)

	// wait all goroutine done
	go func() {
		r.MaxGoroutines.Wait()
		r.processWg.Done()
		gologger.Debug().Msgf("Endpoint task done.")
	}()

	r.processWg.Wait()
	r.Close()

	return nil
}

func (r *Runner) Close() {
	close(r.outChannel)
}

func (r *Runner) runEnumerate(u string) {
	defer r.MaxGoroutines.Done()

	// 1. check connection
	reqClient := httpx.NewGetClient(r.options.Proxy, 10)
	resp, err := reqClient.DoRequest(u)
	if err != nil || resp.StatusCode == 404 {
		gologger.Error().Msgf("URL: %s can not access \n", u)
		return
	}

	// Todo 2. analyze js type: jquery or webpack

	// 3. find available js paths
	// Todo haven't consider if the javascript path is a completed URL
	jsPaths := analyze.ParseJS(resp.String(), resp.Body)

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

	// 3. find endpoints
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

	// Todo somethings the input is too long, need optimize prompt or input
	input := strings.Join(endpoints[len(endpoints)-20:], "\n")
	if input == "" {
		return
	}
	endpointsFromAI := r.AIEngine.Generate(input)

	//unqEndpoints := map[string]struct{}{}
	// Todo Add goroutine to handle endpoint check
	for _, ep := range endpointsFromAI {
		// unique endpoint
		//ep.SetHash()
		//if _, ok := unqEndpoints[ep.Hash]; ok {
		//	continue
		//}
		//unqEndpoints[ep.Hash] = struct{}{}

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

func (r *Runner) runVueCheck(u string) {
	defer func() {
		r.processWg.Done()
		gologger.Debug().Msgf("Vue path task done.")
	}()

	for vueCheckTask := range r.vueTaskChan {
		rst, page := r.crawlerEngine.RunHeadless(vueCheckTask)
		// Todo there is a problem that rst can never be nil
		if rst == nil {
			gologger.Debug().
				Msgf("Get result from crawler engine failed,current task is %s\n", rst.URL)
			page.MustClose()
			continue
		}

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

func (r *Runner) checkEndpoint(ep types.EndPoint) {

}
