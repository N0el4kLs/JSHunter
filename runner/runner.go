package runner

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"js-hunter/pkg/analyze"
	"js-hunter/pkg/extracter"
	_ "js-hunter/pkg/extracter/extractor/api_key"
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
	vueTaskChan chan *types.Task

	// processWg endpoint and vue check task wait group to end the process
	processWg sync.WaitGroup
}

func NewRunner(option *Options) (*Runner, error) {
	runner := &Runner{
		options: option,
	}

	// load target(s) from CLI or file
	if option.URL != "" {
		runner.URLs = append(runner.URLs, option.URL)
	}

	if option.URLFile != "" {
		urls, err := util.LoadTargets(option.URLFile)
		if err != nil {
			return runner, err
		}
		runner.URLs = append(runner.URLs, urls...)
	}

	if option.AiSource != "" && (option.IsEndpointCheck || option.IsCheckAll) {
		envPath := util.FixPath(option.EnvPath)
		gologger.Info().Msgf("Load env file from: %s\n", envPath)
		err := godotenv.Load(envPath)
		if err != nil {
			return runner, fmt.Errorf("Error loading .env file: %v", err)
		}
		// Todo When you add new ai source engines, add new "case" condition to init ai engine
		switch option.AiSource {
		case gemini.GEMINI:
			geminiEngine := gemini.Provider{}
			err = geminiEngine.Auth()
			if err != nil {
				return runner, err
			}
			runner.AIEngine = geminiEngine
			gologger.Info().Msgf("Gemini ai source is ready...\n")
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
		runner.vueTaskChan = make(chan *types.Task, 30)
	}

	if option.IsEndpointCheck || option.IsCheckAll {
		runner.endpointTaskChan = make(chan string)
	}

	// Max goroutines to handle urls
	sw := sizedwaitgroup.New(30)
	runner.MaxGoroutines = &sw
	runner.outChannel = make(chan types.Result)
	runner.outputOver = make(chan struct{})

	runner.writer = writer.NewWriter()
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

		go r.runVuePathCheck()
	}

	if r.endpointTaskChan != nil {
		r.processWg.Add(1)

		go r.checkEndpoint()
	}

	for _, u := range r.URLs {
		// Todo there is problem that endpoint has two analysis method, regexp and ai source
		// In this condition, judge ai source only, need improve later
		if r.endpointTaskChan != nil {
			r.endpointTaskChan <- u
		}

		if r.vueTaskChan != nil {
			t := types.NewTask(u)
			r.vueTaskChan <- t
		}
	}

	// producer is over
	r.closeTaskQueue()

	// wait vue path check process and endpoint check process done
	r.processWg.Wait()

	return nil
}

func (r *Runner) Close() {
	close(r.outChannel)
	<-r.outputOver
	if r.crawlerEngine != nil {
		r.crawlerEngine.Close()
	}
	r.writer.Close()
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
		gologger.Warning().Msgf("URL: %s can not access \n", u)
		return
	}

	// 2 . find available js paths and extract information from js files
	// 2.1 find all js paths
	var (
		baseURL string
		jsURIs  []string
	)
	jsPaths, completeU := analyze.ParseJS(u, resp.Body)
	gologger.Info().Msgf("Find %d Javascript file in %s \n", len(jsPaths), u)

	baseURL = findBaseURL(u, completeU, jsPaths)
	if baseURL == "" {
		gologger.Warning().Msgf("Can not get base url: %s\n", u)
		return
	}
	//  get all absolute js path
	for _, jsPath := range jsPaths {
		if strings.HasPrefix(jsPath, "http") {
			jsURIs = append(jsURIs, jsPath)
			continue
		}
		jsURIs = append(jsURIs, baseURL+jsPath)
	}
	// add base url to jsURIs to sensitive extract
	jsURIs = append(jsURIs, u)
	// 2.2 extract endpoints keywords and sensitive information from js files
	endpointsKeyword := r.jsInformExtract(jsURIs)
	endpointsKeyword = util.UniqueSlice(endpointsKeyword)
	if len(endpointsKeyword) == 0 {
		return
	}

	// 3. analyze endpoints
	var (
		endpointsChan     = make(chan types.EndPoint)
		analysisProcessWg = &sync.WaitGroup{}
	)
	// 3.1 use Ai engine to analyze endpoints
	if r.AIEngine != nil {
		analysisProcessWg.Add(1)
		gologger.Info().Msgf("Start parse the content with %s.\n", r.options.AiSource)
		go r.analyzeWithAi(endpointsChan, endpointsKeyword, analysisProcessWg)
	}
	// 3.2 analyze the endpoint manually
	// ajax or webpack
	analysisProcessWg.Add(1)
	go r.analyzeWithManual(analyze.GetJavascriptType(resp.String()), endpointsChan, endpointsKeyword, analysisProcessWg)

	// wait all analysis process done and close the endpointsChan
	go func() {
		analysisProcessWg.Wait()
		close(endpointsChan)
	}()

	// 4. check whether the endpoint is broken or not
	for ep := range endpointsChan {
		epClient := types.Endpoint2Client(ep)
		epURI := baseURL + ep.Path
		resp1, err1 := epClient.DoRequest(epURI)
		if err1 != nil {
			continue
		}

		// Just output the information of each endpoint request
		// and let user determine whether it is a broken access or not
		r.outChannel <- types.NewEdRst(resp1)
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

func (r *Runner) runVuePathCheck() {
	defer func() {
		r.processWg.Done()
		gologger.Debug().Msgf("Vue path task done.")
	}()

	gologger.Info().Msgf("Start vue path check...\n")

	for vueCheckTask := range r.vueTaskChan {
		currentTask, page := r.crawlerEngine.GetAllVueRouters(vueCheckTask)

		// if find vue router
		if len(currentTask.Subs) > 0 {
			ctx, checkItems := headless.PrepareRouterCheck(currentTask)
			rets := r.crawlerEngine.RouterBrokenAnalysis(ctx, checkItems)
			for ret := range rets {
				r.outChannel <- ret
			}
		}
		page.MustClose()
	}
}

// jsInformExtract find the all endpoint snippet and sensitive inform in the js file
func (r *Runner) jsInformExtract(jsURIs []string) []string {
	var (
		endpoints     []string
		sensitiveUniq = make(map[string]struct{})
	)
	reqClient := httpx.NewGetClient(r.options.Proxy, 10)

	for _, jsUrl := range jsURIs {
		resp, err := reqClient.DoRequest(jsUrl)
		if err != nil {
			gologger.Warning().Msgf("Can not access javascript file: %s\n", jsUrl)
			continue
		}

		stringBody := resp.String()

		for _, ector := range r.extractors {
			ed := ector.Extract(stringBody)
			switch ector.Type() {
			case extracter.PATH:
				endpoints = append(endpoints, ed...)
			case extracter.SENSITIVE:
				for _, sen := range ed {
					if _, ok := sensitiveUniq[sen]; !ok {
						sensitiveUniq[sen] = struct{}{}
						r.outChannel <- types.Result{
							TypeOfRst: types.SensitiveCheckType,
							SensitiveRst: types.InspectSensitiveRst{
								URL: jsUrl,
								Msg: sen,
							},
						}
					}
				}
			}
		}
	}
	return endpoints
}

func (r *Runner) analyzeWithAi(edChan chan<- types.EndPoint, edpointsSnippets []string, wg *sync.WaitGroup) {
	defer wg.Done()

	var (
		loopCount = len(edpointsSnippets) / 20
		aiWg      = sync.WaitGroup{}
	)
	// In order to avoid the long text input and long generate time,
	// divide the endpointsKeyword into 20 endpointsKeyword for each input
	if len(edpointsSnippets)%20 != 0 {
		loopCount++
	}
	for i := 0; i < loopCount; i++ {
		aiWg.Add(1)
		go func(index int) {
			defer aiWg.Done()

			var input string
			if index == loopCount-1 {
				input = strings.Join(edpointsSnippets[index*20:], "\n")
			} else {
				input = strings.Join(edpointsSnippets[index*20:(index+1)*20], "\n")
			}

			endpointsFromAI, err := r.AIEngine.Generate(input)
			if err != nil {
				gologger.Error().Msgf("%s\n", err)
				return
			}
			for _, ed := range endpointsFromAI {
				edChan <- ed
			}
		}(i)
	}

	aiWg.Wait()
}

func (r *Runner) analyzeWithManual(jsType analyze.JavascriptType, edChan chan<- types.EndPoint, edpintsKeywords []string, wg *sync.WaitGroup) {
	defer wg.Done()
	switch jsType {
	case analyze.Ajax:
		// Todo
	case analyze.Webpack:
		// todo
	}
}
func findBaseURL(u, completeU string, pathes []string) string {
	if completeU != "" {
		l, baseurl := util.LongestCommonSubstring(u, completeU)
		if l != 0 {
			return baseurl
		}
		gologger.Debug().Msgf("Can not find common substring between %s and %s\n", u, completeU)
	}
	if len(pathes) == 0 {
		return u
	}
	var (
		subPathLists []string
		baseURL      string
	)
	uu, err := url.Parse(u)
	if err != nil {
		gologger.Error().Msgf("Can not parse url: %s \n", u)
		return ""
	}
	tmpBaseURL := fmt.Sprintf("%s://%s", uu.Scheme, uu.Host)
	subPah := strings.Split(uu.Path, "/")
	for i := 0; i < len(subPah); i++ {
		subPathLists = append(subPathLists, strings.Join(subPah[:i+1], "/"))
	}
	tmpU := tmpBaseURL + pathes[0]
	reqClient := httpx.NewGetClient("", 10)
	resp, err := reqClient.DoRequest(tmpU)
	if err != nil {
		gologger.Error().Msgf("URL: %s can not access \n", tmpU)
		gologger.Debug().
			Msgf("Get base url error: %s\n", err)
		return ""
	}
	// Content-Encoding: gzip can not get the content length field directly
	//if resp.StatusCode == 200 && resp.ContentLength > 0 {
	if resp.StatusCode == 200 {
		baseURL = tmpBaseURL
	} else {
		for _, subPath := range subPathLists {
			tmpU = tmpBaseURL + subPath + pathes[0]
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
	return baseURL
}
