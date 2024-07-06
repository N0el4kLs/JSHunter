package runner

import (
	"errors"
	"strings"

	"js-hunter/pkg/llm/gemini"
	"js-hunter/pkg/llm/gpt"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

type Options struct {
	// URL to find vulnerabilities in javascript files
	URL string

	// URLFile which contains URLs to find vulnerabilities in javascript files
	URLFile string

	// IsCheckAll is a flag to check all
	IsCheckAll bool

	// IsEndpointCheck is a flag to check for endpoints
	IsEndpointCheck bool

	// IsVuePathCheck is a flag to check vue paths
	IsVuePathCheck bool

	// Proxy to use for the request client
	Proxy string

	// Timeout for the request client
	Timeout int

	// Threads
	Threads int

	// Headers for request client
	Headers string

	// Ai source to use
	AiSource string

	// Output
	Output string

	// Debug option
	// IsDebug set log level to debug
	IsDebug bool

	// IsHeadless enable headless browser or log
	IsHeadless bool
}

func ParseOptions() (*Options, error) {
	ShowBanner()

	options := &Options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("A tool to find vulnerabilities in javascript files")

	flagSet.CreateGroup("input", "INPUT",
		flagSet.StringVarP(&options.URL, "url", "u", "", "URL to find vulnerabilities in javascript files"),
		flagSet.StringVarP(&options.URLFile, "file", "f", "", "File containing URLs to find vulnerabilities in javascript files"),
	)

	flagSet.CreateGroup("options", "OPTIONS",
		flagSet.BoolVar(&options.IsCheckAll, "ac", false, "Check both endpoints and vue paths"),
		flagSet.BoolVar(&options.IsEndpointCheck, "ec", false, "Check for endpoints"),
		flagSet.BoolVar(&options.IsVuePathCheck, "vc", false, "Check for vue paths"),
		flagSet.StringVar(&options.AiSource, "ai", "gemini",
			"AI source to use for extracting endpoints.Only support gemini and gpt3 for now. Default is gemini."),
		flagSet.StringVarP(&options.Proxy, "proxy", "p", "", "Proxy to use for the requests"),
		flagSet.IntVarP(&options.Timeout, "timeout", "t", 15, "Timeout in seconds for the requests"),
		flagSet.IntVarP(&options.Threads, "threads", "T", 50, "Number of threads to use for the scanner"),
		flagSet.StringVarP(&options.Headers, "headers", "H", "", "Headers to use for the requests"),
	)

	flagSet.CreateGroup("output", "OUTPUT",
		flagSet.StringVarP(&options.Output, "output", "o", "", "File to write the output to"),
	)

	flagSet.CreateGroup("debug", "DEBUG",
		flagSet.BoolVar(&options.IsDebug, "debug", false, "Enable debug mode"),
		flagSet.BoolVar(&options.IsHeadless, "headless", false, "enable headless browser while running"),
	)

	if err := flagSet.Parse(); err != nil {
		return nil, err
	}

	if options.IsDebug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	} else {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelError)
	}

	if options.URLFile == "" && options.URL == "" {
		return nil, errors.New("please provide a URL or a file containing URLs")
	}

	if !(options.IsCheckAll || options.IsVuePathCheck || options.IsCheckAll) {
		return nil, errors.New("must choose a scan type")
	}

	if strings.ToLower(options.AiSource) == strings.ToLower(gemini.GEMINI) {
		options.AiSource = gemini.GEMINI
	} else if strings.ToLower(options.AiSource) != strings.ToLower(gpt.Gpt) {
		options.AiSource = gpt.Gpt
	} else {
		return nil, errors.New("unknown ai provider,only support gemini and gpt3 for now. Example: --ai gemini or --ai gpt")
	}

	return options, nil
}
