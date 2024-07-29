package writer

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"js-hunter/pkg/types"
	"js-hunter/pkg/util"

	"github.com/projectdiscovery/gologger"
)

type Writer struct {
	edResultBuffer map[string]*types.MarkdownBuffer

	vueResultBuffer map[string]*types.MarkdownBuffer
}

func NewWriter() *Writer {
	w := &Writer{}
	w.edResultBuffer = make(map[string]*types.MarkdownBuffer)
	w.vueResultBuffer = make(map[string]*types.MarkdownBuffer)

	return w
}

func (w *Writer) DefaultWriter(rst types.Result) {
	// Write data to output
	var builder strings.Builder

	if rst.TypeOfRst&types.EndpointCheckType == types.EndpointCheckType {
		builder.WriteString(rst.EndpointRst.URL)

		builder.WriteString(" [")
		builder.WriteString(rst.EndpointRst.Method)
		builder.WriteString("] ")

		builder.WriteString("[")
		builder.WriteString(strconv.Itoa(rst.EndpointRst.StatusCode))
		builder.WriteString("] ")
		title := fmt.Sprintf("%s [%v]", rst.EndpointRst.URL, rst.EndpointRst.StatusCode)
		if w.edResultBuffer[title] == nil {
			w.edResultBuffer[title] = types.NewReadmeBuffer()
		}
		w.edResultBuffer[title].AddEdItem(title, rst.Response.Dump())
	}

	if rst.TypeOfRst&types.SensitiveCheckType == types.SensitiveCheckType {
		builder.WriteString(rst.SensitiveRst.URL)

		builder.WriteString(" [")
		builder.WriteString(rst.SensitiveRst.Msg)
		builder.WriteString(" ] ")
	}

	if rst.TypeOfRst&types.VuePathCheckType == types.VuePathCheckType {
		builder.WriteString(rst.VuePathRst.URI)
		if w.vueResultBuffer[rst.VuePathRst.ParentURL] == nil {
			w.vueResultBuffer[rst.VuePathRst.ParentURL] = types.NewReadmeBuffer()
		}
		w.vueResultBuffer[rst.VuePathRst.ParentURL].AddVueItem(rst.VuePathRst.URI, rst.VuePathRst.ScreenshotName)
	}

	gologger.Info().Label(types.WithLabel(rst.TypeOfRst)).
		Msgf(builder.String())
}

func (w *Writer) Close() {
	w.exportVuePathReport()
}

func (w *Writer) exportVuePathReport() {
	writerWg := sync.WaitGroup{}
	writerWg.Add(2)

	// vue result to file
	go func() {
		defer writerWg.Done()

		for baseU, contentBuffer := range w.vueResultBuffer {
			// if haven't any vue router result, do not generate the report and clean the screenshot folder
			resultFolder := filepath.Join(util.WorkDir, "reports", "vue_reports", util.URL2FileName(baseU))
			if contentBuffer.Toc.String() == "" {
				os.RemoveAll(resultFolder)
				continue
			}

			tmpl, _ := template.New("vueReport").Parse(util.GetTemplateContent())
			data := struct {
				URL, Toc, Detail string
			}{
				URL:    baseU,
				Toc:    contentBuffer.Toc.String(),
				Detail: contentBuffer.Detail.String(),
			}

			markdownReportLocaion := filepath.Join(resultFolder, "report.md")
			reportHandle, _ := os.OpenFile(markdownReportLocaion, os.O_CREATE|os.O_RDWR, 0777)
			err := tmpl.Execute(reportHandle, data)
			if err != nil {
				gologger.Warning().Msgf("Error is:%s\n", err)
			}
			gologger.Info().Msgf("Vue path report location: %s\n", markdownReportLocaion)
		}
	}()

	// endpoint result to file
	go func() {
		defer writerWg.Done()
		var (
			tocs    string
			details string
		)

		for _, contentBuffer := range w.edResultBuffer {
			if contentBuffer.Toc.String() == "" {
				continue
			}
			tocs += contentBuffer.Toc.String()
			details += contentBuffer.Detail.String()
		}
		if tocs == "" {
			return
		}
		resultFolder := filepath.Join(util.WorkDir, "reports", "endpoint_reports")
		tmpl, _ := template.New("edReport").Parse(util.GetTemplateContent())
		data := struct {
			URL, Toc, Detail string
		}{
			URL:    "Endpoint Req Report",
			Toc:    tocs,
			Detail: details,
		}
		markdownReportLocaion := filepath.Join(resultFolder, util.GenEdResultFilename())
		reportHandle, _ := os.OpenFile(markdownReportLocaion, os.O_CREATE|os.O_RDWR, 0777)
		err := tmpl.Execute(reportHandle, data)
		if err != nil {
			gologger.Warning().Msgf("Error is:%s\n", err)
		}
		gologger.Info().Msgf("endpoint check report location: %s\n", markdownReportLocaion)
	}()

	writerWg.Wait()
}
