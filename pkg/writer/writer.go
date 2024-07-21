package writer

import (
	"html/template"
	"os"
	"path/filepath"
	"strings"

	"js-hunter/pkg/types"
	"js-hunter/pkg/util"

	"github.com/projectdiscovery/gologger"
)

type Writer struct {
	//isJson bool
	//outputFile io.WriteCloser

	vueResultBuffer map[string]*types.MarkdownBuffer
}

func NewWriter() *Writer {
	w := &Writer{}
	w.vueResultBuffer = make(map[string]*types.MarkdownBuffer)

	return w
}

func (w *Writer) DefaultWriter(rst types.Result) {
	// Write data to output
	var builder strings.Builder

	if rst.TypeOfRst&types.EndpointCheckType == types.EndpointCheckType {
		builder.WriteString(rst.Response.Request.URL.String())

		builder.WriteString(" [")
		builder.WriteString(rst.Response.Request.Method)
		builder.WriteString(" ] ")
	}

	if rst.TypeOfRst&types.VuePathCheckType == types.VuePathCheckType {
		builder.WriteString(rst.VuePathRst.URI)
		if w.vueResultBuffer[rst.VuePathRst.ParentURL] == nil {
			w.vueResultBuffer[rst.VuePathRst.ParentURL] = types.NewReadmeBuffer()
		}
		w.vueResultBuffer[rst.VuePathRst.ParentURL].AddItem(rst.VuePathRst.URI, rst.VuePathRst.ScreenshotName)
	}

	gologger.Info().Label(types.WithLabel(rst.TypeOfRst)).
		Msgf(builder.String())
}

func (w *Writer) Close() {
	w.exportVuePathReport()
}

func (w *Writer) exportVuePathReport() {
	for baseU, contentBuffer := range w.vueResultBuffer {
		// if haven't any vue router result, do not generate the report and clean the screenshot folder
		resultFolder := filepath.Join(util.WorkDir, "reports", "vue_reports", util.URL2FileName(baseU))
		if contentBuffer.Toc.String() == "" {
			os.RemoveAll(resultFolder)
			continue
		}

		tmpl, _ := template.New("markdownReport").Parse(util.GetTemplateContent())
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
}
