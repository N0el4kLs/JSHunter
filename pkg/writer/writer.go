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

	vueResultBuffer map[string]*types.ReadmeBuffer
}

func NewWriter() *Writer {
	w := &Writer{}
	w.vueResultBuffer = make(map[string]*types.ReadmeBuffer)

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
			w.vueResultBuffer[rst.VuePathRst.ParentURL] = new(types.ReadmeBuffer)
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
		tmpl, _ := template.New("markdownReport").Parse(util.GetTemplateContent())
		data := struct {
			URL, Toc, Detail string
		}{
			URL:    baseU,
			Toc:    contentBuffer.Toc.String(),
			Detail: contentBuffer.Detail.String(),
		}

		markdownReportLocaion := filepath.Join("reports", "vue_reports", util.URL2FileName(baseU), "report.md")
		reportHandle, _ := os.OpenFile(markdownReportLocaion, os.O_CREATE|os.O_APPEND, 0777)
		tmpl.Execute(reportHandle, data)
	}
}
