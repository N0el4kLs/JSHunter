package writer

import (
	"strings"

	"js-hunter/pkg/types"

	"github.com/projectdiscovery/gologger"
)

type Writer struct {
	//isJson bool
	//outputFile io.WriteCloser
}

func (w *Writer) StdWriter(rst types.Result) {
	// Write data to output
	var builder strings.Builder

	if rst.TypeOfRst&types.EndpointCheckType == types.EndpointCheckType {
		builder.WriteString(rst.Response.Request.RawURL)

		builder.WriteString(" [")
		builder.WriteString(rst.Response.Request.Method)
		builder.WriteString(" ] ")

		////builder.WriteString("URL: ")
		//builder.WriteString(rst.Response.Request.RawURL)
		//
		//if rst.Response.StatusCode != 404 {
		//	builder.WriteString(" [")
		//	builder.WriteString(strconv.Itoa(rst.Response.StatusCode))
		//	builder.WriteString("] ")
		//
		//	builder.WriteString("[")
		//	builder.WriteString(strconv.Itoa(len((rst.Response.String()))))
		//	builder.WriteString("] ")
		//
		//	//builder.WriteString("[")
		//	//builder.WriteString("Maybe Broken Access")
		//	//builder.WriteString("] ")
		//}
	}

	if rst.TypeOfRst&types.VuePathCheckType == types.VuePathCheckType {
		builder.WriteString(rst.VuePathRst.URI)
	}

	gologger.Info().Label(types.WithLabel(rst.TypeOfRst)).
		Msgf(builder.String())
}

func (w *Writer) Close() {

}
