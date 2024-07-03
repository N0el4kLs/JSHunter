package writer

import (
	"strconv"
	"strings"

	"js-hunter/pkg/types"

	"github.com/projectdiscovery/gologger"
)

type Writer struct {
	//isJson bool
	//outputFile io.WriteCloser
}

//func (w *Writer) HandleOuput() {
//
//}

func (w *Writer) StdWriter(rst types.Result) {
	// Write data to output
	var builder strings.Builder
	//builder.WriteString("URL: ")
	builder.WriteString(rst.Response.Request.RawURL)

	if rst.Response.StatusCode != 404 {
		builder.WriteString(" [")
		builder.WriteString(strconv.Itoa(rst.Response.StatusCode))
		builder.WriteString("] ")

		builder.WriteString("[")
		builder.WriteString(strconv.Itoa(len((rst.Response.String()))))
		builder.WriteString("] ")

		//builder.WriteString("[")
		//builder.WriteString("Maybe Broken Access")
		//builder.WriteString("] ")
	}

	gologger.Info().Msgf(builder.String())
}

func (w *Writer) Close() {

}
