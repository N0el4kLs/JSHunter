package types

import (
	"fmt"
	"strings"
)

type MarkdownBuffer struct {
	// Toc table of content
	Toc strings.Builder

	// Detail detail information about each item
	Detail strings.Builder
}

func NewReadmeBuffer() *MarkdownBuffer {
	return &MarkdownBuffer{
		Toc:    strings.Builder{},
		Detail: strings.Builder{},
	}
}

func (r *MarkdownBuffer) AddItem(s, location string) {
	r.Toc.WriteString(fmt.Sprintf("[%s](####%s)\n", s, s))

	r.Detail.WriteString(fmt.Sprintf("#### %s\n", s))
	r.Detail.WriteString(fmt.Sprintf("![](%s)\n", location))
}
