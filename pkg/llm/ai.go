package llm

import (
	"js-hunter/pkg/types"
)

type AIProvider interface {
	Name() string
	Generate(string) []types.EndPoint
}

type AIEngine struct {
	Provider AIProvider
}
