package llm

import (
	"js-hunter/pkg/types"
)

type AIProvider interface {
	Name() string
	Auth() error
	Generate(string) ([]types.EndPoint, error)
}

type AIEngine struct {
	Provider AIProvider
}
