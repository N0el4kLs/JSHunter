package llm

import (
	"context"

	"js-hunter/pkg/types"
)

type AIProvider interface {
	Name() string
	Auth(context.Context) error
	Generate(context.Context, string) ([]types.EndPoint, error)
}

type AIEngine struct {
	Provider AIProvider
}
