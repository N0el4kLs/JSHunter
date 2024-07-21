package main

import (
	"os"
	"os/signal"
	"time"

	"js-hunter/runner"

	"github.com/projectdiscovery/gologger"
)

func main() {
	options, err := runner.ParseOptions()
	if err != nil {
		gologger.Fatal().Msgf("Could not parse options: %s\n", err)
	}
	newRunner, err := runner.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}

	start := time.Now()

	c := make(chan os.Signal, 1)
	defer close(c)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			gologger.Info().Msgf("CTRL+C pressed: Exiting\n")
			gologger.Info().Msgf("Attempting graceful shutdown...")
			newRunner.Close()
			os.Exit(1)
		}
	}()

	if err = newRunner.Run(); err != nil {
		gologger.Fatal().Msgf("Could not run runner: %s\n", err)
		newRunner.Close()
	}
	newRunner.Close()
	gologger.Info().Msgf("Task done,cost: %v\n", time.Since(start))
}
