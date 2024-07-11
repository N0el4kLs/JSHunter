package util

import (
	"bufio"
	"os"
)

func LoadTargets(path string) ([]string, error) {
	var results []string
	_, err := os.Stat(path)
	if err != nil {
		return results, err
	}
	reader, _ := os.Open(path)
	defer reader.Close()

	rScanner := bufio.NewScanner(reader)
	rScanner.Split(bufio.ScanLines)
	for rScanner.Scan() {
		results = append(results, rScanner.Text())
	}
	return results, nil
}

func UniqueSlice(slice []string) []string {
	var (
		uniqueResult []string
		tmp          = make(map[string]struct{})
	)
	for _, v := range slice {
		if _, ok := tmp[v]; !ok {
			uniqueResult = append(uniqueResult, v)
			tmp[v] = struct{}{}
		}
	}
	return uniqueResult
}
