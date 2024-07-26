package util

import (
	"bufio"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

var (
	WorkDir string
)

func init() {
	WorkDir, _ = os.Getwd()
}

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

func URL2FileName(u string) string {
	uu, _ := url.Parse(u)
	fileName := uu.Host
	if strings.Contains(fileName, ":") {
		fileName = strings.Replace(fileName, ":", "_", -1)
	}
	return fileName
}

func GetTemplateContent() string {
	content := `## {{.URL}}
### TABLE_OF_CONTENT
{{.Toc}}

### DETAIL
{{.Detail}}
`
	return content
}

func FixPath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(WorkDir, path)
}
