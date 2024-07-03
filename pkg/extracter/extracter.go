package extracter

var Extractors []Extracter

const (
	PATH      = "PATH"
	SENSITIVE = "SENSITIVE"
)

type Extracter interface {
	Type() string
	Extract(string) []string
}

func ResigterExtractor(e Extracter) {
	Extractors = append(Extractors, e)
}

//
//type ExtracterResult interface {
//	[]string | string
//}
