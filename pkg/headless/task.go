package headless

type Task struct {
	URL       string
	BaseURI   string
	BaseToken string

	// IndexURL index url when first visit, this field will be used for determining Broken Access
	IndexURL string
	// Subs detected urls from the target vue/javascript resource
	Subs []string
}

func NewTask(URL string) *Task {
	return &Task{
		URL:  URL,
		Subs: make([]string, 0, 30),
	}
}
