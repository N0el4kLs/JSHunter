package types

// Task is the struct to store the target url resources
type Task struct {
	// URL task of which target url
	URL string

	// IndexURL index url when first visit, this field will be used for determining Broken Access
	IndexURL string
	// Subs detected urls from the target vue/javascript resource
	Subs []string
}

// NewTask is the constructor of Task
func NewTask(URL string) *Task {
	return &Task{
		URL:  URL,
		Subs: make([]string, 0, 30),
	}
}

// CheckItem struct to store the target url information
type CheckItem struct {
	// URL inputted target url
	URL string

	// FirstVisitURL first visit url, this field will be used to check the broken access.
	// for example:
	// when visited target: http://example.com
	// the first visit url is http://example.com/index.html
	FirstVisitURL string
}

// VueRouterItem struct to store the vue router url information
type VueRouterItem struct {
	// vue router url
	URL string

	// IndexURL actual href of the vue router url, this field will be used to check the broken access.
	// for example:
	// when visit router: http://example.com/#/home
	// there is a redirect to http://example.com/#/login, so the index url is http://example.com/#/login
	IndexURL string

	// BaseURL base url of the vue router url without any frag or query
	Base string

	// Token tokenized url
	Token string

	// where the vue router url comes from
	ParentURL CheckItem
}
