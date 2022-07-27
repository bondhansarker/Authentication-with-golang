package types

type Pagination struct {
	Limit             int64       `json:"limit"`
	Page              int64       `json:"page"`
	Sort              string      `json:"sort"`
	TotalRows         int64       `json:"total_rows"`
	TotalPages        int64       `json:"total_pages"`
	FirstPage         string      `json:"first_page"`
	PreviousPage      string      `json:"previous_page"`
	NextPage          string      `json:"next_page"`
	LastPage          string      `json:"last_page"`
	FromRow           int64       `json:"from_row"`
	ToRow             int64       `json:"to_row"`
	Rows              interface{} `json:"rows"`
	QueryString       string      `json:"search"`
	QueryTargetFields []string    `json:"target"`
	Searches          []Search    `json:"searches"`
}

type PaginationResp struct {
	Limit       int64       `json:"limit"`
	Page        int64       `json:"page"`
	TotalRows   int64       `json:"total_rows"`
	TotalPages  int64       `json:"total_pages"`
	FromRow     int64       `json:"from_row"`
	ToRow       int64       `json:"to_row"`
	Rows        interface{} `json:"rows"`
	QueryString string      `json:"search"`
	// Searches    []Search    `json:"searches"`
}

type Search struct {
	Column string `json:"column,omitempty"`
	Action string `json:"action,omitempty"`
	Query  string `json:"query"`
}
