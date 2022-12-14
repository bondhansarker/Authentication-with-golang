package paginations

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"auth/config"
	serializers "auth/types"
	"auth/utils/methods"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

func GeneratePaginationRequest(c *echo.Context) *serializers.Pagination {
	// default limit, page & sort parameter
	limit := config.App().Limit
	page := config.App().Page
	sort := config.App().Sort
	searchString := ""

	var searches []serializers.Search

	query := (*c).QueryParams()
	for key, value := range query {
		queryValue := value[len(value)-1]

		switch key {
		case "limit":
			limit, _ = strconv.ParseInt(queryValue, 10, 64)
		case "page":
			page, _ = strconv.ParseInt(queryValue, 10, 64)
		case "sort":
			sort = queryValue
		case "search":
			searchString = queryValue
		}

		// check if query parameter key contains dot
		if strings.Contains(key, ".") {
			// split query parameter key by dot
			searchKeys := strings.Split(key, ".")

			// create search object
			search := serializers.Search{Column: searchKeys[0], Action: searchKeys[1], Query: queryValue}

			// add search object to searches array
			searches = append(searches, search)
		}
	}

	return &serializers.Pagination{Limit: limit, Page: page, Sort: sort, QueryString: searchString, Searches: searches}
}

func GeneratePagesPath(c echo.Context, resp *serializers.Pagination) {
	// search query params
	searchQueryParams := ""
	totalPages := resp.TotalPages
	for _, search := range resp.Searches {
		searchQueryParams += fmt.Sprintf("&%s.%s=%s", search.Column, search.Action, search.Query)
	}

	// set first & last page paginations response
	resp.FirstPage = fmt.Sprintf("?limit=%d&page=%d&sort=%s", resp.Limit, 1, resp.Sort) + searchQueryParams
	resp.LastPage = fmt.Sprintf("?limit=%d&page=%d&sort=%s", resp.Limit, totalPages, resp.Sort) + searchQueryParams

	if resp.Page > 1 {
		// set previous page paginations response
		resp.PreviousPage = fmt.Sprintf("?limit=%d&page=%d&sort=%s", resp.Limit, resp.Page-1, resp.Sort) + searchQueryParams
	}

	if resp.Page < totalPages {
		// set next page paginations response
		resp.NextPage = fmt.Sprintf("?limit=%d&page=%d&sort=%s", resp.Limit, resp.Page+1, resp.Sort) + searchQueryParams
	}

	if resp.Page > totalPages {
		// reset previous page
		resp.PreviousPage = ""
	}

	urlPath := c.Request().URL.Path

	resp.FirstPage = fmt.Sprintf("%s/%s", urlPath, resp.FirstPage)
	resp.LastPage = fmt.Sprintf("%s/%s", urlPath, resp.LastPage)
	resp.NextPage = fmt.Sprintf("%s/%s", urlPath, resp.NextPage)
	resp.PreviousPage = fmt.Sprintf("%s/%s", urlPath, resp.PreviousPage)
}
func CalculateTotalPageAndRows(pagination *serializers.Pagination, totalRows int64) int64 {
	var totalPages, fromRow, toRow int64 = 0, 0, 0

	// calculate total pages
	totalPages = int64(math.Ceil(float64(totalRows) / float64(pagination.Limit)))

	if pagination.Page == 1 {
		// set from & to row on first page
		fromRow = 1
		toRow = pagination.Limit
	} else {
		if pagination.Page <= totalPages {
			// calculate from & to row
			fromRow = (pagination.Page-1)*pagination.Limit + 1
			toRow = fromRow + pagination.Limit - 1
		}
	}

	if toRow > totalRows {
		// set to row with total rows
		toRow = totalRows
	}

	pagination.FromRow = fromRow
	pagination.ToRow = toRow

	return totalPages
}

func GenerateFilteringCondition(dbClient *gorm.DB, tableName string, pagination *serializers.Pagination, DoCount bool) *gorm.DB {
	offset := (pagination.Page - 1) * pagination.Limit
	var dbQuery *gorm.DB
	if DoCount {
		dbQuery = dbClient
	} else {
		dbQuery = dbClient.Limit(int(pagination.Limit)).Offset(int(offset)).Order(pagination.Sort)
	}

	queryString := pagination.QueryString
	if queryString != "" {
		queryString = "%" + queryString + "%"
		for _, field := range pagination.QueryTargetFields {
			searchQuery := fmt.Sprintf("%s LIKE ?", field)
			dbQuery = dbQuery.Or(searchQuery, queryString)
		}
	}

	// generate where query
	searches := pagination.Searches

	if searches != nil {
		for _, value := range searches {
			var column string
			column = value.Column
			if !methods.IsEmpty(tableName) {
				column = tableName + "." + value.Column
			}
			action := value.Action
			query := value.Query

			switch action {
			case "equals":
				whereQuery := fmt.Sprintf("%s = ?", column)
				dbQuery = dbQuery.Where(whereQuery, query)
			case "contains":
				whereQuery := fmt.Sprintf("%s LIKE ?", column)
				dbQuery = dbQuery.Where(whereQuery, "%"+query+"%")
			case "in":
				whereQuery := fmt.Sprintf("%s IN (?)", column)
				queryArray := strings.Split(query, ",")
				dbQuery = dbQuery.Where(whereQuery, queryArray)
			case "gt":
				whereQuery := fmt.Sprintf("%s > (?)", column)
				queryArray := query
				dbQuery = dbQuery.Where(whereQuery, queryArray)
			case "gte":
				whereQuery := fmt.Sprintf("%s >= (?)", column)
				queryArray := query
				dbQuery = dbQuery.Where(whereQuery, queryArray)
			case "lt":
				whereQuery := fmt.Sprintf("%s < (?)", column)
				queryArray := query
				dbQuery = dbQuery.Where(whereQuery, queryArray)
			case "lte":
				whereQuery := fmt.Sprintf("%s <= (?)", column)
				queryArray := query
				dbQuery = dbQuery.Where(whereQuery, queryArray)
			}
		}
	}

	return dbQuery
}
