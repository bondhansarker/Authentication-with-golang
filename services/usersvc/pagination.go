package usersvc

import (
	"fmt"
	"math"
	"strings"

	serializers "auth/types"
	"auth/utils/methodutil"
	"gorm.io/gorm"
)

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

func GenerateFilteringCondition(r *gorm.DB, tableName string, pagination *serializers.Pagination, isCount bool) *gorm.DB {
	offset := (pagination.Page - 1) * pagination.Limit
	var sort string

	sort = pagination.Sort

	if !methodutil.IsEmpty(tableName) {
		sort = tableName + "." + pagination.Sort
	}
	var find *gorm.DB

	if !isCount {
		// get data with limit, offset & order
		find = r.Limit(int(pagination.Limit)).Offset(int(offset)).Order(sort)
	} else {
		find = r
	}

	queryString := pagination.QueryString
	if queryString != "" {
		queryString = "%" + queryString + "%"
		for _, field := range pagination.QueryTargetFields {
			searchQuery := fmt.Sprintf("%s LIKE ?", field)
			find = find.Or(searchQuery, queryString)
		}
	}

	// generate where query
	searches := pagination.Searches

	if searches != nil {
		for _, value := range searches {
			var column string
			column = value.Column
			if !methodutil.IsEmpty(tableName) {
				column = tableName + "." + value.Column
			}
			action := value.Action
			query := value.Query

			switch action {
			case "equals":
				whereQuery := fmt.Sprintf("%s = ?", column)
				find = find.Where(whereQuery, query)
			case "contains":
				whereQuery := fmt.Sprintf("%s LIKE ?", column)
				find = find.Where(whereQuery, "%"+query+"%")
			case "in":
				whereQuery := fmt.Sprintf("%s IN (?)", column)
				queryArray := strings.Split(query, ",")
				find = find.Where(whereQuery, queryArray)
			case "gt":
				whereQuery := fmt.Sprintf("%s > (?)", column)
				queryArray := query
				find = find.Where(whereQuery, queryArray)
			case "gte":
				whereQuery := fmt.Sprintf("%s >= (?)", column)
				queryArray := query
				find = find.Where(whereQuery, queryArray)
			case "lt":
				whereQuery := fmt.Sprintf("%s < (?)", column)
				queryArray := query
				find = find.Where(whereQuery, queryArray)
			case "lte":
				whereQuery := fmt.Sprintf("%s <= (?)", column)
				queryArray := query
				find = find.Where(whereQuery, queryArray)
			}
		}
	}

	return find
}
