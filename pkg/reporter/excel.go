package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"

	"github.com/xuri/excelize/v2"
)

type ExcelReportType int

const (
	ExcelReportDirscan ExcelReportType = iota
	ExcelReportFingerprint
	ExcelReportDirscanAndFingerprint
)

// GenerateExcelReport 生成 Excel 报告
func GenerateExcelReport(filterResult *interfaces.FilterResult, reportType ExcelReportType, outputPath string) (string, error) {
	if filterResult == nil {
		return "", fmt.Errorf("过滤结果为空")
	}

	logger.Debugf("开始生成 Excel 报告: %s", outputPath)
	logger.Debugf("ValidPages: %d, PrimaryFilteredPages: %d, StatusFilteredPages: %d",
		len(filterResult.ValidPages), len(filterResult.PrimaryFilteredPages), len(filterResult.StatusFilteredPages))

	file := excelize.NewFile()
	headers := excelHeaders(reportType)

	// Sheet 1: Filtered Results (默认 Sheet1 重命名)
	sheet1Name := "Filtered Results"
	if err := file.SetSheetName("Sheet1", sheet1Name); err != nil {
		// 如果找不到 Sheet1，则创建新 Sheet
		file.NewSheet(sheet1Name)
	}

	filteredRows := buildExcelRows(filterResult.ValidPages, reportType)
	if err := writeSheet(file, sheet1Name, headers, filteredRows); err != nil {
		return "", fmt.Errorf("写入 Sheet1 失败: %w", err)
	}

	// Sheet 2: All Results (No Filter)
	// 合并 ValidPages, PrimaryFilteredPages, StatusFilteredPages
	var allPages []interfaces.HTTPResponse
	allPages = append(allPages, filterResult.ValidPages...)
	allPages = append(allPages, filterResult.PrimaryFilteredPages...)
	allPages = append(allPages, filterResult.StatusFilteredPages...)

	sheet2Name := "All Results (No Filter)"
	file.NewSheet(sheet2Name)
	unfilteredRows := buildExcelRows(allPages, reportType)
	if err := writeSheet(file, sheet2Name, headers, unfilteredRows); err != nil {
		return "", fmt.Errorf("写入 Sheet2 失败: %w", err)
	}

	// 设置默认激活的 Sheet 为第一个
	index, _ := file.GetSheetIndex(sheet1Name)
	file.SetActiveSheet(index)

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return "", fmt.Errorf("创建输出目录失败: %w", err)
	}

	if err := file.SaveAs(outputPath); err != nil {
		return "", fmt.Errorf("保存 Excel 报告失败: %w", err)
	}

	return outputPath, nil
}

// writeSheet 将数据写入指定的 Excel Sheet
func writeSheet(file *excelize.File, sheetName string, headers []string, rows [][]interface{}) error {
	// 定义样式
	headerStyle, _ := file.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Color: "FFFFFF", Size: 12},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"4F81BD"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
	})

	contentStyle, _ := file.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{Vertical: "center", WrapText: true},
	})

	// 设置列宽
	file.SetColWidth(sheetName, "A", "A", 40) // URL
	file.SetColWidth(sheetName, "B", "B", 15) // Status/Title
	file.SetColWidth(sheetName, "C", "C", 25) // Title/Fingerprint
	file.SetColWidth(sheetName, "D", "D", 15) // Content-Length
	file.SetColWidth(sheetName, "E", "E", 20) // Content-Type
	file.SetColWidth(sheetName, "F", "F", 30) // Fingerprint Name
	file.SetColWidth(sheetName, "G", "G", 40) // Rule

	// 写入表头
	for idx, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(idx+1, 1)
		file.SetCellValue(sheetName, cell, header)
	}
	// 应用表头样式
	headerRange, _ := excelize.CoordinatesToCellName(len(headers), 1)
	file.SetCellStyle(sheetName, "A1", headerRange, headerStyle)

	// 写入数据
	for rowIdx, row := range rows {
		// 行号从2开始
		currentLine := rowIdx + 2

		for colIdx, cellValue := range row {
			cell, _ := excelize.CoordinatesToCellName(colIdx+1, currentLine)
			file.SetCellValue(sheetName, cell, cellValue)
		}

		// 应用内容样式
		rowRangeStart, _ := excelize.CoordinatesToCellName(1, currentLine)
		rowRangeEnd, _ := excelize.CoordinatesToCellName(len(headers), currentLine)
		file.SetCellStyle(sheetName, rowRangeStart, rowRangeEnd, contentStyle)
	}

	return nil
}

func excelHeaders(reportType ExcelReportType) []string {
	switch reportType {
	case ExcelReportDirscanAndFingerprint:
		return []string{"URL", "状态码", "标题", "Content-length", "Content-type", "指纹名称", "指纹规则"}
	case ExcelReportFingerprint:
		return []string{"URL", "状态码", "标题", "指纹名称", "指纹规则"}
	case ExcelReportDirscan:
		fallthrough
	default:
		return []string{"URL", "状态码", "标题", "Content-length", "Content-type", "指纹名称", "指纹规则"}
	}
}

func buildExcelRows(pages []interfaces.HTTPResponse, reportType ExcelReportType) [][]interface{} {
	rows := make([][]interface{}, 0)
	for _, page := range pages {
		// 每次只为每个页面生成一行，不再拆分指纹到多行
		rows = append(rows, buildExcelRow(page, reportType))
	}

	if len(rows) == 0 {
		// 没有有效页面时提供空报告主体
		rows = append(rows, buildExcelRow(interfaces.HTTPResponse{}, reportType))
	}

	return rows
}

func buildExcelRow(page interfaces.HTTPResponse, reportType ExcelReportType) []interface{} {
	var row []interface{}

	// 收集指纹信息
	var fpNames []string
	var fpRules []string

	for _, match := range page.Fingerprints {
		if match.RuleName != "" {
			fpNames = append(fpNames, match.RuleName)
		}
		if match.Matcher != "" {
			fpRules = append(fpRules, match.Matcher)
		} else if match.DSLMatched != "" {
			// 兼容 DSLMatched 字段
			fpRules = append(fpRules, match.DSLMatched)
		}
	}

	// 合并字符串，使用逗号分隔名称，换行分隔规则和内容以保持清晰
	namesStr := strings.Join(fpNames, ", ")
	rulesStr := strings.Join(fpRules, "\n")

	switch reportType {
	case ExcelReportDirscanAndFingerprint:
		row = append(row,
			page.URL,
			page.StatusCode,
			page.Title,
			page.ContentLength,
			page.ContentType,
			namesStr,
			rulesStr,
		)
	case ExcelReportFingerprint:
		row = append(row,
			page.URL,
			page.StatusCode,
			page.Title,
			namesStr,
			rulesStr,
		)
	case ExcelReportDirscan:
		fallthrough
	default:
		row = append(row,
			page.URL,
			page.StatusCode,
			page.Title,
			page.ContentLength,
			page.ContentType,
			namesStr,
			rulesStr,
		)
	}

	return row
}

// sanitizeSnippet (已移除使用，保留函数或删除均可，建议删除以保持整洁)
// GeneratePortscanExcel 生成端口扫描 Excel 报告
// 输出列：IP, Port
// 端口扫描模块已移除，Excel 报告不再包含端口结果
