package report

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"

	"github.com/Timatoot/telltale/internal/model"
)

//go:embed templates/report.html.tmpl
var htmlSource string

var htmlReport = template.Must(template.New("report").Funcs(template.FuncMap{
	"warnings": coverageWarnings,
	"status":   analysisStatus,
}).Parse(htmlSource))

func RenderHTML(input *model.ScanReport, canary string) ([]byte, error) {
	p := presentation{canary: canary, singleLine: true}
	r, err := p.report(input)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := htmlReport.Execute(&out, r); err != nil {
		return nil, fmt.Errorf("render HTML: %w", err)
	}
	return guardedOutput(out.Bytes(), canary, template.HTMLEscapeString(canary))
}
