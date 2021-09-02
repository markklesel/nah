package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/aquasecurity/tfsec/pkg/rule"

	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

type custom struct {
	Severity     string              `json:"severity"`
	Impact       string              `json:"possibleImpact"`
	Urls         []string            `json:"urls"`
	Apis         []string            `json:"apis"`
	ExternalRefs map[string][]string `json:"refs"`
}

type metadata struct {
	Id          string `json:"id"`
	ApiVersion  int    `json:"apiVersion"`
	Version     int    `json:"version"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Custom      custom `json:"custom"`
}

func newMetadata(r rule.Rule) metadata {

	return metadata{
		Id:          "AQUA_ID_GOES_HERE",
		ApiVersion:  2,
		Version:     1,
		Title:       r.Documentation.Summary,
		Description: strings.TrimSpace(r.Documentation.Explanation),
		Custom: custom{
			Severity: string(r.DefaultSeverity),
			Impact:   r.Documentation.Impact,
			Urls:     r.Documentation.Links,
			Apis:     []string{},
			ExternalRefs: map[string][]string{
				"tfsec": []string{r.ID()},
				"cspm":  []string{},
				"cfsec": []string{},
			},
		},
	}

}

func main() {

	for _, rule := range scanner.GetRegisteredRules() {

		path := fmt.Sprintf("../cloud-metadata/%s/%s/%s/", rule.Provider, rule.Service, rule.ShortCode)

		if err := os.MkdirAll(path, 0777); err != nil {
			panic(err)
		}

		metadata := newMetadata(rule)

		body, err := json.MarshalIndent(metadata, "", "  ")
		if err != nil {
			panic(err)
		}

		ioutil.WriteFile(fmt.Sprintf("%s/metadata.json", path), body, 0777)

	}

}
