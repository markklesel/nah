package main

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"io/ioutil"
	"os"
	"sort"
	"strings"

	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

type reference struct {
	Title string `json:"title"`
	Url   string `json:"url"`
}

type custom struct {
	Severity     string              `json:"severity"`
	Impact       string              `json:"possibleImpact"`
	References   []reference            `json:"references"`
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

type fileContent struct {
	Provider string
	Checks   []rule.Rule
}

var providers map[string]string = map[string]string{
	"AWS":          "AWS",
	"AZURE":        "AZU",
	"CLOUDSTACK":   "CSK",
	"DIGITALOCEAN": "DIG",
	"GENERAL":      "GEN",
	"GITHUB":       "GIT",
	"GOOGLE":       "GCP",
	"KUBERNETES":   "K8S",
	"OPENSTACK":    "OSK",
	"ORACLE":       "OCI",
}

func newMetadata(id string, r rule.Rule) metadata {

	m := metadata{
		Id:          id,
		ApiVersion:  2,
		Version:     1,
		Title:       r.Documentation.Summary,
		Description: strings.TrimSpace(r.Documentation.Explanation),
		Custom: custom{
			Severity:   string(r.DefaultSeverity),
			Impact:     r.Documentation.Impact,
			Apis:       []string{},
			ExternalRefs: map[string][]string{
				"cfsec": []string{},
				"cspm":  []string{},
				"tfsec": []string{r.ID()},
			},
		},
	}

	for _, link := range r.Documentation.Links {
		if strings.Contains(link, "terraform") {
			continue
		}
		m.Custom.References = append(m.Custom.References, reference{Title: "title", Url: link})
	}


	if strings.ToUpper(string(r.Provider)) == "AWS" {
		m.Custom.ExternalRefs["cfsec"] = append(m.Custom.ExternalRefs["cfsec"], r.ID())
	}
	return m
}

func main() {

	providersIndex := make(map[string]map[string]string)

	for _, c := range getSortedfileContents() {

		providerIndex := make(map[string]string)

		for i, r := range c.Checks {

			provider := providers[strings.ToUpper(c.Provider)]
			id := fmt.Sprintf("AVD-%s-%04d", provider, i+1)

			fmt.Printf("Writing file for %s\n", id)
			path := fmt.Sprintf("%s/%s/%s/", c.Provider, r.Service, r.ShortCode)
			providerIndex[id] = fmt.Sprintf("%smetadata.json", path)
			if err := os.MkdirAll(path, 0777); err != nil {
				panic(err)
			}

			metadata := newMetadata(id, r)

			body, err := json.MarshalIndent(metadata, "", "  ")
			if err != nil {
				panic(err)
			}

			ioutil.WriteFile(fmt.Sprintf("../cloud-metadata/%s/metadata.json", path), body, 0777)
		}

		body, err := json.MarshalIndent(providerIndex, "", "  ")
		if err != nil {
			panic(err)
		}
		ioutil.WriteFile(fmt.Sprintf("../cloud-metadata/%s/index.json", c.Provider), body, 0777)
		providersIndex[c.Provider] = providerIndex
	}
	body, err := json.MarshalIndent(providersIndex, "", "  ")
	if err != nil {
		panic(err)
	}
	ioutil.WriteFile("../cloud-metadata/index.json", body, 0777)

}

func getSortedfileContents() []*fileContent {
	rules := scanner.GetRegisteredRules()

	checkMap := make(map[string][]rule.Rule)

	for _, r := range rules {
		provider := string(r.Provider)
		checkMap[provider] = append(checkMap[provider], r)
	}

	var fileContents []*fileContent
	for provider := range checkMap {
		checks := checkMap[provider]
		sortChecks(checks)
		fileContents = append(fileContents, &fileContent{
			Provider: provider,
			Checks:   checks,
		})
	}
	return fileContents
}

func sortChecks(checks []rule.Rule) {
	sort.Slice(checks, func(i, j int) bool {
		return checks[i].ID() < checks[j].ID()
	})
}
