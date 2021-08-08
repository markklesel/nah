package custom

import (
	"fmt"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"
)

func checkTags(block block.Block, spec *MatchSpec, ctx *hclcontext.Context) CustomResultState {
	expectedTag := fmt.Sprintf("%v", spec.MatchValue)

	if block.HasChild("tags") {
		tagsBlock := block.GetAttribute("tags")
		if tagsBlock.Contains(expectedTag) {
			return CustomResultSuccess
		}
	}

	var alias string
	if block.HasChild("provider") {
		aliasRef, err := block.GetAttribute("provider").Reference()
		if err == nil {
			alias = aliasRef.String()
		}
	}

	awsProviders := ctx.GetProviderBlocksByProvider("aws", alias)
	for _, providerBlock := range awsProviders {
		if providerBlock.HasChild("default_tags") {
			defaultTags := providerBlock.GetBlock("default_tags")
			if defaultTags.HasChild("tags") {
				tags := defaultTags.GetAttribute("tags")
				if tags.Contains(expectedTag) {
					return CustomResultSuccess
				}
			}
		}
	}
	return CustomResultFailure
}

func ofType(block block.Block, spec *MatchSpec) CustomResultState {
	switch value := spec.MatchValue.(type) {
	case []interface{}:
		for _, v := range value {
			if block.TypeLabel() == v {
				return CustomResultSuccess
			}
		}
	}

	return CustomResultFailure
}
