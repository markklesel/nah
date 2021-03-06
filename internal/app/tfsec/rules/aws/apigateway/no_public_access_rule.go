package apigateway

// ATTENTION!
// This rule was autogenerated!
// Before making changes, consider updating the generator.

import (
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		Provider:  provider.AWSProvider,
		Service:   "api-gateway",
		ShortCode: "no-public-access",
		Documentation: rule.RuleDocumentation{
			Summary:     "No public access to API Gateway methods",
			Explanation: `API Gateway methods should be protected by authorization or api key. OPTION verb calls can be used without authorization`,
			Impact:      "API gateway methods can be unauthorized accessed",
			Resolution:  "Use and authorization method or require API Key",
			BadExample: []string{`
resource "aws_api_gateway_method" "bad_example" {
  rest_api_id   = aws_api_gateway_rest_api.MyDemoAPI.id
  resource_id   = aws_api_gateway_resource.MyDemoResource.id
  http_method   = "GET"
  authorization = "NONE"
}
`},
			GoodExample: []string{`
resource "aws_api_gateway_method" "good_example" {
  rest_api_id   = aws_api_gateway_rest_api.MyDemoAPI.id
  resource_id   = aws_api_gateway_resource.MyDemoResource.id
  http_method   = "GET"
  authorization = "AWS_IAM"
}
`,
				`
resource "aws_api_gateway_method" "good_example" {
  rest_api_id      = aws_api_gateway_rest_api.MyDemoAPI.id
  resource_id      = aws_api_gateway_resource.MyDemoResource.id
  http_method      = "GET"
  authorization    = "NONE"
  api_key_required = true
}
`,
				`
resource "aws_api_gateway_method" "good_example" {
  rest_api_id   = aws_api_gateway_rest_api.MyDemoAPI.id
  resource_id   = aws_api_gateway_resource.MyDemoResource.id
  http_method   = "OPTION"
  authorization = "NONE"
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_method#authorization",
			},
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"aws_api_gateway_method",
		},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, resourceBlock block.Block, module block.Module) {
			if authorizationAttr := resourceBlock.GetAttribute("authorization"); authorizationAttr.IsNotNil() && authorizationAttr.Equals("NONE") {
				if verbAttr := resourceBlock.GetAttribute("http_method"); verbAttr.IsNotNil() && verbAttr.Equals("OPTION", block.IgnoreCase) {
					return
				}
				if keyReqAttr := resourceBlock.GetAttribute("api_key_required"); keyReqAttr.IsNotNil() && keyReqAttr.IsTrue() {
					return
				}

				set.AddResult().
					WithDescription("Resource '%s' has authorization set to NONE", resourceBlock.FullName()).
					WithAttribute(authorizationAttr)
			}
		},
	})
}
