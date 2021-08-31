module "example" {
  source = "./moduleWithIssues"
  tags   = var.tags 
}

module "example-with-default-vars" {
  source = "./moduleWithIssues"
}

variable "tags" {
  type = map(any)
  default = {
    repo  = "https://github.com/foo"
  }
}
