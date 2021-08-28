resource "aws_s3_bucket" "bucket" {

  tags = merge(
    var.tags, { "Name" = "foo" }
  )
}


variable "tags" {
  type = map(any)
  default = {
    repo2 = "https://github.com/foo"
  }
}
