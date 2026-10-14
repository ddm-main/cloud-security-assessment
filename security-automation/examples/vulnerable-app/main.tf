resource "aws_s3_bucket" "data" {
  bucket = "demo-data"
  acl    = "public-read"
}

resource "aws_security_group_rule" "ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_db_instance" "db" {
  publicly_accessible = true
  storage_encrypted   = false
}
