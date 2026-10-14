resource "aws_s3_bucket" "data" {
  bucket = "demo-data"
}

resource "aws_db_instance" "db" {
  publicly_accessible             = false
  storage_encrypted               = true
  deletion_protection             = true
  enabled_cloudwatch_logs_exports = ["postgresql"]
  performance_insights_enabled    = true
}
