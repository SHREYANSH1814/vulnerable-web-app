provider "aws" {
  region     = "us-west-2"
  access_key = "AKIAIOSFODNN7EXAMPLE4"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY4"
}

resource "aws_s3_bucket" "app_bucket" {
  bucket = "vulnerable-app-storage"
  acl    = "public-read"  # Insecure ACL setting
}

resource "aws_db_instance" "app_database" {
  allocated_storage    = 20
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t2.micro"
  name                 = "vulnerable_app_db"
  username             = "admin"
  password             = "insecure_database_password_123"  # Hardcoded password
  parameter_group_name = "default.mysql5.7"
  publicly_accessible  = true  # Insecure setting
  skip_final_snapshot  = true
}

resource "aws_iam_access_key" "deploy_user_key" {
  user = aws_iam_user.deploy_user.name
}

resource "aws_iam_user" "deploy_user" {
  name = "deploy-user"
}

resource "aws_iam_user_policy" "deploy_policy" {
  name = "deploy-policy"
  user = aws_iam_user.deploy_user.name

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
EOF
}

# Hardcoded SSH key for EC2 instances
resource "aws_key_pair" "app_key" {
  key_name   = "app-key"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCxz5BgESV9BDjwSGWxCI7WUGZTrjEcNJZgzm1qpXFsj8jA2IzKjjFLFl2+i2kZ4GpfhPWyYOQIKSh8Q4bO4Jh4hQ7m3zz3YHHZeQOOQhZXYMCJq5XwJ4MFwZ6yw0FXX4JQT7qzWuHZ8KeEPUJiJQZcW5nnNUTvuDPWnGKPYS7cEg9xTmM+MeoXYoQ5tpDOQAZ13nUGPBJ8UhAEjkHIVphV6LFGfJgD7GxGxCQzI7NG3NkcUQaQQXmdRp+M5PkWVj3MiOUDJSNK6LQ5XbLOZpYifZWZ4YXRhHgYtZwBGBqlebS6lKzJlLQjCBYcXLUlAMq8RQQmTHXCXxGBhR8QJvTV"
}

# Output sensitive information (bad practice)
output "db_password" {
  value = aws_db_instance.app_database.password
}

output "access_key" {
  value = aws_iam_access_key.deploy_user_key.id
}

output "secret_key" {
  value = aws_iam_access_key.deploy_user_key.secret
}
