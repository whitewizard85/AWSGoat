
variable "module_name" {
  type        = string
  description = "Nome del modulo passato da GitHub Actions"
}
variable "AWS_REGION" {
  type    = string
  default = "us-east-1"
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.27"
    }
  }
}

provider "aws" {
  region = var.AWS_REGION
}

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

# ------------------------------------------------------------
# 2. Network Configuration (VPC, Subnets, IGW)
# ------------------------------------------------------------
resource "aws_vpc" "lab-vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "AWS_GOAT_VPC"
  }
}

# Renamed to match your LB references (public_1 and public_2)
resource "aws_subnet" "public_1" {
  vpc_id                  = aws_vpc.lab-vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = data.aws_availability_zones.available.names[0]
  tags = { Name = "aws-goat-public-1" }
}

resource "aws_subnet" "public_2" {
  vpc_id                  = aws_vpc.lab-vpc.id
  cidr_block              = "10.0.2.0/24"
  map_public_ip_on_launch = true
  availability_zone       = data.aws_availability_zones.available.names[1]
  tags = { Name = "aws-goat-public-2" }
}

resource "aws_internet_gateway" "my_vpc_igw" {
  vpc_id = aws_vpc.lab-vpc.id
  tags   = { Name = "AWS_GOAT_IGW" }
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.lab-vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.my_vpc_igw.id
  }
}

resource "aws_route_table_association" "a" {
  subnet_id      = aws_subnet.public_1.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "b" {
  subnet_id      = aws_subnet.public_2.id
  route_table_id = aws_route_table.public_rt.id
}

# ------------------------------------------------------------
# 3. Security Groups
# ------------------------------------------------------------

# Renamed to 'alb_sg' to match your LB reference
resource "aws_security_group" "alb_sg" {
  name        = "Load-Balancer-SG-${var.module_name}"
  description = "SG for load balancer"
  vpc_id      = aws_vpc.lab-vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "ecs_sg" {
  name        = "ECS-SG-${var.module_name}"
  vpc_id      = aws_vpc.lab-vpc.id

  ingress {
    from_port       = 0
    to_port         = 65535
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ------------------------------------------------------------
# 4. Database (RDS)
# ------------------------------------------------------------
resource "aws_db_subnet_group" "database-subnet-group" {
  name        = "database-subnets-${var.module_name}"
  subnet_ids  = [aws_subnet.public_1.id, aws_subnet.public_2.id]
  description = "Subnets for Database Instance"
}

resource "aws_security_group" "database-security-group" {
  name   = "Database-SG-${var.module_name}"
  vpc_id = aws_vpc.lab-vpc.id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_sg.id]
  }
}

resource "aws_db_instance" "database-instance" {
  identifier             = "aws-goat-db-${var.module_name}"
  allocated_storage      = 10
  instance_class         = "db.t3.micro"
  engine                 = "mysql"
  engine_version         = "8.0"
  username               = "root"
  password               = "T2kVB3zgeN3YbrKS"
  parameter_group_name   = "default.mysql8.0"
  skip_final_snapshot    = true
  db_subnet_group_name   = aws_db_subnet_group.database-subnet-group.name
  vpc_security_group_ids = [aws_security_group.database-security-group.id]
}

# ------------------------------------------------------------
# 5. Load Balancer
# ------------------------------------------------------------
resource "aws_lb" "application_load_balancer" {
  name               = "aws-goat-alb-${var.module_name}"
  internal           = false
  load_balancer_type = "application"
  subnets            = [aws_subnet.public_1.id, aws_subnet.public_2.id]
  security_groups    = [aws_security_group.alb_sg.id]
}

# ------------------------------------------------------------
# 6. IAM & Secrets
# ------------------------------------------------------------
resource "aws_iam_policy" "instance_boundary_policy" {
  name = "aws-goat-boundary-${var.module_name}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["iam:*", "ec2:*", "s3:*", "ssm:*"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role" "ecs-instance-role" {
  name                 = "ecs-instance-role-${var.module_name}"
  permissions_boundary = aws_iam_policy.instance_boundary_policy.arn
  assume_role_policy = jsonencode({
    Version = "2008-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_secretsmanager_secret" "rds_creds" {
  name                    = "RDS_CREDS_${var.module_name}"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "secret_version" {
  secret_id     = aws_secretsmanager_secret.rds_creds.id
  secret_string = jsonencode({ username = "root", password = "T2kVB3zgeN3YbrKS" })
}

# ------------------------------------------------------------
# 7. Outputs
# ------------------------------------------------------------
output "ad_Target_URL" {
  value = "${aws_lb.application_load_balancer.dns_name}/login.php"
}
