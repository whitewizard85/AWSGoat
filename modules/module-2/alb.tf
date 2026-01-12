############################
# Application Load Balancer
############################

resource "aws_lb" "app_alb" {
  name               = "app-alb-${var.module_name}"
  load_balancer_type = "application"
  internal           = false

  security_groups = [aws_security_group.alb_sg.id]

  subnets = [
    aws_subnet.public_a.id,
    aws_subnet.public_b.id
  ]

  tags = {
    Name = "app-alb-${var.module_name}"
  }
}

############################
# Security Group for ALB
############################

resource "aws_security_group" "alb_sg" {
  name        = "alb-sg-${var.module_name}"
  description = "Security group for ALB"
  vpc_id      = aws_vpc.lab-vpc.id

  ingress {
    description = "HTTP from Internet"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "alb-sg-${var.module_name}"
  }
}

############################
# Target Group
############################

resource "aws_lb_target_group" "app_tg" {
  name     = "app-tg-${var.module_name}"
  port     = 3000
  protocol = "HTTP"
  vpc_id   = aws_vpc.lab-vpc.id

  health_check {
    enabled             = true
    interval            = 30
    path                = "/"
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
    matcher             = "200-399"
  }

  tags = {
    Name = "app-tg-${var.module_name}"
  }
}

############################
# Listener HTTP
############################

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.app_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app_tg.arn
  }
}

############################
# Output
############################

output "alb_dns_name" {
  description = "Public DNS name of the Application Load Balancer"
  value       = aws_lb.app_alb.dns_name
}
