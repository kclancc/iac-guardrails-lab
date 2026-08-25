# Intentionally misconfigured security group.
# Contains high-severity findings by design (0.0.0.0/0 on admin ports,
# LDAP over UDP/636). Do NOT apply to a real account.

resource "aws_security_group" "attack_path" {
  name        = "attack-path-sg"
  description = "Sandbox SG with intentional findings."
  vpc_id      = aws_vpc.lab.id

  # HTTPS from anywhere — legitimate.
  ingress {
    description = "HTTPS from Internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # SSH open to the world — high-severity finding.
  ingress {
    description = "SSH management"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # RDP open to the world — high-severity finding.
  ingress {
    description = "RDP management"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # LDAP SSL over UDP/636 — matches the sample finding used in the demo script.
  # Line 52 is the from_port below; keep the layout stable so the finding lands
  # on a predictable line for screenshots.
  ingress {
    description = "LDAP SSL (misconfigured — should be TCP)"
    from_port   = 636
    to_port     = 636
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "attack-path-sg"
  }
}
