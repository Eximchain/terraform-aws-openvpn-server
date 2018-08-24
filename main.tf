# ---------------------------------------------------------------------------------------------------------------------
# PROVIDERS
# ---------------------------------------------------------------------------------------------------------------------
provider "aws" {
  version = "~> 1.5"

  region  = "${var.aws_region}"
}

# ---------------------------------------------------------------------------------------------------------------------
# KEY PAIR
# ---------------------------------------------------------------------------------------------------------------------
resource "aws_key_pair" "admin" {
  key_name_prefix = "openvpn-admin-"
  public_key      = "${var.public_key}"
}

# ---------------------------------------------------------------------------------------------------------------------
# NETWORKING
# ---------------------------------------------------------------------------------------------------------------------
resource "aws_vpc" "openvpn" {
  cidr_block           = "${var.vpc_base_cidr}"
  enable_dns_hostnames = true

  tags {
    Name = "OpenVPN"
  }
}

resource "aws_internet_gateway" "openvpn" {
  vpc_id = "${aws_vpc.openvpn.id}"

  tags {
    Name = "OpenVPN"
  }
}

resource "aws_route" "openvpn" {
  route_table_id         = "${aws_vpc.openvpn.main_route_table_id}"
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = "${aws_internet_gateway.openvpn.id}"
}

resource "aws_subnet" "openvpn" {
  vpc_id                  = "${aws_vpc.openvpn.id}"
  cidr_block              = "${var.vpc_base_cidr}"
  map_public_ip_on_launch = true

  tags {
    Name = "OpenVPN"
  }
}


# ---------------------------------------------------------------------------------------------------------------------
# OPENVPN SERVER
# ---------------------------------------------------------------------------------------------------------------------
resource "aws_instance" "openvpn_server" {
  connection {
    # The default username for our AMI
    user = "openvpnas"

    # The connection will use the local SSH agent for authentication if this is empty.
    private_key = "${var.private_key}"
  }

  ami           = "${var.openvpn_ami}"
  instance_type = "${var.openvpn_instance_type}"

  key_name = "${aws_key_pair.admin.id}"

  subnet_id = "${aws_subnet.openvpn.id}"

  vpc_security_group_ids = ["${aws_security_group.openvpn.id}"]

  disable_api_termination = "${var.enable_termination_protection}"
  tenancy                 = "${var.use_dedicated_instance ? "dedicated" : "default"}"

  tags {
    Name    = "OpenVPN Server: ${var.region_dns_common_name == "" ? var.aws_region : var.region_dns_common_name}"
    Purpose = "OpenVPN"
    Region  = "${var.aws_region}"
  }

  user_data = <<EOF
public_hostname=${aws_route53_record.openvpn.fqdn}
admin_user=${var.openvpn_admin_user}
admin_pw=${var.openvpn_admin_pw}
reroute_gw=${var.openvpn_reroute_gw}
reroute_dns=${var.openvpn_reroute_dns}
EOF

  provisioner "file" {
    source = "assets/exim_logo.png"
    destination = "/tmp/exim_logo.png"
  }

  provisioner "remote-exec" {
    inline = [
      # Disable auto-updates so provisioners don't fail to obtain lock
      "sudo sh -c 'echo \"APT::Periodic::Enable \"0\";\" >> /etc/apt/apt.conf.d/10periodic'",
      # Add Threatstack repository and key
      "curl https://app.threatstack.com/APT-GPG-KEY-THREATSTACK | sudo apt-key add -",
      "echo \"deb https://pkg.threatstack.com/Ubuntu `lsb_release -c | cut -f2` main\" | sudo tee /etc/apt/sources.list.d/threatstack.list > /dev/null",
      # Remove software with vulnerabilities
      "sudo apt-get remove -y tcpdump bzip2 ed cron",
      # Update and install packages
      "sudo apt-get update",
      "yes N | sudo apt-get upgrade -y",
      "sudo apt-get install threatstack-agent -y",
      # Insert our SSL cert
      "echo '${var.cert_public_key}' | sudo tee /usr/local/openvpn_as/etc/web-ssl/server.crt > /dev/null",
      "echo '${var.cert_private_key}' | sudo tee /usr/local/openvpn_as/etc/web-ssl/server.key > /dev/null",
      # Set DNS Servers and traffic routing
      "sudo /usr/local/openvpn_as/scripts/sacli -k vpn.client.routing.reroute_dns -v custom ConfigPut",
      "sudo /usr/local/openvpn_as/scripts/sacli -k vpn.server.dhcp_option.dns.0 -v 8.8.8.8 ConfigPut",
      "sudo /usr/local/openvpn_as/scripts/sacli -k vpn.server.dhcp_option.dns.1 -v 8.8.4.4 ConfigPut",
      "sudo /usr/local/openvpn_as/scripts/sacli -k vpn.server.routing.gateway_access -v true ConfigPut",
      "sudo /usr/local/openvpn_as/scripts/sacli -k vpn.general.osi_layer -v 3 ConfigPut",
      # Set VPN network info
      "sudo /usr/local/openvpn_as/scripts/sacli -k vpn.daemon.0.client.network -v ${element(split("/", var.vpn_cidr), 0)} ConfigPut",
      "sudo /usr/local/openvpn_as/scripts/sacli -k vpn.daemon.0.client.netmask_bits -v ${element(split("/", var.vpn_cidr), 1)} ConfigPut",
      # Enable LDAP authentication via FoxPass
      "sudo /usr/local/openvpn_as/scripts/sacli -k auth.module.type -v ldap ConfigPut",
      "sudo /usr/local/openvpn_as/scripts/sacli -k auth.ldap.0.name -v 'FoxPass LDAP' ConfigPut",
      "sudo /usr/local/openvpn_as/scripts/sacli -k auth.ldap.0.server.0.host -v ldap.foxpass.com ConfigPut",
      "sudo /usr/local/openvpn_as/scripts/sacli -k auth.ldap.0.bind_dn -v cn=${var.openvpn_admin_user},dc=${element(split(".", var.sub_domain), 0)},dc=${element(split(".", var.sub_domain), 1)} ConfigPut",
      "sudo /usr/local/openvpn_as/scripts/sacli -k auth.ldap.0.bind_pw -v ${var.openvpn_admin_pw} ConfigPut",
      "sudo /usr/local/openvpn_as/scripts/sacli -k auth.ldap.0.users_base_dn -v ou=people,dc=${element(split(".", var.sub_domain), 0)},dc=${element(split(".", var.sub_domain), 1)} ConfigPut",
      "sudo /usr/local/openvpn_as/scripts/sacli -k auth.ldap.0.uname_attr -v uid ConfigPut",
      "sudo /usr/local/openvpn_as/scripts/sacli -k auth.ldap.0.use_ssl -v always ConfigPut",
      "sudo /usr/local/openvpn_as/scripts/sacli -k auth.ldap.0.timeout -v ${var.authentication_timeout_seconds} ConfigPut",
      # Add custom logo and name to the config
      "sudo mv /tmp/exim_logo.png /usr/local/openvpn_as/",
      "sudo sed -i 's/sa.company_name=OpenVPN, Inc./sa.company_name=Eximchain Pte. Ltd.\\nsa.logo_image_file=\\/usr\\/local\\/openvpn_as\\/exim_logo.png/' /usr/local/openvpn_as/etc/as.conf",
      # Do a warm restart so the config is picked up
      "sudo /usr/local/openvpn_as/scripts/sacli start",
      "sudo service openvpnas restart",
      # Start Threatstack agent
      "sudo cloudsight setup --deploy-key=${var.threatstack_deploy_key} --ruleset=\"Base Rule Set\" --agent_type=i",
    ]
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# OPENVPN SERVER SECURITY GROUP AND RULES
# ---------------------------------------------------------------------------------------------------------------------
resource "aws_security_group" "openvpn" {
  name_prefix = "openvpn-server-"
  description = "Used for OpenVPN Access Server"
  vpc_id      = "${aws_vpc.openvpn.id}"

  tags {
    Name = "OpenVPN"
  }
}

# Allow SSH Access for server administration
resource "aws_security_group_rule" "openvpn_ssh" {
  security_group_id = "${aws_security_group.openvpn.id}"
  type              = "ingress"

  from_port = 22
  to_port   = 22
  protocol  = "tcp"

  cidr_blocks = ["0.0.0.0/0"]
}

# Allow OpenVPN TCP
resource "aws_security_group_rule" "openvpn_tcp" {
  security_group_id = "${aws_security_group.openvpn.id}"
  type              = "ingress"

  from_port = 443
  to_port   = 443
  protocol  = "tcp"

  cidr_blocks = ["0.0.0.0/0"]
}

# Allow OpenVPN UDP
resource "aws_security_group_rule" "openvpn_udp" {
  security_group_id = "${aws_security_group.openvpn.id}"
  type              = "ingress"

  from_port = 1194
  to_port   = 1194
  protocol  = "udp"

  cidr_blocks = ["0.0.0.0/0"]
}

# Allow OpenVPN Web UI
resource "aws_security_group_rule" "openvpn_web" {
  security_group_id = "${aws_security_group.openvpn.id}"
  type              = "ingress"

  from_port = 943
  to_port   = 943
  protocol  = "tcp"

  cidr_blocks = ["0.0.0.0/0"]
}

# Allow all egress
resource "aws_security_group_rule" "openvpn_egress" {
  security_group_id = "${aws_security_group.openvpn.id}"
  type              = "egress"

  from_port = 0
  to_port   = 0
  protocol  = "-1"

  cidr_blocks = ["0.0.0.0/0"]
}

# ---------------------------------------------------------------------------------------------------------------------
# ELASTIC IP
# ---------------------------------------------------------------------------------------------------------------------
resource "aws_eip" "openvpn" {
  vpc = true

  tags {
    Name = "OpenVPN"
  }
}

resource "aws_eip_association" "openvpn" {
  allocation_id = "${aws_eip.openvpn.id}"
  instance_id   = "${aws_instance.openvpn_server.id}"
}

# ---------------------------------------------------------------------------------------------------------------------
# DNS RECORD
# ---------------------------------------------------------------------------------------------------------------------
data "aws_route53_zone" "domain" {
  name         = "${var.sub_domain}."
}

resource "aws_route53_record" "openvpn" {
  zone_id = "${data.aws_route53_zone.domain.zone_id}"
  name    = "vpn-${var.region_dns_common_name == "" ? var.aws_region : var.region_dns_common_name}.${var.sub_domain}"
  type    = "A"
  ttl     = "300"
  records = ["${aws_eip.openvpn.public_ip}"]
}

# ---------------------------------------------------------------------------------------------------------------------
# CLOUDWATCH ALARMS
# ---------------------------------------------------------------------------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "health_check_failed" {
  alarm_name           = "${aws_sns_topic.health_check_failed.name}"
  comparison_operator  = "GreaterThanOrEqualToThreshold"
  evaluation_periods   = "1"
  metric_name          = "StatusCheckFailed"
  namespace            = "AWS/EC2"
  period               = "60"
  statistic            = "Sum"
  threshold            = "1"
  treat_missing_data   = "notBreaching"
  alarm_description    = "This alarm alerts us when the VPN server in ${var.aws_region} fails health checks"

  alarm_actions = ["${aws_sns_topic.health_check_failed.arn}"]

  dimensions {
    InstanceId = "${aws_instance.openvpn_server.id}"
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# SNS TOPICS FOR CLOUDWATCH ALARMS
# ---------------------------------------------------------------------------------------------------------------------
resource "aws_sns_topic" "health_check_failed" {
  name = "vpn-${var.aws_region}-health-check-failed"
}

# ---------------------------------------------------------------------------------------------------------------------
# SNS NOTIFICATIONS FOR "ON-CALL"
# ---------------------------------------------------------------------------------------------------------------------
resource "aws_sns_topic_subscription" "health_check_failed" {
  count = "${length(var.oncall_phone_list)}"

  topic_arn = "${aws_sns_topic.health_check_failed.arn}"
  protocol  = "sms"
  endpoint  = "${element(var.oncall_phone_list, count.index)}"
}
