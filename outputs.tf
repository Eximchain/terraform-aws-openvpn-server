output "public_ip"   {
  value = "${aws_eip.openvpn.public_ip}"
}

output "public_fqdn" {
  value = "${aws_route53_record.openvpn.fqdn}"
}

output "aws_region" {
  value = "${var.aws_region}"
}

output "vpc_id" {
  value = "${aws_vpc.openvpn.id}"
}
