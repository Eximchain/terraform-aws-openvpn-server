output "public_ip"   {
  value = "${aws_eip.openvpn.public_ip}"
}

output "public_fqdn" {
  value = "${aws_route53_record.openvpn.fqdn}"
}
