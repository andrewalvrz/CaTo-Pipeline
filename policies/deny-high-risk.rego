package main

deny[msg] {
  input.artifacts[_].vulnerabilities[_].severity == "High"
  msg := "High severity CVE found"
}
