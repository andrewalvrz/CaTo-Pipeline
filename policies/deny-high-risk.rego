package main

deny[msg] {
  some i, j
  input.artifacts[i].vulnerabilities[j].severity == "High"
  msg := "High severity CVE found"
}
