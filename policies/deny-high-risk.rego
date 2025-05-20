package main

deny[msg] if {
  some i, j
  input.artifacts[i].vulnerabilities[j].severity == "High"
  msg := sprintf("High severity CVE found in %v", [input.artifacts[i].name])
}
