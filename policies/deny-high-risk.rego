package main

deny[msg] if {
  some i, j
  input.artifacts[i].vulnerabilities[j].severity == "High"
  msg := "High severity CVE found in " + input.artifacts[i].name
}
