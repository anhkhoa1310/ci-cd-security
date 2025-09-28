#!/bin/bash

OUTPUT_FILE="security-report.md"
echo "# Security Vulnerability Report (Generated: $(date -u))" > $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

# --- CVSS to CIA Impact Mapping ---
cvss_impact() {
  local score=$1
  if (( $(echo "$score >= 9" | bc -l) )); then
    echo "High / High / High"
  elif (( $(echo "$score >= 7" | bc -l) )); then
    echo "Medium / Medium / Medium"
  elif (( $(echo "$score >= 4" | bc -l) )); then
    echo "Low / Low / Low"
  else
    echo "None / None / None"
  fi
}

# --- CVE to OWASP ASVS Mapping ---
asvs_mapping() {
  local cve=$1
  case $cve in
    *12798*) echo "V5.3 - Logging and Encoding";;
    *24813*) echo "V1.4 - Secure Deployment";;
    *22102*) echo "V5.1 - Input Validation";;
    *38821*) echo "V2.1 - Authentication";;
    *22228*) echo "V3.2 - Credential Storage";;
    *4244*)  echo "V5.2 - Data Protection";;
    *)       echo "V0 - Unclassified";;
  esac
}

# --- Trivy JSON Scanner (Table Format) ---
extract_trivy_json() {
  local FILE=$1
  echo -e "\n## Trivy Scan Report from \`$FILE\`" >> $OUTPUT_FILE

  local VULN_COUNT
  VULN_COUNT=$(jq '[.Results[]? | select(.Vulnerabilities != null) | .Vulnerabilities[]?] | length' "$FILE")

  if [[ "$VULN_COUNT" -eq 0 ]]; then
    echo "No vulnerabilities found in \`$FILE\`." >> $OUTPUT_FILE
    return
  fi

  echo '| CVE | Package | Version | Severity | CVSS | CIA | ASVS | Link |' >> $OUTPUT_FILE
  echo '|-----|---------|---------|----------|------|-----|------|------|' >> $OUTPUT_FILE

  jq -c '.Results[]? | select(.Vulnerabilities != null) | .Target as $target | .Vulnerabilities[]?' "$FILE" | while read -r vuln; do
    cve=$(echo "$vuln" | jq -r '.VulnerabilityID')
    pkg=$(echo "$vuln" | jq -r '.PkgName')
    version=$(echo "$vuln" | jq -r '.InstalledVersion')
    severity=$(echo "$vuln" | jq -r '.Severity')
    link=$(echo "$vuln" | jq -r '.PrimaryURL')
    cvss=$(echo "$vuln" | jq -r '.CVSS.nvd.V3Score // empty')
    cvss=${cvss:-"N/A"}
    cia=$(cvss_impact "$cvss")
    asvs=$(asvs_mapping "$cve")

    echo "| $cve | $pkg | $version | $severity | $cvss | $cia | $asvs | [link]($link) |" >> $OUTPUT_FILE
  done
}

# --- Snyk SARIF Parser ---
extract_snyk_sarif() {
  local FILE=$1
  echo -e "\n## Snyk Scan Report from \`$FILE\`" >> $OUTPUT_FILE

  local VULNS=$(jq '.runs[0].results | length' "$FILE")
  if [[ "$VULNS" -eq 0 ]]; then
    echo "** No vulnerabilities found in \`$FILE\`.**" >> $OUTPUT_FILE
    return
  fi

  jq -c '.runs[0].results[]?' "$FILE" | while read -r result; do
    ruleId=$(echo "$result" | jq -r '.ruleId')
    message=$(echo "$result" | jq -r '.message.text')
    severity=$(echo "$result" | jq -r '.level')
    location=$(echo "$result" | jq -r '.locations[0].physicalLocation.artifactLocation.uri')
    line=$(echo "$result" | jq -r '.locations[0].physicalLocation.region.startLine')
    echo "- **Rule ID**: $ruleId  
  - **Message**: $message  
  - **Severity**: $severity  
  - **Location**: $location:$line  
" >> $OUTPUT_FILE
  done
}

# --- SonarCloud Summary ---
extract_sonar_summary() {
  echo -e "\n## SonarCloud Summary" >> $OUTPUT_FILE

  if [[ -z "$SONAR_TOKEN" ]]; then
    echo " Skipped SonarCloud summary (missing SONAR_TOKEN env)" >> $OUTPUT_FILE
    return
  fi

  REPO_NAME=$(basename "$(git config --get remote.origin.url)" .git)
  API_URL="https://sonarcloud.io/api/measures/component?component=PhuHuynh197_${REPO_NAME}&metricKeys=bugs,vulnerabilities,security_hotspots"

  local response=$(curl -s -u "$SONAR_TOKEN": "$API_URL")

  local bug_count=$(echo "$response" | jq -r '.component.measures[] | select(.metric=="bugs") | .value // "0"')
  local vuln_count=$(echo "$response" | jq -r '.component.measures[] | select(.metric=="vulnerabilities") | .value // "0"')
  local sec_hotspot=$(echo "$response" | jq -r '.component.measures[] | select(.metric=="security_hotspots") | .value // "0"')

  if [[ "$bug_count" == "0" && "$vuln_count" == "0" && "$sec_hotspot" == "0" ]]; then
    echo "** No issues found in SonarCloud analysis.**" >> $OUTPUT_FILE
  else
    echo "* bugs: $bug_count" >> $OUTPUT_FILE
    echo "* vulnerabilities: $vuln_count" >> $OUTPUT_FILE
    echo "* security_hotspots: $sec_hotspot" >> $OUTPUT_FILE
  fi
}

# --- Run All Extractors ---
if [ -f trivy-fs.json ]; then
  extract_trivy_json "trivy-fs.json"
fi

if [ -f trivy-image.json ]; then
  extract_trivy_json "trivy-image.json"
fi

if [ -f snyk.sarif ]; then
  extract_snyk_sarif "snyk.sarif"
fi

if [[ -n "$SONAR_TOKEN" && "$GITHUB_WORKFLOW" == *"SonarCloud"* ]]; then
  extract_sonar_summary
fi

echo -e "\n Done. Generated $OUTPUT_FILE"
