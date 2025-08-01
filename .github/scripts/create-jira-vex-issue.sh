#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# This script creates a JIRA issue for each vulnerability found in a dependency.
# The script is idempotent, meaning it will not create duplicate issues if one already exists for the same CVE or GHSA ID.
#
# Usage: ./create-jira-vex-issue.sh <dependencyName> <packageEcosystem> <prevVersion>
set -eo pipefail

# Configuration
JIRA_BASE_URL=https://issues.apache.org/jira
JIRA_PROJECT=SOLR

# Logging utility
LOG_LEVEL=${LOG_LEVEL:-info}
declare -A LOG_LEVELS=( [error]=0 [info]=1 [debug]=2 )
exec 3>&2

function log() {
  local level="$1"
  shift
  local msg="$*"
  [[ ${LOG_LEVELS[$level]} -le ${LOG_LEVELS[$LOG_LEVEL]} ]] && echo "[$level] $msg" >&3 || true
}

# Check if the JIRA issue already exists for the given CVE or GHSA ID
#
# Usage: find_jira_issues <cve_id> <ghsa_id>
#
# Returns the JIRA issue key if found, otherwise returns an empty string.
function find_jira_issues() {
    local cve_id="$1"
    local ghsa_id="$2"
    log info "Searching for JIRA issues for $cve_id or $ghsa_id"
    # Search for a JIRA issue containing the CVE or GHSA ID in the summary or description
    # Requires: JIRA_BASE_URL, JIRA_PROJECT, JIRA_TOKEN environment variables
    local jql="project=$JIRA_PROJECT AND (summary ~ \"$cve_id\" OR description ~ \"$cve_id\" OR summary ~ \"$ghsa_id\" OR description ~ \"$ghsa_id\")"
    curl --silent --fail --show-error --get \
      -H "Authorization: Bearer $JIRA_API_TOKEN" \
      --data-urlencode "jql=$jql" \
      --data-urlencode "fields=summary" \
      "$JIRA_BASE_URL/rest/api/2/search" \
      | jq -r .issues[].key
}

# Create a JIRA issue for the given vulnerability
#
# Usage: create_jira_issue <artifactId> <cve_id> <ghsa_id> <severity> <summary>
function create_jira_issue() {
    local artifactId="$1"
    local cve_id="$2"
    local ghsa_id="$3"
    local severity="$4"
    local summary="$5"

    local jira_summary="Assess expoitability of ${cve_id} in dependency \`${artifactId}\`"
    local jira_description="h2. Vulnerability Assessment Request

Please assess the exploitability of the following vulnerability in Apache Solr:

* *Dependency*: \`${artifactId}\`
* *CVE ID*: \`${cve_id}\`
* *GHSA ID*: \`${ghsa_id}\`
* *Severity*: \`${severity}\`

${summary}

h3. Context

This issue was automatically created to track and assess the impact of the reported vulnerability on Apache Solr.
Please provide your analysis and recommended actions."

    # Create the JIRA issue using the JIRA REST API
    local payload
    payload=$(jq -n \
      --arg project "$JIRA_PROJECT" \
      --arg summary "$jira_summary" \
      --arg description "$jira_description" \
      '{
        fields: {
          project: { key: $project },
          summary: $summary,
          description: $description,
          issuetype: { name: "Task" },
          labels: ["security"]
        }
      }')

    if [ "$DRY_RUN" = "1" ]; then
      log info "[DRY-RUN] Would create JIRA issue for $artifactId ($cve_id, $ghsa_id, $severity)"
      log info "[DRY-RUN] Payload: $payload"
      echo "SOLR-DRYRUN"
      return 0
    fi

    local response
    response=$(curl --silent --show-error -X POST \
      -H "Authorization: Bearer $JIRA_TOKEN" \
      -H "Content-Type: application/json" \
      --data "$payload" \
      "$JIRA_BASE_URL/rest/api/2/issue")
    if jq -e 'has("errors")' <<<"$response" > /dev/null; then
        log error "Failed to create JIRA issue for $artifactId ($cve_id, $ghsa_id, $severity)"
        log error "Request: $payload"
        log error "Response: $response"
        exit 1
    fi
    jq -r '.key' <<<"$response"
}

# Find vulnerabilities for the given dependency
#
# Usage: find_vulnerabilities <groupId> <artifactId> <version>
#
# Returns each vulnerability as JSON object {cve_id: <cve_id>, ghsa_id: <ghsa_id>} on a new line.
function find_vulnerabilities() {
    local groupId="$1"
    local artifactId="$2"
    local version="$3"

    log info "Finding vulnerabilities for $groupId:$artifactId:$version"
    # Call the GitHub Advisory Database API to find vulnerabilities affecting the specified Maven dependency
    curl --silent --fail --show-error --get \
       -H "Accept: application/vnd.github+json" \
       "https://api.github.com/advisories?ecosystem=maven&affects=${groupId}:${artifactId}@${version}" \
       | jq --compact-output --monochrome-output \
       --arg artifactId "$artifactId" \
       '.[] | {artifactId:$artifactId, cve_id: .cve_id, ghsa_id: .ghsa_id, severity: .severity, summary: .summary}'
}

# Main script execution starts here
if [[ "$1" == "--dry-run" ]]; then
    DRY_RUN=1
    shift
else
    DRY_RUN=0
fi

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 [--dry-run] <groupId> <artifactId> <version>"
    echo "Requires GITHUB_TOKEN and JIRA_TOKEN environment variables to be set."
    exit 1
fi

#if [ -z "$GITHUB_TOKEN" ] || [ -z "$JIRA_TOKEN" ]; then
#    echo "Error: GITHUB_TOKEN and JIRA_API_TOKEN environment variables must be set."
#    exit 1
#fi

GROUP_ID=$1
ARTIFACT_ID=$2
VERSION=$3

# Find vulnerabilities for the given dependency
find_vulnerabilities "$GROUP_ID" "$ARTIFACT_ID" "$VERSION" | while read -r vulnerability; do
    log debug "Processing vulnerability: $vulnerability"
    cve_id=$(echo "$vulnerability" | jq -r '.cve_id')
    ghsa_id=$(echo "$vulnerability" | jq -r '.ghsa_id')
    severity=$(echo "$vulnerability" | jq -r '.severity')
    summary=$(echo "$vulnerability" | jq -r '.summary')
    log info "Found vulnerability:
    CVE: $cve_id
    GHSA: $ghsa_id
    Severity: $severity
    Summary: $summary"

    # Check if the JIRA issue already exists
    mapfile -t jira_issues < <(find_jira_issues "$cve_id" "$ghsa_id")
    if [ "${#jira_issues[@]}" -ne 0 ]; then
        log info "Found existing JIRA issues: ${jira_issue[*]}"
        echo "${jira_issues[0]}"
        continue
    fi

    # Create a new JIRA issue for the vulnerability
    jira_issue=$(create_jira_issue "$ARTIFACT_ID" "$cve_id" "$ghsa_id" "$severity" "$summary")
    log info "Created JIRA issue $jira_issue for $cve_id or $ghsa_id"
    echo "$jira_issue"
done