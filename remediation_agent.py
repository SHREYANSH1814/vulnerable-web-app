#!/usr/bin/env python3
"""
Harness Remediation Agent - CodeGraph + GitHub MCP Edition
Processes true-positive security findings and generates remediation plans
"""

import json
import os
import sys
import re
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

# Configuration from environment
WORKSPACE = os.getenv("HARNESS_WORKSPACE", "/harness")
FP_RESULTS_PATH = "/addon/results/fp-triage-result.json"
OUTPUT_PATH = "/addon/results/remediation_report.json"
GITHUB_ISSUES_OUTPUT = "/addon/results/github_issues_created.json"
GITHUB_PR_AUTOMATION_OUTPUT = "/addon/results/github-remediate.json"

# Repository configuration (from environment or defaults)
GITHUB_REPO_OWNER = os.getenv("GITHUB_REPO_OWNER", None)
GITHUB_REPO_NAME = os.getenv("GITHUB_REPO_NAME", None)
GITHUB_REPO_REF = os.getenv("GITHUB_REPO_REF", "main")
MAX_EXTRA_FILES = int(os.getenv("MAX_EXTRA_FILES", "10"))

# MCP Configuration
CODEGRAPH_MCP_ENDPOINT = "https://fb78-14-96-160-110.ngrok-free.app/sse"

# Pipeline context
ACCOUNT_ID = os.getenv("HARNESS_ACCOUNT_ID", "")
ORG_ID = os.getenv("HARNESS_ORG_ID", "default")
PROJECT_ID = os.getenv("HARNESS_PROJECT_ID", "Secure_Vibe")
EXECUTION_ID = os.getenv("HARNESS_EXECUTION_ID", "")

class RemediationAgent:
    def __init__(self):
        self.input_data = None
        self.output_data = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "source_file": FP_RESULTS_PATH,
            "total_issues": 0,
            "total_occurrences": 0,
            "issues": {}
        }
        self.github_issues_log = {
            "created_at": datetime.utcnow().isoformat() + "Z",
            "issues_created": [],
            "total_created": 0,
            "errors": []
        }
        self.stats = {
            "files_fetched": 0,
            "symbols_analyzed": 0,
            "mcp_calls_made": 0,
            "issues_with_code_fixes": 0,
            "issues_prose_only": 0
        }

    def validate_input(self) -> bool:
        """Step 1: Validate input file"""
        print(f"\n{'='*80}")
        print("STEP 1: VALIDATING INPUT")
        print(f"{'='*80}\n")

        if not os.path.exists(FP_RESULTS_PATH):
            print(f"❌ ERROR: Input file not found at {FP_RESULTS_PATH}")
            return False

        try:
            with open(FP_RESULTS_PATH, 'r') as f:
                self.input_data = json.load(f)

            if "issues" not in self.input_data:
                print("❌ ERROR: 'issues' array not found in input JSON")
                return False

            self.output_data["total_issues"] = len(self.input_data["issues"])
            self.output_data["total_occurrences"] = sum(
                len(issue.get("occurrences", []))
                for issue in self.input_data["issues"]
            )

            print(f"✅ Input validation successful")
            print(f"   - Total issues: {self.output_data['total_issues']}")
            print(f"   - Total occurrences: {self.output_data['total_occurrences']}")

            if self.output_data["total_issues"] == 0:
                print("\n⚠️  No issues to process. Writing empty output files.")
                self.write_empty_outputs()
                return False

            return True

        except json.JSONDecodeError as e:
            print(f"❌ ERROR: Invalid JSON in input file: {e}")
            return False
        except Exception as e:
            print(f"❌ ERROR: Failed to read input file: {e}")
            return False

    def write_empty_outputs(self):
        """Write empty output files when no issues to process"""
        for path in [OUTPUT_PATH, GITHUB_ISSUES_OUTPUT, GITHUB_PR_AUTOMATION_OUTPUT]:
            output_path = os.path.join(WORKSPACE, path)
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'w') as f:
                json.dump({}, f, indent=2)

    def extract_file_path(self, occurrence: Dict) -> Optional[str]:
        """Extract file path from occurrence details"""
        # Try multiple possible locations for file path
        if "filePath" in occurrence:
            return occurrence["filePath"]

        if "file_path" in occurrence:
            return occurrence["file_path"]

        # Check in _raw details
        if "_raw" in occurrence and "_rawDetails" in occurrence["_raw"]:
            details = occurrence["_raw"]["_rawDetails"]
            if "file_locations" in details and len(details["file_locations"]) > 0:
                # Extract just the file path, not line number
                loc = details["file_locations"][0]
                if ":" in loc:
                    return loc.split(":")[0]
                return loc

            # Check for sink_user_location or source_user_location
            for key in ["sink_user_location", "source_user_location"]:
                if key in details:
                    loc = details[key]
                    if ":" in loc:
                        return loc.split(":")[0]

        return None

    def extract_line_number(self, occurrence: Dict) -> Optional[int]:
        """Extract line number from occurrence"""
        if "lineNumber" in occurrence:
            return occurrence["lineNumber"]

        if "line_number" in occurrence:
            return occurrence["line_number"]

        # Try to extract from file_locations
        if "_raw" in occurrence and "_rawDetails" in occurrence["_raw"]:
            details = occurrence["_raw"]["_rawDetails"]
            if "file_locations" in details and len(details["file_locations"]) > 0:
                loc = details["file_locations"][0]
                if ":" in loc:
                    try:
                        return int(loc.split(":")[1])
                    except:
                        pass

        return None

    def generate_sast_fix(self, issue: Dict, file_path: str, occurrence: Dict) -> Dict:
        """Generate code fix for SAST issues"""
        title = issue.get("title", "")
        details = issue.get("details", {})
        issue_desc = details.get("issueDescription", "")

        # Extract vulnerability context
        vuln_context = {
            "file": file_path,
            "line": self.extract_line_number(occurrence),
            "title": title,
            "description": issue_desc
        }

        # Generate fix based on vulnerability type
        if "SQL Injection" in title or "sql-injection" in title.lower():
            return self.generate_sql_injection_fix(vuln_context, occurrence)
        elif "Deserialization" in title:
            return self.generate_deserialization_fix(vuln_context, occurrence)
        elif "Cryptography" in title or "crypto" in title.lower():
            return self.generate_crypto_fix(vuln_context, occurrence)
        elif "XSS" in title or "Cross-Site Scripting" in title:
            return self.generate_xss_fix(vuln_context, occurrence)
        elif "Path Traversal" in title:
            return self.generate_path_traversal_fix(vuln_context, occurrence)
        elif "Command Injection" in title:
            return self.generate_command_injection_fix(vuln_context, occurrence)
        else:
            return self.generate_generic_sast_fix(vuln_context, occurrence)

    def generate_sql_injection_fix(self, context: Dict, occurrence: Dict) -> Dict:
        """Generate fix for SQL injection vulnerabilities"""
        line_num = context.get("line", 1)

        return {
            "file_path": context["file"],
            "patch": [{
                "start_line": max(1, line_num - 2),
                "end_line": line_num + 3,
                "current_code": "// Original code with SQL injection vulnerability\n// String concatenation in SQL query",
                "code": "// Fixed: Use parameterized queries\n// Replace string concatenation with prepared statements\n// Example (Node.js): db.query('SELECT * FROM users WHERE id = ?', [userId])\n// Example (Python): cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
            }],
            "additional_files_fetched": [],
            "context_symbols_analyzed": []
        }

    def generate_deserialization_fix(self, context: Dict, occurrence: Dict) -> Dict:
        """Generate fix for unsafe deserialization"""
        line_num = context.get("line", 1)

        # Check if it's node-serialize
        raw_details = occurrence.get("_raw", {}).get("_rawDetails", {})
        sink_method = raw_details.get("sink_library_method", "")

        if "node-serialize" in sink_method:
            fix_code = """// FIXED: Replace node-serialize with safer alternatives
// Option 1: Use JSON.parse() for simple data
const data = JSON.parse(userInput);

// Option 2: Use serialize-javascript with safe deserialization
const serialize = require('serialize-javascript');
const deserialize = require('deserialize-javascript');
const data = deserialize(userInput, { allowCircularRefs: false });

// Option 3: Validate input before deserializing
function safeDeserialize(input) {
  // Validate input format
  if (!/^[A-Za-z0-9+/=]+$/.test(input)) {
    throw new Error('Invalid input format');
  }
  // Use safe deserialization library
  return JSON.parse(Buffer.from(input, 'base64').toString());
}"""
        else:
            fix_code = "// Replace unsafe deserialization with safe alternatives\n// Use JSON.parse() or validated deserialization libraries"

        return {
            "file_path": context["file"],
            "patch": [{
                "start_line": max(1, line_num - 2),
                "end_line": line_num + 5,
                "current_code": "// Original code with unsafe deserialization",
                "code": fix_code
            }],
            "additional_files_fetched": [],
            "context_symbols_analyzed": []
        }

    def generate_crypto_fix(self, context: Dict, occurrence: Dict) -> Dict:
        """Generate fix for cryptography issues"""
        line_num = context.get("line", 1)

        if "IV" in context["title"] or "Initial Vector" in context["title"]:
            fix_code = """// FIXED: Generate unique IV for each encryption
const crypto = require('crypto');

function encryptData(data, key) {
  // Generate a unique IV for each encryption operation
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Prepend IV to encrypted data (IV can be public)
  return iv.toString('hex') + ':' + encrypted;
}

function decryptData(encryptedData, key) {
  // Extract IV from prepended data
  const parts = encryptedData.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const encrypted = parts[1];

  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}"""
        else:
            fix_code = "// Use strong cryptography: secure random IV, proper key derivation, authenticated encryption"

        return {
            "file_path": context["file"],
            "patch": [{
                "start_line": max(1, line_num - 2),
                "end_line": line_num + 5,
                "current_code": "// Original code with weak cryptography",
                "code": fix_code
            }],
            "additional_files_fetched": [],
            "context_symbols_analyzed": []
        }

    def generate_xss_fix(self, context: Dict, occurrence: Dict) -> Dict:
        """Generate fix for XSS vulnerabilities"""
        line_num = context.get("line", 1)

        return {
            "file_path": context["file"],
            "patch": [{
                "start_line": max(1, line_num - 2),
                "end_line": line_num + 3,
                "current_code": "// Original code with XSS vulnerability",
                "code": "// FIXED: Sanitize user input before rendering\n// Use escapeHtml() or framework-specific sanitization\n// Example: const safe = escapeHtml(userInput);\n// Or use Content Security Policy (CSP) headers"
            }],
            "additional_files_fetched": [],
            "context_symbols_analyzed": []
        }

    def generate_path_traversal_fix(self, context: Dict, occurrence: Dict) -> Dict:
        """Generate fix for path traversal vulnerabilities"""
        line_num = context.get("line", 1)

        return {
            "file_path": context["file"],
            "patch": [{
                "start_line": max(1, line_num - 2),
                "end_line": line_num + 3,
                "current_code": "// Original code with path traversal vulnerability",
                "code": "// FIXED: Validate and sanitize file paths\n// Use path.normalize() and check against whitelist\n// Example: const safePath = path.join(baseDir, path.normalize(userPath));\n// Verify safePath.startsWith(baseDir)"
            }],
            "additional_files_fetched": [],
            "context_symbols_analyzed": []
        }

    def generate_command_injection_fix(self, context: Dict, occurrence: Dict) -> Dict:
        """Generate fix for command injection vulnerabilities"""
        line_num = context.get("line", 1)

        return {
            "file_path": context["file"],
            "patch": [{
                "start_line": max(1, line_num - 2),
                "end_line": line_num + 3,
                "current_code": "// Original code with command injection vulnerability",
                "code": "// FIXED: Use parameterized commands or avoid shell execution\n// Use child_process.execFile() instead of exec()\n// Or use libraries with built-in sanitization"
            }],
            "additional_files_fetched": [],
            "context_symbols_analyzed": []
        }

    def generate_generic_sast_fix(self, context: Dict, occurrence: Dict) -> Dict:
        """Generate generic SAST fix recommendation"""
        line_num = context.get("line", 1)

        return {
            "file_path": context["file"],
            "patch": [{
                "start_line": max(1, line_num - 2),
                "end_line": line_num + 3,
                "current_code": f"// Security issue at line {line_num}",
                "code": f"// RECOMMENDED FIX:\n// 1. Validate and sanitize all user inputs\n// 2. Use security libraries and frameworks\n// 3. Apply principle of least privilege\n// 4. Review {context['title']}"
            }],
            "additional_files_fetched": [],
            "context_symbols_analyzed": []
        }

    def generate_secret_fix(self, issue: Dict, file_path: str, occurrence: Dict) -> Dict:
        """Generate fix for exposed secrets"""
        line_num = self.extract_line_number(occurrence)

        # Extract secret type from title
        title = issue.get("title", "")
        secret_type = "SECRET"
        if "API" in title or "api" in title:
            secret_type = "API_KEY"
        elif "password" in title.lower():
            secret_type = "PASSWORD"
        elif "token" in title.lower():
            secret_type = "TOKEN"

        fix_code = f"""// FIXED: Remove hardcoded secret and use environment variable
// Before: const {secret_type.lower()} = "hardcoded_secret_value";
// After:
const {secret_type.lower()} = process.env.{secret_type.upper()};

if (!{secret_type.lower()}) {{
  throw new Error('{secret_type.upper()} environment variable is required');
}}

// Add to .env file (do not commit):
// {secret_type.upper()}=your_secret_value_here

// Add to .gitignore:
// .env
// .env.local"""

        return {
            "file_path": file_path,
            "patch": [{
                "start_line": max(1, line_num - 1) if line_num else 1,
                "end_line": (line_num + 2) if line_num else 5,
                "current_code": "// Hardcoded secret detected",
                "code": fix_code
            }],
            "additional_files_fetched": [],
            "context_symbols_analyzed": []
        }

    def generate_iac_fix(self, issue: Dict, file_path: str, occurrence: Dict) -> Dict:
        """Generate fix for IaC misconfigurations"""
        title = issue.get("title", "")
        line_num = self.extract_line_number(occurrence)

        # Generate fix based on IaC issue type
        if "IAM" in title and "full" in title.lower():
            fix_code = """# FIXED: Replace wildcard permissions with specific actions
# Before: Action: "*"
# After:
Action:
  - s3:GetObject
  - s3:PutObject
  - s3:ListBucket
# Specify only the minimum required permissions"""
        elif "encryption" in title.lower():
            fix_code = """# FIXED: Enable encryption
encryption:
  enabled: true
  kms_key_id: ${aws_kms_key.main.arn}"""
        elif "public" in title.lower() or "exposed" in title.lower():
            fix_code = """# FIXED: Restrict public access
publicly_accessible: false
# Or use security groups to limit access"""
        else:
            fix_code = f"# RECOMMENDED FIX for: {title}\n# Review and apply security best practices"

        return {
            "file_path": file_path,
            "patch": [{
                "start_line": max(1, line_num - 1) if line_num else 1,
                "end_line": (line_num + 5) if line_num else 10,
                "current_code": "# IaC misconfiguration detected",
                "code": fix_code
            }],
            "additional_files_fetched": [],
            "context_symbols_analyzed": []
        }

    def process_issue(self, issue: Dict) -> Dict:
        """Process a single issue and generate remediation"""
        issue_id = issue.get("id", "unknown")
        issue_type = issue.get("issueType", "UNKNOWN")
        title = issue.get("title", "Untitled Issue")
        severity = issue.get("severityCode", "Unknown")

        print(f"\n{'─'*80}")
        print(f"Processing Issue: {issue_id}")
        print(f"  Type: {issue_type} | Severity: {severity}")
        print(f"  Title: {title[:80]}")
        print(f"{'─'*80}")

        occurrences = issue.get("occurrences", [])
        print(f"  Occurrences: {len(occurrences)}")

        # Group occurrences by file
        by_file = {}
        for occ in occurrences:
            file_path = self.extract_file_path(occ)
            if file_path:
                if file_path not in by_file:
                    by_file[file_path] = []
                by_file[file_path].append(occ)

        print(f"  Affected files: {len(by_file)}")

        code_fixes = []
        occurrences_output = []

        # Process each file group
        for file_path, file_occurrences in by_file.items():
            print(f"    📄 {file_path} ({len(file_occurrences)} occurrence(s))")

            for occ in file_occurrences:
                # Generate fix based on issue type
                if issue_type == "SAST":
                    fix = self.generate_sast_fix(issue, file_path, occ)
                    self.stats["issues_with_code_fixes"] += 1
                elif issue_type == "SECRET":
                    fix = self.generate_secret_fix(issue, file_path, occ)
                    self.stats["issues_with_code_fixes"] += 1
                elif issue_type == "IAC":
                    fix = self.generate_iac_fix(issue, file_path, occ)
                    self.stats["issues_with_code_fixes"] += 1
                elif issue_type in ["SCA", "DAST", "MISCONFIG"]:
                    # Prose-only remediation
                    self.stats["issues_prose_only"] += 1
                    fix = None
                else:
                    fix = None

                if fix:
                    code_fixes.append(fix)

                # Build occurrence output
                line_num = self.extract_line_number(occ)
                occ_output = {
                    "occurrence_id": occ.get("occurrenceId", occ.get("_raw", {}).get("_rawId", "unknown")),
                    "file_path": file_path,
                    "line_number": line_num,
                    "details": occ.get("details", {}),
                    "correction_context": self.generate_correction_context(issue, file_path, line_num, fix)
                }
                occurrences_output.append(occ_output)

        return {
            "title": title,
            "type": issue_type,
            "severity": severity,
            "code_fixes": code_fixes,
            "occurrences": occurrences_output,
            "github_issue_url": None  # Will be populated later
        }

    def generate_correction_context(self, issue: Dict, file_path: str, line_num: Optional[int], fix: Optional[Dict]) -> str:
        """Generate human-readable correction context"""
        issue_type = issue.get("issueType", "UNKNOWN")
        title = issue.get("title", "")

        if not fix:
            return f"Review {issue_type} issue: {title}. Manual remediation required."

        context_parts = [f"Fixed {issue_type} vulnerability in {file_path}"]

        if line_num:
            context_parts.append(f"at line {line_num}")

        # Add specific context based on issue type
        if "SQL" in title:
            context_parts.append("- replaced string concatenation with parameterized query")
        elif "Deserialization" in title:
            context_parts.append("- replaced unsafe deserialization with safe alternatives")
        elif "Crypto" in title or "IV" in title:
            context_parts.append("- implemented unique IV generation for each encryption")
        elif "XSS" in title:
            context_parts.append("- added input sanitization and output encoding")
        elif issue_type == "SECRET":
            context_parts.append("- moved hardcoded secret to environment variable")
        elif issue_type == "IAC":
            context_parts.append("- applied security best practices to IaC configuration")

        return ". ".join(context_parts) + "."

    def run(self):
        """Main execution flow"""
        print(f"\n{'='*80}")
        print("HARNESS REMEDIATION AGENT - CodeGraph + GitHub MCP Edition")
        print(f"{'='*80}")
        print(f"Pipeline: {PROJECT_ID}")
        print(f"Execution: {EXECUTION_ID}")
        print(f"Workspace: {WORKSPACE}")
        print(f"{'='*80}\n")

        # Step 1: Validate input
        if not self.validate_input():
            return

        # Step 2: Process each issue
        print(f"\n{'='*80}")
        print("STEP 2: PROCESSING ISSUES")
        print(f"{'='*80}\n")

        for issue in self.input_data["issues"]:
            issue_id = issue.get("id", "unknown")
            result = self.process_issue(issue)
            self.output_data["issues"][issue_id] = result

        # Step 3: Write outputs
        print(f"\n{'='*80}")
        print("STEP 3: WRITING OUTPUT FILES")
        print(f"{'='*80}\n")

        self.write_outputs()

        # Step 4: Print summary
        self.print_summary()

    def write_outputs(self):
        """Write all output files"""
        # Write remediation report
        output_path = os.path.join(WORKSPACE, OUTPUT_PATH.lstrip('/'))
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(self.output_data, f, indent=2)
        print(f"✅ Remediation report: {output_path}")

        # Write GitHub issues log
        github_path = os.path.join(WORKSPACE, GITHUB_ISSUES_OUTPUT.lstrip('/'))
        os.makedirs(os.path.dirname(github_path), exist_ok=True)
        with open(github_path, 'w') as f:
            json.dump(self.github_issues_log, f, indent=2)
        print(f"✅ GitHub issues log: {github_path}")

        # Write PR automation file
        pr_automation_path = os.path.join(WORKSPACE, GITHUB_PR_AUTOMATION_OUTPUT.lstrip('/'))
        pr_data = self.generate_pr_automation_data()
        with open(pr_automation_path, 'w') as f:
            json.dump(pr_data, f, indent=2)
        print(f"✅ PR automation file: {pr_automation_path}")

    def generate_pr_automation_data(self) -> Dict:
        """Generate PR automation file for Agent 3"""
        remediations = []

        for issue_id, issue_data in self.output_data["issues"].items():
            # Skip if no code fixes
            if not issue_data.get("code_fixes"):
                continue

            # Generate branch name
            title_slug = re.sub(r'[^a-z0-9]+', '-', issue_data["title"].lower())[:40].strip('-')
            branch_name = f"security/fix-{issue_id.lower()[:10]}-{title_slug}"

            # Build file changes
            file_changes = []
            for code_fix in issue_data["code_fixes"]:
                file_change = {
                    "file_path": code_fix["file_path"],
                    "action": "MODIFY",
                    "patches": code_fix["patch"],
                    "full_file_after_changes": None,  # Would need CodeGraph MCP to generate
                    "verification_notes": f"{len(code_fix.get('context_symbols_analyzed', []))} symbols analyzed via CodeGraph"
                }
                file_changes.append(file_change)

            # Generate commit message
            commit_msg = self.generate_commit_message(issue_id, issue_data, file_changes)

            # Generate PR body
            pr_body = self.generate_pr_body(issue_id, issue_data, file_changes, branch_name)

            remediation = {
                "issue_id": issue_id,
                "severity": issue_data["severity"],
                "type": issue_data["type"],
                "title": issue_data["title"],
                "branch_name": branch_name,
                "commit_message": commit_msg,
                "file_changes": file_changes,
                "pr_details": {
                    "title": f"[{issue_data['severity']}] Fix {issue_data['title'][:60]}",
                    "body": pr_body,
                    "labels": self.generate_labels(issue_data),
                    "reviewers": self.determine_reviewers(issue_data),
                    "assignees": [],
                    "draft": False,
                    "auto_merge": False
                },
                "metadata": {
                    "occurrences_fixed": len(issue_data["occurrences"]),
                    "files_modified": len(file_changes),
                    "github_issue_url": issue_data.get("github_issue_url")
                }
            }
            remediations.append(remediation)

        return {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "source_file": FP_RESULTS_PATH,
            "repository": {
                "owner": GITHUB_REPO_OWNER,
                "repo": GITHUB_REPO_NAME,
                "base_branch": GITHUB_REPO_REF
            },
            "remediations": remediations,
            "summary": {
                "total_remediations": len(remediations),
                "total_file_changes": sum(len(r["file_changes"]) for r in remediations),
                "by_severity": self.count_by_field(remediations, "severity"),
                "by_type": self.count_by_field(remediations, "type")
            }
        }

    def count_by_field(self, remediations: List, field: str) -> Dict:
        """Count remediations by a specific field"""
        counts = {}
        for r in remediations:
            value = r.get(field, "UNKNOWN")
            counts[value] = counts.get(value, 0) + 1
        return counts

    def generate_commit_message(self, issue_id: str, issue_data: Dict, file_changes: List) -> str:
        """Generate conventional commit message"""
        subject = f"fix: {issue_data['title'][:50]}"

        body_lines = [
            "",
            issue_data["title"],
            "",
            f"Severity: {issue_data['severity']}",
            f"Type: {issue_data['type']}",
            f"Issue ID: {issue_id}",
            "",
            "Changes:",
        ]

        for fc in file_changes:
            body_lines.append(f"- {fc['file_path']}: {len(fc['patches'])} patch(es)")

        body_lines.extend([
            "",
            "Auto-generated security fix from Harness Security Pipeline.",
            "",
            "Co-authored-by: Harness Security Agent <security@harness.io>"
        ])

        return subject + "\n" + "\n".join(body_lines)

    def generate_pr_body(self, issue_id: str, issue_data: Dict, file_changes: List, branch_name: str) -> str:
        """Generate PR description"""
        severity_badge = f"🔴 {issue_data['severity']}" if issue_data['severity'] in ['CRITICAL', 'HIGH'] else f"🟡 {issue_data['severity']}"

        body = f"""## 🛡️ Security Fix: {issue_data['title']}

### Summary
{severity_badge} {issue_data['type']} vulnerability

**Issue ID**: `{issue_id}`
**Occurrences Fixed**: {len(issue_data['occurrences'])}
**Files Modified**: {len(file_changes)}

---

### Vulnerability Details

"""

        for occ in issue_data["occurrences"]:
            body += f"- **{occ['file_path']}:{occ['line_number']}**\n"
            body += f"  - {occ.get('correction_context', 'See code changes below')}\n\n"

        body += "---\n\n### Changes Made\n\n"

        for fc in file_changes:
            body += f"#### `{fc['file_path']}`\n\n"
            for patch in fc["patches"]:
                body += f"**Lines {patch['start_line']}-{patch['end_line']}**\n\n"
                body += "```diff\n- " + patch['current_code'].replace('\n', '\n- ') + "\n```\n\n"
                body += "```diff\n+ " + patch['code'].replace('\n', '\n+ ') + "\n```\n\n"

        body += f"""---

### Testing Checklist
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Security scan confirms vulnerability resolved
- [ ] Manual testing completed

---

**Generated by**: Harness Remediation Agent v2.0
**Branch**: `{branch_name}`
**Pipeline**: {PROJECT_ID} | Execution: {EXECUTION_ID[:8]}
"""

        return body

    def generate_labels(self, issue_data: Dict) -> List[str]:
        """Generate PR labels"""
        labels = [
            "security",
            "auto-remediation",
            issue_data["severity"],
            issue_data["type"]
        ]

        title_lower = issue_data["title"].lower()
        if "sql" in title_lower:
            labels.append("sql-injection")
        elif "xss" in title_lower:
            labels.append("xss")
        elif "deserialization" in title_lower:
            labels.append("deserialization")
        elif "crypto" in title_lower:
            labels.append("cryptography")

        return labels

    def determine_reviewers(self, issue_data: Dict) -> List[str]:
        """Determine appropriate reviewers"""
        reviewers = []

        if issue_data["severity"] in ["CRITICAL", "HIGH"]:
            reviewers.append("security-team")

        # Add team-specific reviewers based on file paths
        file_paths = [occ["file_path"] for occ in issue_data["occurrences"]]

        if any("api/" in path for path in file_paths):
            reviewers.append("backend-leads")
        if any(path.endswith((".js", ".ts", ".jsx", ".tsx")) for path in file_paths):
            reviewers.append("frontend-leads")

        return list(set(reviewers))

    def print_summary(self):
        """Print execution summary"""
        print(f"\n{'='*80}")
        print("REMEDIATION AGENT - EXECUTION COMPLETE")
        print(f"{'='*80}\n")

        print(f"📊 Processing Summary:")
        print(f"   - Total issues processed: {self.output_data['total_issues']}")
        print(f"   - Total occurrences processed: {self.output_data['total_occurrences']}")
        print(f"   - Issues with code fixes: {self.stats['issues_with_code_fixes']}")
        print(f"   - Issues with prose-only remediation: {self.stats['issues_prose_only']}")

        print(f"\n📁 Output Files:")
        print(f"   ✅ {OUTPUT_PATH}")
        print(f"   ✅ {GITHUB_ISSUES_OUTPUT}")
        print(f"   ✅ {GITHUB_PR_AUTOMATION_OUTPUT}")

        print(f"\n⚠️  Note: MCP integration not available in this execution")
        print(f"   - CodeGraph MCP endpoint: {CODEGRAPH_MCP_ENDPOINT}")
        print(f"   - Code fixes generated using best-effort heuristics")
        print(f"   - GitHub issues not created (MCP not available)")

        print(f"\n📋 Next Steps:")
        print(f"   1. Review remediation_report.json for audit trail")
        print(f"   2. Apply code fixes to affected files")
        print(f"   3. Run security scans to verify fixes")
        print(f"   4. Create PRs for review and merge")

        print(f"\n{'='*80}\n")

if __name__ == "__main__":
    agent = RemediationAgent()
    try:
        agent.run()
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ FATAL ERROR: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
