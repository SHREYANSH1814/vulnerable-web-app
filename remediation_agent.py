#!/usr/bin/env python3
"""
Harness Remediation Agent - CodeGraph + GitHub MCP Edition
Generates code fixes for security vulnerabilities and creates GitHub issues
"""

import json
import os
import sys
import re
import subprocess
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

# Configuration
INPUT_FILE = "/addon/results/fp-triage-result.json"
OUTPUT_FILE = "/addon/results/remediation_report.json"
GITHUB_ISSUES_LOG = "/addon/results/github_issues_created.json"
PR_AUTOMATION_FILE = "/addon/results/github-remediate.json"
PR_METADATA_FILE = "/addon/results/remediation_metadata.json"

WORKSPACE = os.environ.get('HARNESS_WORKSPACE', '/harness')
REPO_DIR = '/harness'

# Parse repository info from git remote
GITHUB_REPO_OWNER = "SHREYANSH1814"
GITHUB_REPO_NAME = "vulnerable-web-app"
GITHUB_REPO_REF = "main"

MAX_EXTRA_FILES = 10


class RemediationAgent:
    """Main remediation agent class"""

    def __init__(self):
        self.input_data = None
        self.output_data = {
            "generated_at": datetime.now().isoformat(),
            "source_file": INPUT_FILE,
            "total_issues": 0,
            "total_occurrences": 0,
            "issues": {}
        }
        self.github_issues_log = {
            "created_at": datetime.now().isoformat(),
            "issues_created": [],
            "total_created": 0,
            "errors": []
        }
        self.stats = {
            "files_fetched": 0,
            "symbols_analyzed": 0,
            "code_fixes_generated": 0,
            "prose_remediations": 0,
            "github_issues_created": 0,
            "github_issues_failed": 0
        }

    def load_input(self) -> bool:
        """Load and validate input file"""
        print(f"\n📂 Step 1: Loading input file...")

        if not os.path.exists(INPUT_FILE):
            print(f"   ❌ ERROR: Input file not found: {INPUT_FILE}")
            return False

        try:
            with open(INPUT_FILE, 'r') as f:
                self.input_data = json.load(f)

            if "issues" not in self.input_data:
                print(f"   ❌ ERROR: Invalid input format - 'issues' key missing")
                return False

            self.output_data["total_issues"] = len(self.input_data.get("issues", []))
            self.output_data["total_occurrences"] = sum(
                len(issue.get("occurrences", []))
                for issue in self.input_data.get("issues", [])
            )

            if self.output_data["total_issues"] == 0:
                print(f"   ℹ️  No issues to process (empty input)")
                return False

            print(f"   ✓ Loaded {self.output_data['total_issues']} issues")
            print(f"   ✓ Total occurrences: {self.output_data['total_occurrences']}")
            return True

        except json.JSONDecodeError as e:
            print(f"   ❌ ERROR: Invalid JSON format: {e}")
            return False
        except Exception as e:
            print(f"   ❌ ERROR: Failed to load input: {e}")
            return False

    def get_file_content(self, file_path: str) -> Optional[str]:
        """Fetch file content from local filesystem or GitHub MCP"""
        # Try local filesystem first
        abs_path = self.find_file_in_harness(file_path)
        if abs_path and os.path.exists(abs_path):
            try:
                with open(abs_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                print(f"      📄 Read {file_path} from filesystem ({len(content)} chars)")
                self.stats["files_fetched"] += 1
                return content
            except Exception as e:
                print(f"      ⚠️  Could not read {abs_path}: {e}")

        print(f"      ℹ️  File not found locally: {file_path}")
        return None

    def find_file_in_harness(self, file_path: str) -> Optional[str]:
        """Find file in /harness using multiple strategies"""
        # Strategy 1: Direct join
        candidate = os.path.join(REPO_DIR, file_path.lstrip('/'))
        if os.path.exists(candidate):
            return candidate

        # Strategy 2: Strip /harness prefix
        stripped = file_path
        for prefix in ('/harness/', '/harness'):
            if stripped.startswith(prefix):
                stripped = stripped[len(prefix):]
                break
        candidate2 = os.path.join('/harness', stripped)
        if os.path.exists(candidate2):
            return candidate2

        # Strategy 3: Find by basename
        basename = os.path.basename(file_path)
        try:
            result = subprocess.run(
                ['find', '/harness', '-name', basename, '-type', 'f'],
                capture_output=True, text=True, timeout=10
            )
            candidates = [l for l in result.stdout.strip().split('\n') if l]
            if not candidates:
                return None

            # Score by longest matching suffix
            fp_parts = file_path.replace('\\', '/').lstrip('/').split('/')
            best, best_score = None, 0
            for c in candidates:
                c_parts = c.split('/')
                score = sum(
                    1 for i, seg in enumerate(reversed(fp_parts))
                    if i < len(c_parts) and c_parts[-(i + 1)] == seg
                )
                if score > best_score:
                    best_score, best = score, c
            return best
        except Exception:
            return None

    def extract_code_context(self, file_content: str, line_number: int, context_lines: int = 10) -> str:
        """Extract code around a specific line"""
        lines = file_content.split('\n')
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)
        return '\n'.join(lines[start:end])

    def generate_fix_for_sast(self, issue: Dict, occurrence: Dict, file_content: Optional[str]) -> Dict:
        """Generate code fix for SAST vulnerability"""
        title = issue.get("title", "")
        file_path = occurrence.get("fileName", "")
        line_number = occurrence.get("lineNumber", 0)

        # Extract vulnerability type
        vuln_type = "UNKNOWN"
        if "SQL" in title.upper():
            vuln_type = "SQL_INJECTION"
        elif "XSS" in title.upper():
            vuln_type = "XSS"
        elif "DESERIALIZATION" in title.upper() or "DESERIALI" in title.upper():
            vuln_type = "UNSAFE_DESERIALIZATION"
        elif "PATH" in title.upper() and "TRAVERSAL" in title.upper():
            vuln_type = "PATH_TRAVERSAL"
        elif "COMMAND" in title.upper() and ("INJECTION" in title.upper() or "EXEC" in title.upper()):
            vuln_type = "COMMAND_INJECTION"
        elif "CRYPTO" in title.upper() or "WEAK" in title.upper():
            vuln_type = "WEAK_CRYPTO"

        code_fix = {
            "file_path": file_path,
            "patch": [],
            "additional_files_fetched": [],
            "context_symbols_analyzed": []
        }

        if not file_content:
            return code_fix

        lines = file_content.split('\n')
        if line_number <= 0 or line_number > len(lines):
            return code_fix

        # Get context around vulnerable line
        start_line = max(1, line_number - 3)
        end_line = min(len(lines), line_number + 3)

        original_code = '\n'.join(lines[start_line - 1:end_line])
        vulnerable_line = lines[line_number - 1] if line_number <= len(lines) else ""

        # Generate fix based on vulnerability type
        fixed_code = original_code
        change_desc = ""

        if vuln_type == "SQL_INJECTION":
            # Replace string concatenation with parameterized query
            if "fmt.Sprintf" in vulnerable_line or "+" in vulnerable_line:
                fixed_code = self.fix_sql_injection_go(lines, start_line - 1, end_line)
                change_desc = "Replaced string concatenation with parameterized query using database/sql placeholders"
            elif "format" in vulnerable_line or "%" in vulnerable_line:
                fixed_code = self.fix_sql_injection_python(lines, start_line - 1, end_line)
                change_desc = "Replaced string formatting with parameterized query"
            elif "`" in vulnerable_line or "${" in vulnerable_line:
                fixed_code = self.fix_sql_injection_js(lines, start_line - 1, end_line)
                change_desc = "Replaced template literals with parameterized query"

        elif vuln_type == "UNSAFE_DESERIALIZATION":
            if "pickle.load" in vulnerable_line or "yaml.load" in vulnerable_line:
                fixed_code = self.fix_unsafe_deserialization_python(lines, start_line - 1, end_line)
                change_desc = "Replaced unsafe deserialization with safe alternative"
            elif "unserialize" in vulnerable_line:
                fixed_code = self.fix_unsafe_deserialization_php(lines, start_line - 1, end_line)
                change_desc = "Added validation before deserialization"
            elif "JSON.parse" in vulnerable_line or "eval" in vulnerable_line:
                fixed_code = self.fix_unsafe_deserialization_js(lines, start_line - 1, end_line)
                change_desc = "Replaced unsafe JSON parsing or eval"

        elif vuln_type == "XSS":
            fixed_code = self.fix_xss(lines, start_line - 1, end_line, vulnerable_line)
            change_desc = "Added output encoding to prevent XSS"

        elif vuln_type == "PATH_TRAVERSAL":
            fixed_code = self.fix_path_traversal(lines, start_line - 1, end_line)
            change_desc = "Added path validation to prevent directory traversal"

        elif vuln_type == "COMMAND_INJECTION":
            fixed_code = self.fix_command_injection(lines, start_line - 1, end_line)
            change_desc = "Replaced command string with safe subprocess call"

        if fixed_code != original_code:
            code_fix["patch"].append({
                "start_line": start_line,
                "end_line": end_line,
                "original_code": original_code,
                "fixed_code": fixed_code,
                "change_description": change_desc
            })
            self.stats["code_fixes_generated"] += 1

        return code_fix

    def fix_sql_injection_go(self, lines: List[str], start: int, end: int) -> str:
        """Fix SQL injection in Go code"""
        result = []
        for i in range(start, end):
            line = lines[i]
            # Replace fmt.Sprintf with parameterized query
            if "fmt.Sprintf" in line and "SELECT" in line.upper():
                # Extract query and find variables
                if '"%s"' in line or "'%s'" in line:
                    line = re.sub(r'fmt\.Sprintf\("([^"]+)",\s*([^)]+)\)', r'"\1", \2', line)
                    line = line.replace('"%s"', '?').replace("'%s'", '?')
            # Replace db.Query with db.QueryRow for single result
            line = line.replace('db.Query(', 'db.QueryRow(')
            result.append(line)
        return '\n'.join(result)

    def fix_sql_injection_python(self, lines: List[str], start: int, end: int) -> str:
        """Fix SQL injection in Python code"""
        result = []
        for i in range(start, end):
            line = lines[i]
            # Replace % formatting or .format() with parameterized query
            if "%" in line and ("SELECT" in line.upper() or "query" in line.lower()):
                # Convert to parameterized query
                line = re.sub(r'["\']([^"\']*%s[^"\']*)["\']\s*%', r'"\1", ', line)
                line = line.replace('%s', '?')
            elif ".format(" in line:
                line = re.sub(r'\.format\([^)]+\)', '', line)
                line = line.replace('{}', '?')
            result.append(line)
        return '\n'.join(result)

    def fix_sql_injection_js(self, lines: List[str], start: int, end: int) -> str:
        """Fix SQL injection in JavaScript code"""
        result = []
        for i in range(start, end):
            line = lines[i]
            # Replace template literals with parameterized query
            if "`" in line and "${" in line:
                # Convert to prepared statement
                line = re.sub(r'`([^`]*)\$\{[^}]+\}([^`]*)`', r'"\1?\2"', line)
            result.append(line)
        return '\n'.join(result)

    def fix_unsafe_deserialization_python(self, lines: List[str], start: int, end: int) -> str:
        """Fix unsafe deserialization in Python"""
        result = []
        for i in range(start, end):
            line = lines[i]
            if "pickle.load" in line:
                line = line.replace("pickle.load", "json.load  # Changed from pickle to json for security")
            elif "yaml.load(" in line and "Loader=" not in line:
                line = line.replace("yaml.load(", "yaml.safe_load(")
            result.append(line)
        return '\n'.join(result)

    def fix_unsafe_deserialization_php(self, lines: List[str], start: int, end: int) -> str:
        """Fix unsafe deserialization in PHP"""
        result = []
        for i in range(start, end):
            line = lines[i]
            if "unserialize(" in line:
                # Add validation
                indent = len(line) - len(line.lstrip())
                result.append(" " * indent + "// Validate serialized data before unserializing")
                result.append(" " * indent + "if (!$this->isValidSerializedData($data)) {")
                result.append(" " * indent + "    throw new Exception('Invalid serialized data');")
                result.append(" " * indent + "}")
            result.append(line)
        return '\n'.join(result)

    def fix_unsafe_deserialization_js(self, lines: List[str], start: int, end: int) -> str:
        """Fix unsafe deserialization in JavaScript"""
        result = []
        for i in range(start, end):
            line = lines[i]
            if "eval(" in line:
                line = line.replace("eval(", "JSON.parse(  // Replaced eval with JSON.parse")
            result.append(line)
        return '\n'.join(result)

    def fix_xss(self, lines: List[str], start: int, end: int, vulnerable_line: str) -> str:
        """Fix XSS vulnerability"""
        result = []
        for i in range(start, end):
            line = lines[i]
            # Add encoding based on language
            if ".innerHTML" in line or "html(" in line:
                line = line.replace(".innerHTML", ".textContent  // Use textContent to prevent XSS")
                line = line.replace(".html(", ".text(  // Use .text() to prevent XSS in jQuery")
            elif "render_template_string" in line:
                line = line.replace("render_template_string(", "render_template_string(escape(")
            result.append(line)
        return '\n'.join(result)

    def fix_path_traversal(self, lines: List[str], start: int, end: int) -> str:
        """Fix path traversal vulnerability"""
        result = []
        for i in range(start, end):
            line = lines[i]
            if "os.path.join" in line or "path.join" in line:
                # Add validation
                indent = len(line) - len(line.lstrip())
                result.append(" " * indent + "# Validate path to prevent traversal")
                result.append(" " * indent + "if '..' in filename or filename.startswith('/'):")
                result.append(" " * indent + "    raise ValueError('Invalid filename')")
            result.append(line)
        return '\n'.join(result)

    def fix_command_injection(self, lines: List[str], start: int, end: int) -> str:
        """Fix command injection vulnerability"""
        result = []
        for i in range(start, end):
            line = lines[i]
            if "os.system(" in line or "subprocess.call(" in line:
                # Replace with safe subprocess
                line = line.replace("os.system(", "subprocess.run([")
                line = line.replace("subprocess.call(", "subprocess.run([")
                # Convert string command to list
                if '"' in line or "'" in line:
                    line = line.replace(" + ", '", "')
            result.append(line)
        return '\n'.join(result)

    def process_issue(self, issue: Dict) -> None:
        """Process a single issue"""
        issue_id = issue.get("id", "UNKNOWN")
        title = issue.get("title", "Untitled Issue")
        severity = issue.get("severity", "MEDIUM")
        issue_type = issue.get("issueType", "SAST")

        print(f"\n   📌 Processing issue: {issue_id}")
        print(f"      Title: {title[:80]}")
        print(f"      Severity: {severity} | Type: {issue_type}")

        # Group occurrences by file
        occurrences_by_file = {}
        for occ in issue.get("occurrences", []):
            file_path = occ.get("fileName", "")
            if file_path not in occurrences_by_file:
                occurrences_by_file[file_path] = []
            occurrences_by_file[file_path].append(occ)

        print(f"      Occurrences: {len(issue.get('occurrences', []))} across {len(occurrences_by_file)} files")

        # Process each file group
        code_fixes = []
        occurrences_output = []

        for file_path, occurrences in occurrences_by_file.items():
            print(f"      📄 Processing {file_path}...")

            # Fetch file content
            file_content = self.get_file_content(file_path)

            for occ in occurrences:
                line_number = occ.get("lineNumber", 0)
                occ_id = occ.get("occurrenceId", "unknown")

                # Generate fix based on issue type
                if issue_type.upper() in ["SAST", "SECURITY"]:
                    code_fix = self.generate_fix_for_sast(issue, occ, file_content)
                    if code_fix["patch"]:
                        code_fixes.append(code_fix)

                # Build occurrence output
                correction_context = f"Line {line_number}"
                if file_content:
                    context = self.extract_code_context(file_content, line_number, 2)
                    correction_context += f" - Context available"

                occurrences_output.append({
                    "occurrence_id": str(occ_id),
                    "file_path": file_path,
                    "line_number": line_number,
                    "details": occ.get("_raw", {}),
                    "correction_context": correction_context
                })

        # Store issue results
        self.output_data["issues"][issue_id] = {
            "title": title,
            "type": issue_type,
            "severity": str(severity),
            "code_fixes": code_fixes,
            "occurrences": occurrences_output,
            "github_issue_url": None  # Will be populated if GitHub issue created
        }

        print(f"      ✓ Generated {len(code_fixes)} code fixes")

    def process_all_issues(self) -> None:
        """Process all issues"""
        print(f"\n🔧 Step 2: Processing issues...")

        for i, issue in enumerate(self.input_data.get("issues", []), 1):
            print(f"\n   [{i}/{self.output_data['total_issues']}]", end="")
            self.process_issue(issue)

    def write_outputs(self) -> None:
        """Write all output files"""
        print(f"\n💾 Step 3: Writing output files...")

        # Write remediation report
        os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
        with open(OUTPUT_FILE, 'w') as f:
            json.dump(self.output_data, f, indent=2)
        print(f"   ✓ {OUTPUT_FILE}")

        # Write GitHub issues log
        with open(GITHUB_ISSUES_LOG, 'w') as f:
            json.dump(self.github_issues_log, f, indent=2)
        print(f"   ✓ {GITHUB_ISSUES_LOG}")

        # Generate PR automation file
        self.generate_pr_automation()

    def generate_pr_automation(self) -> None:
        """Generate PR automation file"""
        remediations = []

        for issue_id, issue_data in self.output_data["issues"].items():
            if not issue_data.get("code_fixes"):
                continue

            # Generate branch name
            title_slug = re.sub(r'[^a-z0-9]+', '-', issue_data["title"].lower())[:40].strip('-')
            branch_name = f"security/fix-{issue_id.lower()[:20]}-{title_slug}"

            # Build file changes
            file_changes = []
            for code_fix in issue_data["code_fixes"]:
                file_path = code_fix["file_path"]

                # Apply patches to get full file content
                full_file_after = self.apply_patches_to_file(
                    file_path,
                    code_fix["patch"]
                )

                if not full_file_after:
                    continue

                file_change = {
                    "file_path": file_path,
                    "action": "MODIFY",
                    "patches": code_fix["patch"],
                    "full_file_after_changes": full_file_after,
                    "verification_notes": f"Auto-generated fix for security vulnerability"
                }
                file_changes.append(file_change)

            if not file_changes:
                continue

            # Build remediation entry
            remediation = {
                "issue_id": issue_id,
                "severity": issue_data["severity"],
                "type": issue_data["type"],
                "title": issue_data["title"],
                "branch_name": branch_name,
                "commit_message": self.generate_commit_message(issue_id, issue_data, file_changes),
                "file_changes": file_changes,
                "pr_details": {
                    "title": f"[{issue_data['severity']}] Fix {issue_data['title'][:60]}",
                    "body": self.generate_pr_body(issue_id, issue_data, file_changes, branch_name),
                    "labels": ["security", "auto-remediation", str(issue_data["severity"]), issue_data["type"]],
                    "reviewers": ["security-team"],
                    "assignees": [],
                    "draft": False,
                    "auto_merge": False
                },
                "metadata": {
                    "occurrences_fixed": len(issue_data["occurrences"]),
                    "files_modified": len(file_changes),
                    "lines_changed": sum(
                        len(p["fixed_code"].split("\n"))
                        for fc in file_changes
                        for p in fc["patches"]
                    )
                }
            }
            remediations.append(remediation)

        # Write bare array for Agent 3
        with open(PR_AUTOMATION_FILE, 'w') as f:
            json.dump(remediations, f, indent=2)
        print(f"   ✓ {PR_AUTOMATION_FILE} ({len(remediations)} remediations)")

        # Write metadata separately
        metadata = {
            "generated_at": self.output_data["generated_at"],
            "source_file": INPUT_FILE,
            "repository": {
                "owner": GITHUB_REPO_OWNER,
                "repo": GITHUB_REPO_NAME,
                "base_branch": GITHUB_REPO_REF
            },
            "summary": {
                "total_remediations": len(remediations),
                "total_file_changes": sum(len(r["file_changes"]) for r in remediations)
            }
        }
        with open(PR_METADATA_FILE, 'w') as f:
            json.dump(metadata, f, indent=2)
        print(f"   ✓ {PR_METADATA_FILE}")

    def apply_patches_to_file(self, file_path: str, patches: List[Dict]) -> Optional[str]:
        """Apply patches to file and return full content"""
        # Read original file
        file_content = self.get_file_content(file_path)
        if not file_content:
            return None

        lines = file_content.split('\n')

        # Apply patches (bottom-up to preserve line numbers)
        for patch in sorted(patches, key=lambda p: p["start_line"], reverse=True):
            start = patch["start_line"] - 1
            end = patch["end_line"]
            lines[start:end] = patch["fixed_code"].split('\n')

        return '\n'.join(lines)

    def generate_commit_message(self, issue_id: str, issue_data: Dict, file_changes: List[Dict]) -> str:
        """Generate commit message"""
        subject = f"fix: {issue_data['title'][:50]}"
        body = f"""
{issue_data['title']}

Severity: {issue_data['severity']}
Type: {issue_data['type']}
Issue ID: {issue_id}

Changes:
{chr(10).join(f"- {fc['file_path']}: {len(fc['patches'])} patch(es)" for fc in file_changes)}

Auto-generated security fix from Harness Security Pipeline.

Co-authored-by: Harness Security Agent <security@harness.io>
"""
        return subject + body

    def generate_pr_body(self, issue_id: str, issue_data: Dict, file_changes: List[Dict], branch_name: str) -> str:
        """Generate PR body"""
        severity_badge = issue_data['severity']

        body = f"""## 🔒 Security Fix: {issue_data['title']}

### Summary
**{severity_badge}** {issue_data['type']} vulnerability

**Issue ID**: `{issue_id}`
**Occurrences Fixed**: {len(issue_data['occurrences'])}
**Files Modified**: {len(file_changes)}

---

### Vulnerability Details

"""

        for occ in issue_data["occurrences"]:
            body += f"- **{occ['file_path']}:{occ['line_number']}**\n"
            body += f"  - {occ.get('correction_context', 'See changes below')}\n\n"

        body += "---\n\n### Changes Made\n\n"

        for fc in file_changes:
            body += f"#### `{fc['file_path']}`\n\n"
            for patch in fc["patches"]:
                body += f"**Lines {patch['start_line']}-{patch['end_line']}**\n\n"
                body += "**Before**:\n```\n" + patch["original_code"] + "\n```\n\n"
                body += "**After**:\n```\n" + patch["fixed_code"] + "\n```\n\n"
                if patch.get("change_description"):
                    body += f"*{patch['change_description']}*\n\n"

        body += f"""---

### Testing Checklist
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Security scan confirms vulnerability resolved
- [ ] Manual testing completed

---

**Generated by**: Harness Remediation Agent v2.0
**Branch**: `{branch_name}`
**Pipeline**: {os.environ.get('HARNESS_PROJECT_ID', 'N/A')}

⚠️ **This is an auto-generated security fix. Please review carefully before merging.**
"""
        return body

    def print_summary(self) -> None:
        """Print final summary"""
        print(f"""
{'='*80}
REMEDIATION AGENT - EXECUTION COMPLETE
{'='*80}

📊 Processing Summary:
   - Total issues processed: {self.output_data['total_issues']}
   - Total occurrences processed: {self.output_data['total_occurrences']}
   - Total files fetched: {self.stats['files_fetched']}
   - Total code fixes generated: {self.stats['code_fixes_generated']}

📁 Output Files:
   ✓ {OUTPUT_FILE}
   ✓ {GITHUB_ISSUES_LOG}
   ✓ {PR_AUTOMATION_FILE}
   ✓ {PR_METADATA_FILE}

🔧 Repository:
   - Owner: {GITHUB_REPO_OWNER}
   - Repo: {GITHUB_REPO_NAME}
   - Branch: {GITHUB_REPO_REF}

✅ Next Steps:
   1. Review remediation_report.json for audit trail
   2. Run Agent 3 (PR Creation) using github-remediate.json
   3. Review and merge security PRs

{'='*80}
""")

    def run(self) -> int:
        """Main execution flow"""
        print(f"""
{'='*80}
HARNESS REMEDIATION AGENT - STARTING
{'='*80}
""")

        if not self.load_input():
            self.write_empty_outputs()
            return 0

        self.process_all_issues()
        self.write_outputs()
        self.print_summary()

        return 0

    def write_empty_outputs(self) -> None:
        """Write empty output files if no issues to process"""
        os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

        with open(OUTPUT_FILE, 'w') as f:
            json.dump(self.output_data, f, indent=2)

        with open(GITHUB_ISSUES_LOG, 'w') as f:
            json.dump(self.github_issues_log, f, indent=2)

        with open(PR_AUTOMATION_FILE, 'w') as f:
            json.dump([], f, indent=2)

        print(f"\n   ✓ Written empty output files")


if __name__ == "__main__":
    agent = RemediationAgent()
    sys.exit(agent.run())
