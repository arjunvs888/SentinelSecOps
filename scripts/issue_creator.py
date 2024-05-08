# Needed JSON Tags of a vulnerability
# vulnerabilities

# 
# Vulnerability name
# Location
# Description
# Severity
# Identifier
# Status
# Solution

import json
import gitlab
import os
import sys

snyk_report = 'snyk_report.json'
zap_report = 'zap_report.json'
trivy_report = 'gl-container-scanning-report.json'
vulnerability_data = {
    "snyk": [],
    "trivy": [],
    "zap": []
}
terminator = False
html_content =f""" """
# # Construct issue description
def create_snyk_issue_data(vulnerability):
    # Ensure uppercase severity and append "SEVERITY" text
    severity = vulnerability["severity"].upper() + " SEVERITY"
    # Format the package manager information
    package_manager = f"**Package Manager**: _{vulnerability.get('packageManager', 'N/A')}_"
    # Format the vulnerable module information
    vulnerable_module = f"**Vulnerable module**: _{vulnerability.get('name', 'N/A')}_"
    # Format the version information
    version = f"**Version**: _`{vulnerability.get('version', 'N/A')}`_"
    # Format the introduction source of the vulnerability
    introduced_through_raw = "N/A" if 'from' not in vulnerability else ', '.join([f"`{item}`" for item in vulnerability['from']])
    introduced_through = f"**Introduced through**: _[{introduced_through_raw}]_"
    # Process the description to replace double newlines with single ones and strip trailing spaces
    description = vulnerability.get("description", "").replace("\n\n", "\n").strip()
    # Concatenate the parts to form the full issue description text

    # Append the Snyk vulnerability to the 'snyk' list
    snyk_vulnerability = {"severity": severity,
        "package_manager": vulnerability.get('packageManager', 'N/A'),
        "vulnerable_module": vulnerability.get('name', 'N/A'),
        "version": vulnerability.get('version', 'N/A'),
        "introduced_through": introduced_through_raw}
    vulnerability_data["snyk"].append(snyk_vulnerability)

    report_text = f"**Severity**: `{severity}`\n\n" \
                f"{package_manager}\n\n" \
                f"{vulnerable_module}\n\n" \
                f"{version}\n\n" \
                f"{introduced_through}\n\n" \
                f"## Overview\n\n" \
                f"{description}"
    
    return report_text
def create_trivy_issue_data(vulnerability):
        name = vulnerability.get('name', 'N/A')
        description = vulnerability.get('description', 'N/A').replace('\n', ' ').strip()
        severity = vulnerability.get('severity', 'N/A').upper() + " SEVERITY"
        vulnerable_module = vulnerability.get('location', {}).get('dependency', {}).get('package', {}).get('name', 'N/A')
        version = vulnerability.get('location', {}).get('dependency', {}).get('version', 'N/A')
        operating_system = vulnerability.get('location', {}).get('operating_system', 'Unknown')
        image = vulnerability.get('location', {}).get('image', 'N/A')

        solution = vulnerability.get('solution', 'No solution provided')

        # Extract URLs
        urls = [link['url'] for link in vulnerability.get('links', []) if 'url' in link]
        # Formatting URLs
        links_markdown = '\n'.join([f"- [{url}]({url})" for url in urls])

        vulnerability_data["trivy"].append(
            {"name": name,
            "description": description,
            "severity": severity,
            "vulnerable_module": vulnerable_module,
            "version": version,
            "operating_system": operating_system,
            "image": image,
            "solution": solution,
            "urls": urls})

        # Concatenate the parts to form the full issue description text in Markdown
        report_text = f"**Severity**: `{severity}`\n\n" \
                    f"_{name}_\n\n" \
                    f"**Vulnerable Module**: _{vulnerable_module}_\n\n" \
                    f"**Version**: _`{version}`_\n\n" \
                    f"**Operating System**: _`{operating_system}`_\n\n" \
                    f"**Image**: _`{image}`_\n\n" \
                    f"## Overview\n\n" \
                    f"{description}\n\n" \
                    f"## Solution\n\n" \
                    f"{solution}\n\n" \
                    f"## References\n\n" \
                    f"{links_markdown}"
        # print(report_text)
        # print('-' * 80)  # Print a separator line
        return report_text
def create_zap_issue_data(alert):
    name = alert.get('name', 'N/A')
    description = alert.get('desc', 'N/A').replace('\n', ' ').strip()
    # Split the riskdesc by spaces and take the first element, then append "SEVERITY"
    severity = alert.get('riskdesc', 'N/A').split(' ')[0].upper() + " SEVERITY"
    solution = alert.get('solution', 'No solution provided').replace('\n', ' ').strip()
    other_info = alert.get('otherinfo', 'No additional information provided').replace('\n', ' ').strip()
    references = alert.get('reference', 'No references provided').replace('\u003Cp\u003E', '').replace('\u003C/p\u003E', '\n').strip()
    alert_zap_url = f"https://www.zaproxy.org/docs/alerts/{alert.get('alertRef', 'N/A')}/"

    vulnerability_data["zap"].append(
        {"name": name,
        "description": description,
        "severity": severity,
        "other_info": other_info,
        "references": references,
        "solution": solution,
        "alert_zap_url": alert_zap_url})
    # Concatenate the parts to form the full issue description text in Markdown
    report_text = f"**Severity**: `{severity}`\n\n" \
                f"## Overview\n\n" \
                f"{description}\n\n" \
                f"## Solution\n\n" \
                f"{solution}\n\n" \
                f"## Additional Information\n\n" \
                f"{other_info}\n\n" \
                f"## References\n\n" \
                f"{references}\n\n" \
                f"## ZAP Alert URL\n\n" \
                f"- [ZAP Alert Details]({alert_zap_url})"
    # print (report_text)      
    return report_text
def create_issue(title, description, severity, label):

    # Issue data
    issue_data = {
        'title': title,
        'description': description,
        'labels':[severity, label]
    }
    gl = gitlab.Gitlab(os.environ['CI_SERVER_URL'], private_token=os.environ['PYTHON_SCRIPT_PAT'])
    gl.auth()
    project = gl.projects.get(os.environ['CI_PROJECT_ID'])
    project.issues.create(issue_data)
    print("Issue Created Successfully")
    
def delete_all_issues():
    gl = gitlab.Gitlab(os.environ['CI_SERVER_URL'], private_token=os.environ['PYTHON_SCRIPT_PAT'])
    gl.auth()
    project = gl.projects.get(os.environ['CI_PROJECT_ID'])
    # List all issues for the project
    issues = project.issues.list(all=True)
    # Iterate over the issues to delete them
    for issue in issues:
        print(f"Deleting issue ID: {issue.iid}")
        issue.delete()

    # Verify deletion by attempting to list issues again
    issues_after_deletion = project.issues.list(all=True)
    if not issues_after_deletion:
        print("All issues have been successfully deleted.")
    else:
        print(f"There are still {len(issues_after_deletion)} issues left.")

def process_vulnerability(vulnerability, label):
    """
    Processes a single vulnerability to create an issue.
    """
    global html_content
    global terminator
    # Check the label value and call the appropriate function
    if label == "Trivy":
        description = create_trivy_issue_data(vulnerability)
        title = f"{vulnerability['id']}"
        severity = "Severity:" + vulnerability['severity'].capitalize()
        html_content +=f""" 
    <li class="vulnerability-item">
        <h4>{title}</h4>
        <h5>{vulnerability_data["trivy"][0]["name"]}</h5>
        <h5>{vulnerability_data["trivy"][0]["severity"]}</h5>
        <p><strong>Vulnerable Module:</strong> {vulnerability_data["trivy"][0]["vulnerable_module"]}<br>
        <strong>Version:</strong> {vulnerability_data["trivy"][0]["version"]}<br>
        <strong>Operating System:</strong> {vulnerability_data["trivy"][0]["operating_system"]}<br>
        <strong>Image:</strong> {vulnerability_data["trivy"][0]["image"]}<br>
        <strong>Overview:</strong>{vulnerability_data["trivy"][0]["description"]}</p>
        <p><strong>Solution:</strong> {vulnerability_data["trivy"][0]["solution"]}</p></li>"""

    elif label == "Snyk":
        description = create_snyk_issue_data(vulnerability)
        title = f"{vulnerability['title']}/{vulnerability['name']}"
        severity = "Severity:" + vulnerability['severity'].capitalize()
        
        html_content +=f""" 
    <li class="vulnerability-item">
        <h4>{title}</h4>
        <p><strong>Severity:</strong> {severity}</p>
        <p><strong>Package Manager:</strong> {vulnerability_data["snyk"][0]["package_manager"]}</p>
        <p><strong>Vulnerable Module:</strong> {vulnerability_data["snyk"][0]["vulnerable_module"]}</p>
        <p><strong>Version:</strong> {vulnerability_data["snyk"][0]["version"]}</p>
        <p><strong>Introduced through:</strong> {vulnerability_data["snyk"][0]["introduced_through"]}</p>
    </li> """
        
    elif label == "ZAP":
        title = f"{vulnerability['name']}"
        description = create_zap_issue_data(vulnerability)
        severity = "Severity:" + vulnerability['riskdesc'].split(' ')[0].capitalize()
        html_content+=f"""
        <li class="vulnerability-item">
                <h4>{vulnerability_data["zap"][0]["name"]}</h4>
                <p><strong>{severity}</strong></p>
                <p><strong>Overview:</strong> {vulnerability_data["zap"][0]["description"]}</p>
                <p><strong>Solution:</strong> {vulnerability_data["zap"][0]["solution"]}</p>
                <p><strong>Additional Information:</strong> {vulnerability_data["zap"][0]["other_info"]}</p>
                <p><strong><a href="{vulnerability_data["zap"][0]["alert_zap_url"]}">ZAP Alert URL</a></strong> </p>
            </li>
                """

    else:
        print(f"Unknown label: {label}")
        return  # Exit the function if the label is unknown type
    if severity in ['Severity:Critical','Severity:High']:
        terminator = True
    else:
        terminator = False
    print(title + '/ ' + severity)
    
    create_issue(title, description, severity, label)

def create_snyk_issues():
    ########################SNYK-Create Issues##################################################
    # Load JSON data from file
    try:
        with open(snyk_report) as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Snyk Scan Report not found. Exiting the function...")
        return  # Exit the function if file is not found
    print("Adding vulnerabilities detected by Snyk as issues to GitLab...")
    vulnerabilities = data['vulnerabilities']
    applications = data['applications']
    label = 'Snyk'
    for app in applications:
        for vulnerability in app['vulnerabilities']:  # Iterate over each 'vulnerabilities' list in each application
            process_vulnerability(vulnerability, label)

    for vulnerability in vulnerabilities:
        process_vulnerability(vulnerability, label)

    print("Processing Snyk Report finished...")
    ########################SNYK-Create Issues##################################################

def create_trivy_issues():
    ########################TRIVY-Create Issues##################################################
        # Load JSON data from file

    try:
        with open(trivy_report) as f:
            data = json.load(f)
            vulnerabilities = data['vulnerabilities']

    except FileNotFoundError:
        print(f"Trivy Scan Report not found. Exiting the function...")
        return  # Exit the function if file is not found
    print("Adding vulnerabilities detected by Trivy as issues to GitLab...")

    label = 'Trivy'
    for vulnerability in vulnerabilities:
        # Extract the required information
        process_vulnerability(vulnerability, label)
        print("Processing Trivy Report finished...")

    ########################TRIVY-Create Issues##################################################

def create_zap_issues():
    ########################ZAP-Create Issues##################################################
    # Load JSON data from file

    try:
        with open(zap_report) as f:
            data = json.load(f)
            sites = data['site']

    except FileNotFoundError:
        print(f"ZAP Scan Report not found. Exiting the function...")
        return  # Exit the function if file is not found
    print("Adding vulnerabilities detected by ZAP as issues to GitLab...")

    label = 'ZAP'
    for site in sites:
        for alert in site['alerts']:
            process_vulnerability(alert, label)
    print("Processing ZAP Report finished...")

    ########################ZAP-Create Issues##################################################



html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Enhanced Vulnerability Audit Report</title>
<style>
body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; }}
.container {{ max-width: 960px; margin: auto; background-color: #fff; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }}
header {{ background: #005792; color: #fff; padding: 20px 40px; text-align: center; }}
header h1 {{ margin: 0; }}
.section {{ padding: 20px 40px; border-bottom: 1px solid #eeeeee; }}
.section:last-child {{ border-bottom: none; }}
.section h2 {{ color: #005792; margin-top: 0; }}
.vulnerability-list {{ list-style-type: none; padding: 0; }}
.vulnerability-item {{ background-color: #f9f9f9; margin: 10px 0; padding: 10px; border-left: 5px solid #005792; }}
.vulnerability-item h3 {{ margin-top: 0; }}
.recommendation {{ background-color: #e3f2fd; padding: 10px; margin: 10px 0; border-left: 5px solid #007bff; }}
.tool-section {{ margin-bottom: 20px; }}

/* Snyk Findings Style */
.snyk-section .vulnerability-item {{
    border-left-color: #330066; 
}}
/* Trivy Findings Style */
.trivy-section .vulnerability-item {{
    border-left-color: #c21e56; 
}}

/* ZAP Findings Style */
.zap-section .vulnerability-item {{
    border-left-color: #36454f; 
}}

</style>
</head>
<body>
<div class="container">
<header>
    <h1>SentinelSecOps Vulnerability Audit Report</h1>
    <p>Report Date: 
"""
date = os.environ['CI_JOB_STARTED_AT']
# date = '2024-04-04'
html_content +=date
html_content +=f""" </p>
</header>

<div class="section overview">
<h2>Overview</h2>
<p>This enhanced report summarizes the vulnerabilities identified across various systems by Snyk, Trivy, and ZAP. Detailed findings follow.</p>
</div>
<div class="section">
<h2>Findings</h2>
<!-- Snyk Findings -->
<div class="tool-section snyk-section">
<h3>Snyk Findings</h3> <ul class="vulnerability-list">"""

delete_all_issues()
create_snyk_issues()
html_content +=f"""</ul></div>"""
html_content+=f"""
<div class="tool-section trivy-section">
    <h3>Trivy Findings</h3>
    <ul class="vulnerability-list">"""
create_trivy_issues()
html_content +=f"""</ul></div>"""

html_content+=f"""<div class="tool-section zap-section">
    <h3>ZAP Findings</h3>
    <ul class="vulnerability-list">"""

create_zap_issues()

html_content +=f"""</ul></div></div></div></body></html>"""

# Save the HTML content to a file
with open('enhanced_vulnerability_assessment_report.html', 'w', encoding='utf-8') as file:
    file.write(html_content)

print("HTML report generated successfully.")

if terminator:
    print("Terminator is set to True. Exiting with code 1.")
    sys.exit(1)
else:
        print("No Critical or High Severity Vulnerabilities detected.")

