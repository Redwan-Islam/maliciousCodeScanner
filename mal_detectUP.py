import tkinter as tk
from tkinter import messagebox, ttk
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
import requests
import os
import re
import logging
import subprocess
import base64
import cProfile
import pstats
import io

# Set up logging
logging.basicConfig(filename='error_log.txt', level=logging.ERROR)

def contains_malicious_patterns(file_content):
    """Check for malicious patterns in the file content and return matches."""
    malicious_patterns = {
        r"os\.system\(": "Using os.system can allow execution of arbitrary commands, leading to potential system compromise.",
        r"subprocess\.run\(": "Using subprocess.run can allow execution of shell commands, leading to potential vulnerabilities.",
        r"eval\(": "Using eval can execute arbitrary code, which can be exploited by attackers.",
        r"exec\(": "Using exec can execute arbitrary code, which can be exploited by attackers.",
        r"open\(": "Using open can expose sensitive files if not handled properly.",
        r"with open\(": "Using 'with open' can expose sensitive files if not handled properly.",
        r"pickle\.load\(": "Using pickle.load can lead to arbitrary code execution if untrusted data is deserialized.",
        r"import os": "Importing os can expose system-level operations that may be exploited.",
        r"import subprocess": "Importing subprocess can allow execution of shell commands, leading to potential vulnerabilities.",
        r"document\.write\(": "Using document.write can lead to XSS vulnerabilities if user input is not sanitized.",
        r"innerHTML": "Using innerHTML can lead to XSS vulnerabilities if user input is not sanitized.",
        r"SQL.*\(\s*['\"]\w+['\"]\s*\+\s*input": "Unsanitized input in SQL queries can lead to SQL injection vulnerabilities.",
        r"setTimeout\(": "Using setTimeout can lead to timing attacks if not handled properly.",
        r"setInterval\(": "Using setInterval can lead to performance issues and potential DoS attacks.",
        r"strcpy\(": "Using strcpy can lead to buffer overflow vulnerabilities.",
        r"strcat\(": "Using strcat can lead to buffer overflow vulnerabilities.",
        r"fopen\(": "Using fopen without proper validation can expose sensitive files.",
        r"system\(": "Using system can allow execution of arbitrary commands, leading to potential system compromise.",
        r"shell_exec\(": "Using shell_exec can allow execution of arbitrary shell commands.",
        r"passthru\(": "Using passthru can allow execution of arbitrary commands, leading to potential system compromise.",
        r"curl\(": "Using curl without validation can lead to remote code execution or data leaks.",
        r"file_get_contents\(": "Using file_get_contents can expose sensitive files if not handled properly.",
        r"exec\(": "Using exec can execute arbitrary code, which can be exploited by attackers.",
        r"system\(": "Using system can allow execution of arbitrary commands, leading to potential system compromise.",
        r"eval\(": "Using eval can execute arbitrary code, which can be exploited by attackers.",
        r"request\(": "Using request without validation can lead to SSRF vulnerabilities.",
        r"XMLHttpRequest\(": "Using XMLHttpRequest can lead to XSS vulnerabilities if not handled properly.",
        r"fetch\(": "Using fetch without validation can lead to XSS vulnerabilities if user input is not sanitized.",
        r"window\.open\(": "Using window.open can lead to phishing attacks if not handled properly.",
        r"document\.cookie": "Manipulating document.cookie can lead to session hijacking.",
        r"localStorage": "Using localStorage can lead to XSS vulnerabilities if not handled properly.",
        r"sessionStorage": "Using sessionStorage can lead to XSS vulnerabilities if not handled properly.",
        r"window\.location": "Manipulating window.location can lead to open redirects or phishing attacks.",
        r"setInterval\(": "Using setInterval can lead to performance issues and potential DoS attacks.",
        r"setTimeout\(": "Using setTimeout can lead to timing attacks if not handled properly.",
        r"fetch\(": "Using fetch without validation can lead to XSS vulnerabilities if user input is not sanitized.",
        r"XMLHttpRequest\(": "Using XMLHttpRequest can lead to XSS vulnerabilities if not handled properly.",
        r"document\.write\(": "Using document.write can lead to XSS vulnerabilities if user input is not sanitized.",
        r"innerHTML": "Using innerHTML can lead to XSS vulnerabilities if user input is not sanitized.",
        r"window\.open\(": "Using window.open can lead to phishing attacks if not handled properly.",
        r"document\.cookie": "Manipulating document.cookie can lead to session hijacking.",
        r"localStorage": "Using localStorage can lead to XSS vulnerabilities if not handled properly.",
        r"sessionStorage": "Using sessionStorage can lead to XSS vulnerabilities if not handled properly.",
        r"window\.location": "Manipulating window.location can lead to open redirects or phishing attacks.",
        r"setInterval\(": "Using setInterval can lead to performance issues and potential DoS attacks.",
        r"setTimeout\(": "Using setTimeout can lead to timing attacks if not handled properly.",
        r"request\(": "Using request without validation can lead to SSRF vulnerabilities.",
    }
    
    matches = []
    for pattern, explanation in malicious_patterns.items():
        for line_number, line in enumerate(file_content.splitlines(), start=1):
            if re.search(pattern, line):
                matches.append((line_number, line, explanation))
    return matches

def wrap_text(text, max_length=50):
    """Wrap text to fit within a specified maximum length."""
    words = text.split()
    wrapped_lines = []
    current_line = ""

    for word in words:
        if len(current_line) + len(word) + 1 > max_length:
            wrapped_lines.append(current_line)
            current_line = word
        else:
            current_line += " " + word if current_line else word

    if current_line:
        wrapped_lines.append(current_line)

    return "\n".join(wrapped_lines)

def create_pdf_report(url, repo_owner, scan_time, malicious_details, threat_level, programming_languages, functionality_description):
    """Create a PDF report of the scan results."""
    pdf_filename = "Generic_report.pdf"
    
    # Check if the file already exists and create a new name if necessary
    counter = 1
    while os.path.exists(pdf_filename):
        pdf_filename = f"Generic_report_{counter}.pdf"
        counter += 1

    try:
        doc = SimpleDocTemplate(pdf_filename, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72)
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(name='TitleStyle', fontSize=18, textColor=colors.blue, spaceAfter=6)
        body_style = ParagraphStyle(name='BodyStyle', fontSize=12, textColor=colors.black, spaceAfter=6)

        content = []

        content.append(Paragraph("Generic Report for GitHub Repository Scan", title_style))
        content.append(Spacer(1, 12))  # Space after title

        # Create a table for the report summary
        data = [
            ["Field", "Details"],
            ["Repository Owner", wrap_text(repo_owner)],
            ["Repository Link", wrap_text(url)],
            ["Scan Time", wrap_text(scan_time)],
            ["Threat Level", wrap_text(threat_level)],
            ["Programming Languages", wrap_text(programming_languages)],
            ["Functionality Description", wrap_text(functionality_description)],
        ]

        # Create the table with specified column widths
        table = Table(data, colWidths=[150, 300])  # Adjust widths as necessary
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.blue),  # Header background color
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),  # Header text color
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),  # Align text to the left
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),  # Header font
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),  # Body font
            ('SIZE ', (0, 0), (-1, 0), 12),  # Header font size
            ('SIZE', (0, 1), (-1, -1), 10),  # Body font size
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),  # Padding for header
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),  # Body background color
            ('GRID', (0, 0), (-1, -1), 1, colors.black),  # Grid lines
        ]))

        content.append(table)
        content.append(Spacer(1, 12))  # Space after table

        # Add malicious code details
        if malicious_details:
            content.append(Paragraph("Malicious Code Details:", title_style))
            content.append(Spacer(1, 12))
            for line_number, line, explanation in malicious_details:
                content.append(Paragraph(f"Line {line_number}: {line}", body_style))
                content.append(Paragraph(f"Potential Issue: {explanation}", body_style))
                content.append(Spacer(1, 6))  # Space between entries

        # Add credit statement
        credit_statement = Paragraph("Report and coding done by ~ Fuad Sarker ~", body_style)
        content.append(Spacer(1, 12))  # Space before credit
        content.append(credit_statement)

        doc.build(content)
        
        return pdf_filename, "PDF report created successfully!"
    
    except Exception as e:
        logging.error(f"Error creating PDF: {e}")
        return None, "Failed to create PDF report."

def scan_repository(url):
    """Scan the specified GitHub repository for malicious code."""
    if not url.startswith("https://github.com/"):
        return "Invalid GitHub URL. Please enter a valid repository link.", None

    repo_name = url.split("github.com/")[-1]
    api_url = f"https://api.github.com/repos/{repo_name}/git/trees/main?recursive=1"

    try:
        response = requests.get(api_url)
        response.raise_for_status()
        contents = response.json().get('tree', [])

        malicious_details = []
        threat_level = "Low"  # Default threat level

        for item in contents:
            if item['type'] == 'blob' and item['path'].endswith(('.py', '.js', '.php', '.rb', '.sh', '.txt', '.html')):
                # Fetch the file content
                file_content_response = requests.get(item['url']).json()
                file_content_base64 = file_content_response['content']
                
                # Decode the base64 content
                file_content = base64.b64decode(file_content_base64).decode('utf-8')
                file_name = item['path']
                print(f"Scanning file: {file_name}")  # Debugging line

                # Check for malicious patterns
                matches = contains_malicious_patterns(file_content)
                if matches:
                    print(f"Malicious code detected in {file_name}")  # Debugging line
                    malicious_details.extend(matches)
                    threat_level = "High"  # Update threat level if malicious code is found

        # Generate PDF report
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        functionality_description = "perform various data processing tasks"  # Example description
        pdf_filename, pdf_alert = create_pdf_report(url, repo_name, scan_time, malicious_details, threat_level, "Python", functionality_description)

        # Alert messages
        if malicious_details:
            return "Alert: Malicious code found!", pdf_alert
        else:
            return "Alert: No malicious code found.", pdf_alert
        
    except requests.exceptions.HTTPError as http_err:
        return f"HTTP error occurred: {http_err}", None
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return f"An error occurred: {e}", None

def scan_repository_gui():
    """Handle the GUI interaction for scanning a repository."""
    url = url_entry.get()
    if not url:
        messagebox.showwarning("Input Error", "Please enter a GitHub repository URL.")
        return
    
    # Call the scan_repository function
    alert, pdf_alert = scan_repository(url)
    messagebox.showinfo("Scan Result", alert)
    if pdf_alert:
        messagebox.showinfo("PDF Report", pdf_alert)

# Create the main window
root = tk.Tk()
root.title("GitHub Repository Scanner")
root.geometry("600x400")
root.configure(bg="#f0f0f0")

# Create a stylish frame
frame = ttk.Frame(root, padding="20")
frame.pack(fill=tk.BOTH, expand=True)

# Title label
title_label = ttk.Label(frame, text="GitHub Repository Scanner", font=("Helvetica", 16, "bold"), foreground="#007ACC")
title_label.pack(pady=(0, 10))

# URL entry
url_label = ttk.Label(frame, text="Enter GitHub Repository URL:", font=("Helvetica", 12))
url_label.pack(anchor=tk.W, pady=(0, 10))  # Added space after label
url_entry = ttk.Entry(frame, width=50, font=("Helvetica", 12))
url_entry.pack(pady=(0, 10))

# Scan button with color
scan_button = ttk.Button(frame, text="Scan Repository", command=scan_repository_gui)
scan_button.pack(pady=(0, 20))
scan_button.configure(style="TButton")  # Apply style to button

# Create a style for the button
style = ttk.Style()
style.configure("TButton", background="blue", foreground="black", font=("Helvetica", 12, "bold"))
style.map("TButton", background=[("active", "#005FA3")])  # Change color on hover

# Footer
footer_label = ttk.Label(frame, text="", font=("Helvetica", 10), foreground="#888888")
footer_label.pack(side=tk.BOTTOM, pady=(10, 0))

# Start the GUI event loop
root.mainloop()