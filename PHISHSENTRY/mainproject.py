#main Final Code for the python
import sys
import os
os.environ["QT_QUICK_BACKEND"] = "software"
os.environ["LIBGL_ALWAYS_SOFTWARE"] = "1"

from emailret import get_email_credentials, fetch_emails
from phishing_detector import detect_suspicious_urls, calculate_phishing_score, analyze_attachments
from visual import get_virustotal_api_key, scan_url
from report import generate_report_json, generate_report_csv

from PyQt5.QtWidgets import (
    QApplication, QWidget, QTabWidget, QVBoxLayout, QLabel,
    QPushButton, QTextEdit, QListWidget, QFileDialog, QLineEdit,
    QDialog, QFormLayout, QMessageBox
)
from PyQt5.QtGui import QTextCursor
from PyQt5.QtCore import Qt


class CredentialDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔐 Enter Credentials")
        self.setGeometry(200, 200, 400, 200)
        layout = QFormLayout()

        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Enter Email")
        layout.addRow("Email:", self.email_input)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter App Password")
        layout.addRow("Password:", self.password_input)

        self.api_key_input = QLineEdit()
        self.api_key_input.setEchoMode(QLineEdit.Password)
        self.api_key_input.setPlaceholderText("Enter VirusTotal API Key")
        layout.addRow("VirusTotal API Key:", self.api_key_input)

        self.submit_button = QPushButton("Submit")
        self.submit_button.clicked.connect(self.accept)
        layout.addWidget(self.submit_button)
        self.setLayout(layout)

    def get_credentials(self):
        return (
            self.email_input.text(),
            self.password_input.text(),
            self.api_key_input.text()
        )


class EmailScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PhishSentry - Advanced Email Scanner")
        self.setGeometry(100, 100, 1000, 600)

        self.email_user, self.email_pass, self.api_key = self.get_credentials()
        self.imap_server = "imap.gmail.com"
        self.emails = fetch_emails(self.email_user, self.email_pass, self.imap_server)

        self.init_ui()

    def get_credentials(self):
        dialog = CredentialDialog()
        if dialog.exec_() == QDialog.Accepted:
            return dialog.get_credentials()
        else:
            sys.exit()

    def init_ui(self):
        layout = QVBoxLayout()
        self.tabs = QTabWidget()

        self.tab_emails = QWidget()
        self.tab_analysis = QWidget()

        self.tabs.addTab(self.tab_emails, "📧 Emails")
        self.tabs.addTab(self.tab_analysis, "🔍 Phishing Analysis")

        layout.addWidget(self.tabs)
        self.setLayout(layout)

        self.init_tab_emails()
        self.init_tab_analysis()

    def init_tab_emails(self):
        layout = QVBoxLayout()
        label = QLabel("📬 Select one or more emails to analyze:")
        label.setStyleSheet("font-weight: bold; font-size: 16px;")

        self.email_list = QListWidget()
        self.email_list.setSelectionMode(QListWidget.MultiSelection)

        if self.emails:
            for email in self.emails:
                self.email_list.addItem(f"From: {email['from']} | Subject: {email['subject']}")
        else:
            self.email_list.addItem("No emails retrieved.")

        layout.addWidget(label)
        layout.addWidget(self.email_list)
        self.tab_emails.setLayout(layout)

    def init_tab_analysis(self):
        layout = QVBoxLayout()

        label = QLabel("🧠 Phishing Analysis Summary")
        label.setStyleSheet("font-weight: bold; font-size: 16px;")

        self.analysis_output = QTextEdit()
        self.analysis_output.setReadOnly(True)
        self.analysis_output.setStyleSheet("background-color: #1e1e1e; color: #ffffff; padding: 10px;")

        self.status_label = QLabel("Waiting to scan...")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("font-weight: bold; font-size: 14px; padding: 10px;")

        self.btn_analyze = QPushButton("🔍 Analyze Selected Emails")
        self.btn_analyze.clicked.connect(self.perform_analysis)

        self.btn_export_json = QPushButton("💾 Export Report (JSON)")
        self.btn_export_json.clicked.connect(self.export_json)

        self.btn_export_csv = QPushButton("📁 Export Report (CSV)")
        self.btn_export_csv.clicked.connect(self.export_csv)

        layout.addWidget(label)
        layout.addWidget(self.status_label)
        layout.addWidget(self.analysis_output)
        layout.addWidget(self.btn_analyze)
        layout.addWidget(self.btn_export_json)
        layout.addWidget(self.btn_export_csv)

        self.tab_analysis.setLayout(layout)

    def perform_analysis(self):
        selected = self.email_list.selectedIndexes()
        if not selected:
            self.status_label.setText("⚠ No email selected.")
            return

        self.status_label.setText("🔄 Scanning selected emails... Please wait...")
        self.analysis_output.setText("")
        QApplication.processEvents()

        full_text = ""
        for idx in selected:
            email = self.emails[idx.row()]
            urls = detect_suspicious_urls(email["body"])
            phishing_score = calculate_phishing_score(email["body"])
            attachments = analyze_attachments(email.get("attachments", []))

            email["phishing_score"] = phishing_score
            email["urls"] = urls

            # Score reasoning
            score_reason = "Low risk. Message likely safe." if phishing_score == 0 else (
                "Some suspicious patterns detected." if phishing_score <= 5 else "High risk! Likely phishing.")

            # Start block
            html = f"""
            <div style='margin-bottom: 24px; line-height: 1.6; padding: 10px; border: 1px solid #444; background-color: #111;'>
            <b>📧 Subject:</b> {email['subject']}<br>
            <b>From:</b> {email['from']}<br>
            <b>Phishing Score:</b> <span style='color:{"red" if phishing_score > 5 else "orange" if phishing_score else "lightgreen"}; font-weight:bold;'>{phishing_score}</span> - {score_reason}<br>
            <hr>
            """

            if urls:
                html += "<b style='color:#ff8888;'>⚠ Suspicious URLs:</b><br>"
                for url in urls:
                    html += f"&nbsp;&nbsp;- {url}<br>"
            else:
                html += "✅ <span style='color:lightgreen;'>No suspicious URLs found.</span><br>"

            if attachments:
                html += "<b>📎 Attachments Found:</b><br>"
                for att in attachments:
                    ext = att.split('.')[-1] if '.' in att else 'unknown'
                    html += f"&nbsp;&nbsp;- {att} <i>(.{ext})</i><br>"
            else:
                html += "✅ <span style='color:lightgreen;'>No suspicious attachments found.</span><br>"

            if urls:
                for url in urls:
                    result = scan_url(url, self.api_key)
                    if result and result.get("positives", 0) > 0:
                        html += f"<span style='color:red;'>❌ VirusTotal: {result['positives']}/{result['total']} engines flagged this URL.</span><br>"
                    else:
                        html += f"✅ <span style='color:lightgreen;'>VirusTotal: No issues found for {url}</span><br>"
            else:
                html += "✅ <span style='color:lightgreen;'>No URLs to scan with VirusTotal.</span><br>"

            html += "</div>\n"
            full_text += html

        self.analysis_output.setHtml(full_text)
        self.status_label.setText("✅ Scan complete.")
        QMessageBox.information(self, "Scan Complete", f"{len(selected)} email(s) scanned successfully!")

    def export_json(self):
        filepath, _ = QFileDialog.getSaveFileName(self, "Save Report", "", "JSON Files (*.json)")
        if filepath:
            generate_report_json(self.emails, filepath)
            self.analysis_output.append(f"\n✅ JSON report saved to: {filepath}")

    def export_csv(self):
        filepath, _ = QFileDialog.getSaveFileName(self, "Save Report", "", "CSV Files (*.csv)")
        if filepath:
            generate_report_csv(self.emails, filepath)
            self.analysis_output.append(f"\n✅ CSV report saved to: {filepath}")


def main():
    app = QApplication(sys.argv)
    window = EmailScannerApp()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
