from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, StreamingResponse
import os
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import concurrent.futures
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# 1. النواة الأساسية للفحص
class ProfessionalSecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.parsed_url = urlparse(target_url)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ProSecurityScanner/2.0"
        })
        self.results = {
            "target": self.target_url,
            "security_headers": {},
            "sensitive_files": [],
            "potential_vulnerabilities": []
        }

    def run_full_scan(self):
        self.check_security_headers()
        self.check_sensitive_files()
        self.scan_forms_and_inputs()
        return self.results

    def check_security_headers(self):
        try:
            response = self.session.get(self.target_url, timeout=10, allow_redirects=True)
            headers = response.headers
            important_headers = {
                "Content-Security-Policy": "Missing: Protects against XSS and code injection attacks.",
                "Strict-Transport-Security": "Missing: Enforces secure HTTPS connections (HSTS).",
                "X-Frame-Options": "Missing: Leaves the application vulnerable to Clickjacking.",
                "X-Content-Type-Options": "Missing: Allows MIME-sniffing browser manipulation.",
                "Server": "Exposed: Server technology disclosure detected."
            }
            for header, desc in important_headers.items():
                if header not in headers:
                    self.results["security_headers"][header] = {"status": "Missing", "risk": "Medium", "description": desc}
                else:
                    if header == "Server":
                        self.results["security_headers"][header] = {"status": "Exposed", "value": headers[header], "risk": "Low", "description": desc}
                    else:
                        self.results["security_headers"][header] = {"status": "Present", "value": headers[header], "description": "Header correctly configured."}
        except Exception as e:
            self.results["security_headers"]["error"] = str(e)

    def check_sensitive_files(self):
        common_paths = [
            ".env", "robots.txt", ".git/HEAD", "config.json", 
            "backend/config.py", "backup.zip", "package.json", "api/swagger.json"
        ]
        def test_path(path):
            full_url = urljoin(self.target_url + "/", path)
            try:
                res = self.session.get(full_url, timeout=5, allow_redirects=False)
                if res.status_code == 200 and len(res.content) > 0:
                    if "html" not in res.headers.get("Content-Type", "") or path == "robots.txt":
                        return {"path": path, "url": full_url, "status_code": res.status_code}
            except:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(test_path, path) for path in common_paths]
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    self.results["sensitive_files"].append(res)

    def scan_forms_and_inputs(self):
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            for i, form in enumerate(forms):
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                inputs = [inp.get('name') for inp in form.find_all('input') if inp.get('name')]
                self.results["potential_vulnerabilities"].append({
                    "form_index": i, "action": action, "method": method, "inputs_found": inputs
                })
        except Exception as e:
            self.results["potential_vulnerabilities"].append({"error": str(e)})

    def export_pdf_report(self, buffer):
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
        story = []
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle('ExecTitle', parent=styles['Heading1'], fontSize=20, textColor=colors.HexColor("#1A365D"), spaceAfter=15, alignment=1)
        subtitle_style = ParagraphStyle('SubTitle', parent=styles['Normal'], fontSize=12, textColor=colors.HexColor("#4A5568"), spaceAfter=25, alignment=1)
        heading_style = ParagraphStyle('SectionHeading', parent=styles['Heading2'], fontSize=14, textColor=colors.HexColor("#2B6CB0"), spaceBefore=15, spaceAfter=10)

        story.append(Paragraph("Executive Security Audit Report", title_style))
        story.append(Paragraph(f"Target System: <b>{self.target_url}</b>", subtitle_style))
        story.append(Spacer(1, 10))

        # جدول ترويسات الأمان
        story.append(Paragraph("1. Security Headers Analysis", heading_style))
        headers_data = [["Header Name", "Status", "Risk", "Description"]]
        for header, details in self.results.get("security_headers", {}).items():
            if header != "error":
                headers_data.append([
                    header, 
                    details.get("status", "Unknown"), 
                    details.get("risk", "Low"), 
                    details.get("description", "Standard audit")
                ])
        
        if len(headers_data) > 1:
            t = Table(headers_data, colWidths=[110, 60, 60, 270])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#2B6CB0")),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0,0), (-1,0), 8),
                ('BACKGROUND', (0,1), (-1,-1), colors.HexColor("#F7FAFC")),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E0")),
                ('FONTSIZE', (0,0), (-1,-1), 8.5),
            ]))
            story.append(t)
            
        story.append(Spacer(1, 10))

        # جدول الملفات والمسارات الحساسة المكشوفة
        story.append(Paragraph("2. Sensitive Files & Exposed Endpoints", heading_style))
        sensitive_data = [["Path Found", "Full URL", "Status Code"]]
        for item in self.results.get("sensitive_files", []):
            sensitive_data.append([item["path"], item["url"], str(item["status_code"])])
            
        if len(sensitive_data) > 1:
            t2 = Table(sensitive_data, colWidths=[120, 300, 80])
            t2.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#C53030")),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0,0), (-1,0), 8),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E0")),
                ('FONTSIZE', (0,0), (-1,-1), 9),
            ]))
            story.append(t2)
        else:
            story.append(Paragraph("No sensitive files or public endpoints exposed.", styles['Normal']))
        
        doc.build(story)

# 2. الكلاس المتقدم (يشمل فحص الكوكيز والمسارات المتقدمة)
class AdvancedSecurityScanner(ProfessionalSecurityScanner):
    def __init__(self, target_url):
        super().__init__(target_url)
        self.sqli_payloads = ["'", "\"", "' OR '1'='1"]

    def run_advanced_scan(self):
        self.run_full_scan()
        self.check_cookie_security()
        self.check_advanced_sensitive_paths()
        return self.results

    def check_cookie_security(self):
        try:
            response = self.session.get(self.target_url, timeout=10)
            cookies = response.cookies
            for cookie in cookies:
                cookie_issues = []
                if not cookie.secure:
                    cookie_issues.append("Missing 'Secure' flag")
                if cookie_issues:
                    self.results["potential_vulnerabilities"].append({
                        "type": "Insecure Cookie Configuration",
                        "cookie_name": cookie.name,
                        "issues": cookie_issues,
                        "risk": "Medium",
                        "description": f"The cookie '{cookie.name}' lacks critical security flags."
                    })
        except:
            pass

    def check_advanced_sensitive_paths(self):
        advanced_paths = [
            "swagger/index.html", "api-docs", "graphql", 
            "phpmyadmin", "server-status", ".well-known/security.txt"
        ]
        def test_advanced_path(path):
            full_url = urljoin(self.target_url + "/", path)
            try:
                res = self.session.get(full_url, timeout=5, allow_redirects=False)
                if res.status_code in [200, 403]:
                    return {"path": path, "url": full_url, "status_code": res.status_code}
            except:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(test_advanced_path, path) for path in advanced_paths]
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    self.results["sensitive_files"].append(res)

# 3. تطبيق FastAPI
app = FastAPI(title="ProSecurity SaaS Dashboard", version="2.0")

@app.get("/", response_class=HTMLResponse)
async def dashboard_home():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>ProSecurity SaaS - Advanced Vulnerability Scanner</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #F7FAFC; text-align: center; padding-top: 50px; }
            .container { background: white; max-width: 600px; margin: auto; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
            h2 { color: #1A365D; margin-bottom: 10px; }
            p { color: #4A5568; margin-bottom: 30px; }
            input[type="text"] { width: 80%; padding: 12px; border: 1px solid #CBD5E0; border-radius: 5px; font-size: 16px; margin-bottom: 20px; }
            button { background-color: #2B6CB0; color: white; border: none; padding: 12px 30px; font-size: 16px; border-radius: 5px; cursor: pointer; }
            button:hover { background-color: #2C5282; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>🔒 ProSecurity SaaS Platform</h2>
            <p>Automated Enterprise Security Scanner & PDF Executive Reporting</p>
            <form action="/scan" method="post">
                <input type="text" name="target_url" placeholder="Enter Target URL (e.g., https://example.com)" required><br>
                <button type="submit">Run Security Audit</button>
            </form>
        </div>
    </body>
    </html>
    """

@app.post("/scan", response_class=StreamingResponse)
async def run_scan_endpoint(target_url: str = Form(...)):
    scanner = AdvancedSecurityScanner(target_url)
    scanner.run_advanced_scan()
    
    # توليد التقرير في الذاكرة ومباشرة كدفق بيانات (Streaming)
    pdf_buffer = BytesIO()
    scanner.export_pdf_report(pdf_buffer)
    pdf_buffer.seek(0)
    
    filename = f"security_report_{abs(hash(target_url))}.pdf"
    
    return StreamingResponse(
        pdf_buffer, 
        media_type="application/pdf", 
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("app:app", host="0.0.0.0", port=port)
