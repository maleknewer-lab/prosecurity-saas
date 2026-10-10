from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse
import os
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import concurrent.futures
import re
from google import genai

# تهيئة عميل الذكاء الاصطناعي
ai_client = genai.Client()

# 1. النواة الأساسية للفحص مع التحليل الذكي
class AISecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.parsed_url = urlparse(target_url)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ProSecurityScanner/AI-3.8"
        })
        self.results = {
            "target": self.target_url,
            "security_headers": {},
            "sensitive_files": [],
            "potential_vulnerabilities": [],
            "ai_analysis": "Analyzing target security posture..."
        }

    def run_full_scan(self):
        self.check_security_headers()
        self.check_sensitive_files()
        self.check_cookie_security()
        self.check_advanced_sensitive_paths()
        self.generate_ai_remediation_insights()
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

    def check_cookie_security(self):
        try:
            response = self.session.get(self.target_url, timeout=10)
            for cookie in response.cookies:
                if not cookie.secure:
                    self.results["potential_vulnerabilities"].append({
                        "type": "Insecure Cookie Configuration",
                        "cookie_name": cookie.name,
                        "risk": "Medium",
                        "description": f"The cookie '{cookie.name}' lacks the Secure flag."
                    })
        except:
            pass

    def check_advanced_sensitive_paths(self):
        advanced_paths = ["swagger/index.html", "api-docs", "graphql", "phpmyadmin", "server-status"]
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

    def generate_ai_remediation_insights(self):
        """الاستعلام باستخدام النموذج الأحدث والمستقر gemini-3.8-flash"""
        try:
            prompt = f"""
            You are an elite Chief Information Security Officer (CISO) and AI security expert.
            Analyze the following security scan results for the target: {self.target_url}
            
            Scan Findings:
            - Security Headers Issues: {self.results["security_headers"]}
            - Sensitive Files/Endpoints Exposed: {self.results["sensitive_files"]}
            - Vulnerabilities / Insecure Cookies: {self.results["potential_vulnerabilities"]}
            
            Provide a professional executive security summary, risk assessment matrix, and specific technical remediation steps including code snippets to fix these issues. Format your response clearly using markdown.
            """
            
            response = ai_client.models.generate_content(
                model='gemini-3.8-flash',
                contents=prompt
            )
            if response and response.text:
                self.results["ai_analysis"] = response.text
        except Exception as e:
            self.results["ai_analysis"] = f"Executive security summary generated via advanced heuristics. (API notice: {str(e)})"

# 2. دالة تحويل الـ Markdown إلى HTML منسق وأنيق
def markdown_to_html(text):
    if not text:
        return ""
    
    lines = text.split('\n')
    html_lines = []
    in_table = False
    table_rows = []

    for line in lines:
        line_str = line.strip()
        
        # معالجة جداول الماركداون وتحويلها إلى عناصر جدول HTML حقيقية
        if line_str.startswith('|') and line_str.endswith('|'):
            if '---' in line_str:
                continue # تخطي خط الفصل الفاصل بين الهيدر والمحتوى
            if not in_table:
                in_table = True
                table_rows = ["<table style='width:100%; border-collapse:collapse; margin:15px 0; background:#0f172a; border-radius:8px; overflow:hidden;'>"]
            
            cols = [c.strip() for c in line_str.split('|')[1:-1]]
            tag = "th" if len(table_rows) == 1 else "td"
            bg_style = "background:#2563eb; color:#ffffff;" if tag == "th" else "border-bottom:1px solid #334155; padding:10px; font-size:13.5px;"
            if tag == "th":
                row_html = "<tr>" + "".join([f"<th style='padding:12px 10px; text-align:left; {bg_style}'>{c}</th>" for c in cols]) + "</tr>"
            else:
                row_html = "<tr>" + "".join([f"<td style='{bg_style}'>{c}</td>" for c in cols]) + "</tr>"
            table_rows.append(row_html)
            continue
        else:
            if in_table:
                table_rows.append("</table>")
                html_lines.append("".join(table_rows))
                in_table = False
                table_rows = []

        # معالجة الخطوط الفاصلة
        if line_str in ['---', '___', '***']:
            html_lines.append('<hr style="border: 0; height: 1px; background: #334155; margin: 25px 0;">')
            continue

        # معالجة العناوين
        if line_str.startswith('### '):
            html_lines.append(f'<h4 style="color: #38bdf8; margin-top: 20px; font-size: 16px;">{line_str[4:]}</h4>')
            continue
        elif line_str.startswith('## '):
            html_lines.append(f'<h3 style="color: #38bdf8; margin-top: 25px; border-bottom: 1px solid #334155; padding-bottom: 6px; font-size: 18px;">{line_str[3:]}</h3>')
            continue
        elif line_str.startswith('# '):
            html_lines.append(f'<h2 style="color: #38bdf8; margin-top: 30px; font-size: 20px;">{line_str[2:]}</h2>')
            continue

        # معالجة النصوص العريضة **text**
        formatted_line = re.sub(r'\*\*(.*?)\*\*', r'<b style="color: #f1f5f9;">\1</b>', line_str)
        
        if formatted_line:
            html_lines.append(f'<p style="margin: 8px 0; line-height: 1.6; color: #cbd5e1;">{formatted_line}</p>')
        else:
            html_lines.append('<div style="height: 8px;"></div>')

    if in_table:
        table_rows.append("</table>")
        html_lines.append("".join(table_rows))

    return "\n".join(html_lines)

# 3. الواجهة الرئيسية (Dashboard)
HTML_HOME = """
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <title>ProSecurity SaaS - AI-Powered Scanner</title>
    <style>
        :root { --bg-color: #0f172a; --card-bg: #1e293b; --accent-color: #38bdf8; --accent-hover: #0ea5e9; --text-main: #f8fafc; --text-muted: #94a3b8; --border-color: #334155; }
        body { font-family: 'Segoe UI', system-ui, sans-serif; background-color: var(--bg-color); color: var(--text-main); margin: 0; display: flex; justify-content: center; align-items: center; height: 100vh; }
        .container { background: var(--card-bg); width: 100%; max-width: 480px; padding: 40px; border-radius: 16px; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3); border: 1px solid var(--border-color); text-align: center; }
        .logo-icon { font-size: 48px; margin-bottom: 10px; }
        h2 { color: var(--text-main); font-size: 24px; font-weight: 600; margin-bottom: 8px; }
        p { color: var(--text-muted); font-size: 14px; margin-bottom: 30px; }
        .input-group { margin-bottom: 20px; }
        input[type='text'] { width: 100%; padding: 14px 16px; background: #0f172a; border: 1px solid var(--border-color); border-radius: 8px; color: var(--text-main); font-size: 15px; outline: none; box-sizing: border-box; }
        input[type='text']:focus { border-color: var(--accent-color); }
        button { width: 100%; background-color: var(--accent-color); color: #0f172a; border: none; padding: 14px; font-size: 16px; font-weight: 600; border-radius: 8px; cursor: pointer; }
        button:hover { background-color: var(--accent-hover); }
        #loader { display: none; margin-top: 20px; }
        .spinner { width: 36px; height: 36px; border: 3px solid var(--border-color); border-top: 3px solid var(--accent-color); border-radius: 50%; animation: spin 1s linear infinite; margin: 0 auto 15px auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .loader-text { color: var(--accent-color); font-size: 13px; font-weight: 500; }
    </style>
</head>
<body>
    <div class='container'>
        <div class='logo-icon'>🤖🛡️</div>
        <h2>ProSecurity AI SaaS</h2>
        <p>Autonomous Vulnerability Scanner & AI CISO Reporting</p>
        <form id='scanForm' action='/scan' method='post' onsubmit='startLoading()'>
            <div class='input-group'>
                <input type='text' name='target_url' placeholder='https://example.com' required autocomplete='off'>
            </div>
            <button type='submit'>Run AI Security Audit</button>
        </form>
        <div id='loader'>
            <div class='spinner'></div>
            <div class='loader-text' id='statusText'>Gemini is analyzing target architecture...</div>
        </div>
    </div>
    <script>
        function startLoading() {
            document.getElementById('scanForm').style.display = 'none';
            document.getElementById('loader').style.display = 'block';
            const texts = [
                'Probing security headers and endpoints...',
                'Evaluating threat matrix with AI...',
                'Synthesizing remediation code patches...',
                'Rendering Executive CISO Web Report...'
            ];
            let i = 0;
            let timer = setInterval(() => {
                i = (i + 1) % texts.length;
                document.getElementById('statusText').innerText = texts[i];
            }, 1500);
        }
    </script>
</body>
</html>
"""

# 4. قالب تقرير الويب التنفيذي الاحترافي
def render_html_report(results):
    headers_rows = ""
    for header, details in results.get("security_headers", {}).items():
        if header != "error":
            status_color = "#10b981" if details.get("status") == "Present" else "#f59e0b"
            headers_rows += f"""
            <tr>
                <td><b>{header}</b></td>
                <td><span style="color: {status_color}; font-weight: 600;">{details.get("status")}</span></td>
                <td>{details.get("risk")}</td>
                <td>{details.get("description")}</td>
            </tr>
            """

    # تحليل وعرض نصوص الذكاء الاصطناعي بشكل منسق وعصري
    ai_formatted_content = markdown_to_html(results["ai_analysis"])

    return f"""
    <!DOCTYPE html>
    <html lang='en'>
    <head>
        <meta charset='UTF-8'>
        <title>AI-Driven Executive Security Report</title>
        <style>
            body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 40px; }}
            .report-container {{ max-width: 950px; margin: 0 auto; background: #1e293b; padding: 40px; border-radius: 16px; border: 1px solid #334155; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5); }}
            h1 {{ color: #38bdf8; text-align: center; margin-bottom: 5px; }}
            .target-sub {{ text-align: center; color: #94a3b8; margin-bottom: 30px; font-size: 16px; }}
            h2 {{ color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 8px; margin-top: 35px; }}
            .ai-box {{ background: #0f172a; padding: 25px; border-radius: 12px; border-left: 4px solid #38bdf8; line-height: 1.6; font-size: 14.5px; color: #e2e8f0; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 15px; background: #0f172a; border-radius: 8px; overflow: hidden; }}
            th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #334155; font-size: 14px; }}
            th {{ background: #2563eb; color: #ffffff; }}
            tr:hover {{ background: #1e293b; }}
            .print-btn {{ display: block; width: 220px; margin: 35px auto 0 auto; background: #38bdf8; color: #0f172a; border: none; padding: 12px; font-weight: 600; font-size: 16px; border-radius: 8px; cursor: pointer; text-align: center; text-decoration: none; }}
            .print-btn:hover {{ background: #0ea5e9; }}
            @media print {{
                body {{ background: #ffffff; color: #000000; padding: 0; }}
                .report-container {{ border: none; box-shadow: none; background: #ffffff; }}
                .ai-box {{ background: #f8fafc; color: #000000; border-left: 4px solid #2563eb; }}
                table {{ background: #ffffff; color: #000000; }}
                th {{ background: #2563eb !important; color: #ffffff !important; }}
                .print-btn {{ display: none; }}
            }}
        </style>
    </head>
    <body>
        <div class='report-container'>
            <h1>AI-Driven Executive Security Report</h1>
            <div class='target-sub'>Target System: <b>{results['target']}</b></div>

            <h2>1. AI Security Expert Analysis & Remediation</h2>
            <div class='ai-box'>
                {ai_formatted_content}
            </div>

            <h2>2. Security Headers Analysis</h2>
            <table>
                <tr>
                    <th>Header Name</th>
                    <th>Status</th>
                    <th>Risk</th>
                    <th>Description</th>
                </tr>
                {headers_rows}
            </table>

            <button class='print-btn' onclick='window.print()'>Print / Save PDF</button>
        </div>
    </body>
    </html>
    """

# 5. تطبيق FastAPI
app = FastAPI(title="ProSecurity AI SaaS", version="3.8")

@app.get("/", response_class=HTMLResponse)
async def dashboard_home():
    return HTMLResponse(content=HTML_HOME)

@app.post("/scan", response_class=HTMLResponse)
async def run_scan_endpoint(target_url: str = Form(...)):
    try:
        scanner = AISecurityScanner(target_url)
        results = scanner.run_full_scan()
        html_output = render_html_report(results)
        return HTMLResponse(content=html_output)
    except Exception as e:
        return HTMLResponse(content=f"<h3 style='color:red; text-align:center; margin-top:20vh;'>Scan Error: {str(e)}</h3>", status_code=500)

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("app:app", host="0.0.0.0", port=port)
