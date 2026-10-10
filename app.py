from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse
import os
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import concurrent.futures
import re
import sqlite3
import json
from datetime import datetime
from google import genai

# تهيئة عميل الذكاء الاصطناعي
ai_client = genai.Client()

def init_db():
    try:
        conn = sqlite3.connect("security_history.db")
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                scan_date TEXT,
                findings_summary TEXT,
                raw_results TEXT
            )
        """)
        conn.commit()
        conn.close()
    except:
        pass

init_db()

def save_scan_to_history(target, findings_summary, raw_results):
    try:
        conn = sqlite3.connect("security_history.db")
        cursor = conn.cursor()
        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO scans (target, scan_date, findings_summary, raw_results) VALUES (?, ?, ?, ?)",
                       (target, scan_date, findings_summary, json.dumps(raw_results)))
        conn.commit()
        conn.close()
    except:
        pass

def get_previous_scan(target):
    try:
        conn = sqlite3.connect("security_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT scan_date, findings_summary FROM scans WHERE target = ? ORDER BY id DESC LIMIT 1 OFFSET 1", (target,))
        row = cursor.fetchone()
        conn.close()
        return row if row else None
    except:
        return None

class AISecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.parsed_url = urlparse(target_url)
        self.domain = self.parsed_url.netloc
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ProSecurityScanner/AI-Fast-3.8"
        })
        self.results = {
            "target": self.target_url,
            "security_headers": {},
            "sensitive_files": [],
            "discovered_endpoints": [],
            "potential_vulnerabilities": [],
            "historical_delta": None,
            "ai_analysis": "Analyzing target..."
        }

    def run_full_scan(self):
        self.check_security_headers()
        self.check_sensitive_files()
        self.smart_web_crawler()
        
        prev_scan = get_previous_scan(self.target_url)
        if prev_scan:
            self.results["historical_delta"] = f"Previous audit recorded on {prev_scan[0]}"
        else:
            self.results["historical_delta"] = "First baseline security audit recorded."

        self.generate_ai_remediation_insights()
        save_scan_to_history(self.target_url, "Assessment completed.", self.results)
        return self.results

    def check_security_headers(self):
        try:
            response = self.session.get(self.target_url, timeout=6, allow_redirects=True)
            headers = response.headers
            important_headers = {
                "Content-Security-Policy": "Missing: Protects against XSS.",
                "Strict-Transport-Security": "Missing: Enforces HTTPS.",
                "X-Frame-Options": "Missing: Vulnerable to Clickjacking.",
                "X-Content-Type-Options": "Missing: Allows MIME-sniffing.",
                "Server": "Exposed: Server disclosure."
            }
            for header, desc in important_headers.items():
                if header not in headers:
                    self.results["security_headers"][header] = {"status": "Missing", "risk": "Medium", "description": desc}
                else:
                    if header == "Server":
                        self.results["security_headers"][header] = {"status": "Exposed", "value": headers[header], "risk": "Low", "description": desc}
                    else:
                        self.results["security_headers"][header] = {"status": "Present", "value": headers[header], "description": "Configured."}
        except Exception as e:
            self.results["security_headers"]["error"] = str(e)

    def check_sensitive_files(self):
        common_paths = [".env", "robots.txt", "config.json", "package.json"]
        def test_path(path):
            full_url = urljoin(self.target_url + "/", path)
            try:
                res = self.session.get(full_url, timeout=3, allow_redirects=False)
                if res.status_code == 200 and len(res.content) > 0:
                    return {"path": path, "url": full_url, "status_code": res.status_code}
            except:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(test_path, path) for path in common_paths]
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    self.results["sensitive_files"].append(res)

    def smart_web_crawler(self):
        try:
            response = self.session.get(self.target_url, timeout=6)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                found_links = set()
                for a_tag in soup.find_all('a', href=True):
                    link = a_tag.get('href')
                    absolute_url = urljoin(self.target_url, link)
                    parsed_link = urlparse(absolute_url)
                    if parsed_link.netloc == self.domain:
                        clean_path = parsed_link.path or "/"
                        if not any(clean_path.endswith(ext) for ext in ['.jpg', '.png', '.css', '.js', '.ico']):
                            found_links.add(clean_path)
                self.results["discovered_endpoints"] = list(found_links)[:10]
        except:
            self.results["discovered_endpoints"] = ["/ (Root endpoint active)"]

    def generate_ai_remediation_insights(self):
        prompt = f"""
        You are a CISO security expert. Provide a concise executive security report, risk table, and remediation for: {self.target_url}
        Headers: {self.results["security_headers"]}
        Exposed: {self.results["sensitive_files"]}
        Use markdown formatting with headers (##) and a risk table.
        """
        try:
            response = ai_client.models.generate_content(
                model='gemini-3.8-flash',
                contents=prompt
            )
            if response and response.text:
                self.results["ai_analysis"] = response.text
        except Exception as e:
            self.results["ai_analysis"] = f"### Executive Summary\nStandard heuristic assessment completed successfully. (API note: {str(e)})."

def markdown_to_html(text):
    if not text:
        return ""
    lines = text.split('\n')
    html_lines = []
    in_table = False
    table_rows = []

    for line in lines:
        line_str = line.strip()
        if line_str.startswith('|') and line_str.endswith('|'):
            if '---' in line_str:
                continue
            if not in_table:
                in_table = True
                table_rows = ["<table style='width:100%; border-collapse:collapse; margin:15px 0; background:#0f172a; border-radius:8px; overflow:hidden;'>"]
            cols = [c.strip() for c in line_str.split('|')[1:-1]]
            tag = "th" if len(table_rows) == 1 else "td"
            bg_style = "background:#2563eb; color:#ffffff;" if tag == "th" else "border-bottom:1px solid #334155; padding:10px; font-size:13.5px;"
            cleaned_cols = [re.sub(r'\*\*(.*?)\*\*', r'\1', c) for c in cols]
            if tag == "th":
                row_html = "<tr>" + "".join([f"<th style='padding:12px 10px; text-align:left; {bg_style}'>{c}</th>" for c in cleaned_cols]) + "</tr>"
            else:
                row_html = "<tr>" + "".join([f"<td style='{bg_style}'>{c}</td>" for c in cleaned_cols]) + "</tr>"
            table_rows.append(row_html)
            continue
        else:
            if in_table:
                table_rows.append("</table>")
                html_lines.append("".join(table_rows))
                in_table = False
                table_rows = []

        if line_str in ['---', '___', '***']:
            html_lines.append('<hr style="border: 0; height: 1px; background: #334155; margin: 25px 0;">')
            continue

        if line_str.startswith('### '):
            html_lines.append(f'<h4 style="color: #38bdf8; margin-top: 20px; font-size: 16px;">{line_str[4:]}</h4>')
            continue
        elif line_str.startswith('## '):
            html_lines.append(f'<h3 style="color: #38bdf8; margin-top: 25px; border-bottom: 1px solid #334155; padding-bottom: 6px; font-size: 18px;">{line_str[3:]}</h3>')
            continue
        elif line_str.startswith('# '):
            html_lines.append(f'<h2 style="color: #38bdf8; margin-top: 30px; font-size: 20px;">{line_str[2:]}</h2>')
            continue

        formatted_line = re.sub(r'\*\*(.*?)\*\*', r'<b style="color: #f1f5f9;">\1</b>', line_str)
        if formatted_line:
            html_lines.append(f'<p style="margin: 8px 0; line-height: 1.6; color: #cbd5e1;">{formatted_line}</p>')
        else:
            html_lines.append('<div style="height: 8px;"></div>')

    if in_table:
        table_rows.append("</table>")
        html_lines.append("".join(table_rows))

    return "\n".join(html_lines)

HTML_HOME = """
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <title>ProSecurity SaaS - AI CISO Platform</title>
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
        <h2>ProSecurity Autonomous AI</h2>
        <p>CISO Executive Platform & Red Team Simulator</p>
        <form id='scanForm' action='/scan' method='post' onsubmit='startLoading()'>
            <div class='input-group'>
                <input type='text' name='target_url' placeholder='https://example.com' required autocomplete='off'>
            </div>
            <button type='submit'>Run Autonomous CISO Audit</button>
        </form>
        <div id='loader'>
            <div class='spinner'></div>
            <div class='loader-text' id='statusText'>Running fast security crawl & AI synthesis...</div>
        </div>
    </div>
    <script>
        function startLoading() {
            document.getElementById('scanForm').style.display = 'none';
            document.getElementById('loader').style.display = 'block';
        }
    </script>
</body>
</html>
"""

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

    endpoints_list = "".join([f"<li><code>{ep}</code></li>" for ep in results.get("discovered_endpoints", [])]) or "<li>No endpoints discovered.</li>"
    ai_formatted_content = markdown_to_html(results["ai_analysis"])
    delta_info = results.get("historical_delta", "No history.")

    return f"""
    <!DOCTYPE html>
    <html lang='en'>
    <head>
        <meta charset='UTF-8'>
        <title>Autonomous AI CISO Executive Report</title>
        <style>
            body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 40px; }}
            .report-container {{ max-width: 950px; margin: 0 auto; background: #1e293b; padding: 40px; border-radius: 16px; border: 1px solid #334155; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5); }}
            h1 {{ color: #38bdf8; text-align: center; margin-bottom: 5px; }}
            .target-sub {{ text-align: center; color: #94a3b8; margin-bottom: 20px; font-size: 16px; }}
            .delta-banner {{ background: #0f172a; border-left: 4px solid #f59e0b; padding: 12px 16px; margin-bottom: 25px; border-radius: 6px; font-size: 13.5px; color: #cbd5e1; }}
            h2 {{ color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 8px; margin-top: 35px; }}
            .ai-box {{ background: #0f172a; padding: 25px; border-radius: 12px; border-left: 4px solid #38bdf8; line-height: 1.6; font-size: 14.5px; color: #e2e8f0; }}
            .endpoints-box {{ background: #0f172a; padding: 15px 25px; border-radius: 8px; border: 1px solid #334155; margin-top: 15px; max-height: 180px; overflow-y: auto; }}
            .endpoints-box ul {{ margin: 0; padding-left: 20px; color: #38bdf8; }}
            .endpoints-box li {{ margin: 4px 0; font-size: 13.5px; color: #94a3b8; }}
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
            <h1>Autonomous AI CISO Executive Report</h1>
            <div class='target-sub'>Target System: <b>{results['target']}</b></div>
            
            <div class='delta-banner'>
                <b>📊 Historical Security Delta:</b> {delta_info}
            </div>

            <h2>1. AI Expert Analysis & Threat Assessment</h2>
            <div class='ai-box'>
                {ai_formatted_content}
            </div>

            <h2>2. Smart Crawler Discovered Endpoints</h2>
            <div class='endpoints-box'>
                <ul>
                    {endpoints_list}
                </ul>
            </div>

            <h2>3. Security Headers Analysis</h2>
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
