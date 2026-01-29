from flask import Flask, request, jsonify, render_template, send_file, url_for
from flask_cors import CORS
import os, re, io, json
from email import policy
from email.parser import BytesParser, Parser
from email.message import EmailMessage
from fpdf import FPDF

# Optional libs (graceful)
HAVE_DKIM = HAVE_SPF = HAVE_DNS = HAVE_SCAPY = HAVE_TRANSFORMERS = False
try:
    import dkim; HAVE_DKIM = True
except Exception:
    HAVE_DKIM = False
try:
    import spf; HAVE_SPF = True
except Exception:
    HAVE_SPF = False
try:
    import dns.resolver; HAVE_DNS = True
except Exception:
    HAVE_DNS = False
try:
    from scapy.all import rdpcap; HAVE_SCAPY = True
except Exception:
    HAVE_SCAPY = False

# --- MODEL CONFIGURATION ---
MODEL_NAME = "mshenoda/roberta-spam" 
MODEL_ACCURACY = "~99%"
nlp_pipeline = None
nlp_load_status = "NLP model not loaded."

try:
    from transformers import pipeline
    HAVE_TRANSFORMERS = True
except Exception:
    HAVE_TRANSFORMERS = False

# Regex / constants
RECEIVED_IP_RE = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3})\]?")
DOUBLE_EXT_RE = re.compile(r"\.(\w+)\.(exe|scr|bat|com|js|vbs|docm|xlsm|jar)$", re.IGNORECASE)
SUSPICIOUS_EXT = {"exe","scr","bat","com","js","vbs","docm","xlsm","jar"}


# Parsing helpers
def parse_eml_bytes(data: bytes) -> EmailMessage:
    try:
        return BytesParser(policy=policy.default).parsebytes(data)
    except Exception:
        text = data.decode("utf-8", errors="ignore")
        return Parser(policy=policy.default).parsestr(text)

def extract_received_ips(msg):
    rcvd = msg.get_all("Received") or []
    ips=[]
    for h in rcvd:
        found = RECEIVED_IP_RE.findall(h)
        for ip in found:
            parts=ip.split(".")
            try:
                if len(parts)==4 and all(0<=int(p)<=255 for p in parts):
                    ips.append(ip)
            except Exception:
                pass
    return list(reversed(ips)) if ips else ips

def get_from_and_return_path(msg):
    from_hdr = msg.get("From")
    ret = msg.get("Return-Path") or msg.get("Envelope-From") or None
    return from_hdr, ret

def extract_subject_and_body(msg):
    subject = msg.get("Subject","")
    body_parts=[]
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get_content_disposition() or "")
            if disp=="attachment": continue
            if ctype=="text/plain":
                try: text = part.get_content()
                except:
                    try: text = part.get_payload(decode=True).decode("utf-8",errors="ignore")
                    except: text = ""
                body_parts.append(text)
            elif ctype=="text/html" and not body_parts:
                try: html = part.get_content()
                except:
                    try: html = part.get_payload(decode=True).decode("utf-8",errors="ignore")
                    except: html = ""
                text = re.sub(r"<[^>]+>"," ", html)
                body_parts.append(text)
    else:
        ctype = msg.get_content_type()
        if ctype in ("text/plain","text/html"):
            try: body = msg.get_content()
            except:
                try: body = msg.get_payload(decode=True).decode("utf-8",errors="ignore")
                except: body = ""
            if ctype=="text/html":
                body = re.sub(r"<[^>]+>"," ", body)
            body_parts.append(body)
    body_text = "\n\n".join(p for p in body_parts if p)
    return subject or "", body_text or ""

# SPF/DKIM/DMARC wrappers (graceful)
def spf_check(ip, mail_from=None, helo=None):
    if not HAVE_SPF:
        return {"ok":False,"error":"pyspf not installed"}
    try:
        mail_from = mail_from or "-"
        helo = helo or "unknown"
        res = spf.check2(i=ip, s=mail_from, h=helo)
        return {"ok":True,"result":res[0],"explanation":res[1],"spf_record":res[2]}
    except Exception as e:
        return {"ok":False,"error":str(e)}

def dkim_check(raw_bytes):
    if not HAVE_DKIM:
        return {"ok":False,"error":"dkimpy not installed"}
    try:
        verified = dkim.verify(raw_bytes)
        return {"ok":True,"verified":bool(verified)}
    except Exception as e:
        return {"ok":False,"error":str(e)}

def dmarc_lookup(domain):
    if not HAVE_DNS:
        return {"ok":False,"error":"dnspython not installed"}
    try:
        qname = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(qname,"TXT")
        txts = [b"".join(r.strings).decode("utf-8") for r in answers]
        txt = " ".join(txts)
        policy={}
        for part in [p.strip() for p in txt.split(";") if p.strip()]:
            if "=" in part:
                k,v = part.split("=",1)
                policy[k.lower()] = v
        return {"ok":True,"record":txt,"policy":policy}
    except Exception as e:
        return {"ok":False,"error":str(e)}

# Heuristics
def detect_display_name_spoof(from_header):
    if not from_header:
        return {"ok":False,"error":"No From header"}
    m = re.match(r"\s*([^<]+)\s*<(.+@.+)>", from_header)
    if m:
        display = m.group(1).strip(' "')
        addr = m.group(2); dom = addr.split("@")[-1].lower()
        words = re.findall(r"[A-Za-z]{3,}", display)
        suspicious=False; reasons=[]
        for w in words:
            if w.lower() in dom: continue
            if len(w)>=4 and w[0].isupper():
                suspicious=True
                reasons.append(f"Display contains '{w}' but domain is '{dom}'")
        return {"ok":True,"suspicious":suspicious,"reasons":reasons,"display":display,"addr":addr}
    return {"ok":True,"suspicious":False,"reason":"No display name / simple address"}

def detect_hidden_attachments(msg):
    findings=[]
    if msg.is_multipart():
        for part in msg.iter_attachments():
            filename=part.get_filename(); ctype=part.get_content_type()
            if filename:
                if DOUBLE_EXT_RE.search(filename):
                    findings.append({"type":"double_ext","filename":filename})
                ext = os.path.splitext(filename)[1].lower().lstrip(".")
                if ext in SUSPICIOUS_EXT:
                    findings.append({"type":"suspicious_ext","filename":filename})
            else:
                findings.append({"type":"no_filename","detail":f"attachment type {ctype}"})
            if ctype in ("application/x-msdownload","application/x-dosexec") or ctype.startswith("application/x-"):
                findings.append({"type":"suspicious_ctype","ctype":ctype,"filename":filename})
    else:
        cd = msg.get("Content-Disposition")
        if cd and "attachment" in cd.lower():
            m=re.search(r'filename="?([^";]+)"?', cd)
            fname = m.group(1) if m else None
            findings.append({"type":"singlepart_attach","filename":fname})
    return {"ok":True,"findings":findings}

# NLP loader/classifier
def load_nlp_model():
    global nlp_pipeline, nlp_load_status
    if not HAVE_TRANSFORMERS:
        nlp_load_status = "NLP Error: transformers library not installed."
        return
    try:
        nlp_pipeline = pipeline("text-classification", model=MODEL_NAME)
        nlp_load_status = "NLP Model Loaded Successfully."
    except Exception as e:
        nlp_pipeline = None
        nlp_load_status = f"NLP Error: Failed to load model. {e}"

def nlp_classify(text):
    if nlp_pipeline is None:
        return {"ok":False,"error":"NLP not loaded"}
    if not text or len(text.strip())==0:
        return {"ok":True,"label":"LABEL_0","score":0.0,"note":"empty"}
    try:
        # TRUNCATION FIX
        res = nlp_pipeline(text, truncation=True, max_length=512)
        out = res[0] if isinstance(res,list) and res else res
        return {"ok":True,"label":out.get("label"),"score":float(out.get("score",0.0))}
    except Exception as e:
        return {"ok":False,"error":str(e)}

# Risk compute
def compute_risk(report, nlp_result=None):
    technical_score = 0
    reasons = []

    # 1. SPF Check
    spf = report.get("spf",{})
    if spf.get("ok") and spf.get("result"):
        rf = spf.get("result").lower()
        if rf=="pass":
            reasons.append("SPF passed"); technical_score-=1
        elif rf in ("neutral","none"):
            reasons.append(f"SPF: {rf}")
        else:
            reasons.append(f"SPF failed: {rf}"); technical_score+=2
    else:
        reasons.append("SPF unavailable"); technical_score+=1

    # 2. DKIM Check
    dkim = report.get("dkim",{})
    if dkim.get("ok") and dkim.get("verified"):
        reasons.append("Valid DKIM"); technical_score-=1
    else:
        if dkim.get("ok"):
            reasons.append("DKIM not verified"); technical_score+=2
        else:
            reasons.append("DKIM unavailable"); technical_score+=1

    # 3. DMARC Check
    dmarc = report.get("dmarc",{})
    if dmarc.get("ok") and dmarc.get("policy"):
        p = dmarc.get("policy").get("p","none")
        reasons.append(f"DMARC: {p}")
        if p=="reject": technical_score-=1
    else:
        reasons.append("DMARC missing"); technical_score+=1

    # 4. Display Name Spoofing
    dsp = report.get("display_spoof",{})
    if dsp.get("ok") and dsp.get("suspicious"):
        reasons.append("Display-name impersonation likely"); technical_score+=2

    # 5. Attachment Checks
    att = report.get("attachments",{})
    if att.get("ok") and att.get("findings"):
        reasons.append("Suspicious attachments present"); technical_score+=2

    if report.get("mismatches"):
        reasons.append("Return-Path vs From mismatch"); technical_score+=2

    # --- MASTER OVERRIDE: NLP LOGIC ---
    score = technical_score

    if nlp_result:
        if not nlp_result.get("ok"):
            reasons.append("NLP unavailable")
        else:
            lab = str(nlp_result.get("label","LABEL_0")); sc = float(nlp_result.get("score",0.0))
            
            if lab.upper()=="LABEL_1" or "SPAM" in lab.upper():
                # --- NLP DETECTED SPAM (LABEL_1) ---
                reasons.append(f"NLP: Spam detected ({sc:.2f})")
                score = 5 
                
            else:
                # --- NLP DETECTED SAFE (LABEL_0) ---
                reasons.append(f"NLP: Clean content ({sc:.2f})")
                score = -2

    # Final Verdict Calculation
    if score<=0: verdict="SAFE"
    elif score<=2: verdict="MAYBE"
    else: verdict="RISK"
    
    return {"score":score,"verdict":verdict,"reasons":reasons}

# Analysis function
def analyze_bytes(raw_bytes):
    try:
        msg = parse_eml_bytes(raw_bytes)
    except Exception as e:
        return {"ok":False,"error":f"parse failed: {e}"}
    report={}
    report["headers"] = dict(msg.items())
    report["from"], report["return_path"] = get_from_and_return_path(msg)
    report["received_ips"] = extract_received_ips(msg)
    ip = report["received_ips"][0] if report["received_ips"] else None

    try: report["spf"] = spf_check(ip, mail_from=(report["return_path"] or msg.get("From") or None)) if ip else {"ok":False,"error":"No IP"}
    except Exception as e: report["spf"] = {"ok":False,"error":str(e)}
    try: report["dkim"] = dkim_check(raw_bytes)
    except Exception as e: report["dkim"] = {"ok":False,"error":str(e)}

    try:
        from_hdr = report["from"] or ""
        m = re.search(r"<([^>]+@[^>]+)>", from_hdr)
        if m: domain = m.group(1).split("@")[-1]
        else:
            tok = from_hdr.split()[-1] if from_hdr else ""
            domain = tok.split("@")[-1] if "@" in tok else None
        if domain: report["dmarc"] = dmarc_lookup(domain)
        else: report["dmarc"] = {"ok":False,"error":"no domain"}
    except Exception as e: report["dmarc"] = {"ok":False,"error":str(e)}

    try: report["display_spoof"] = detect_display_name_spoof(report["from"])
    except Exception as e: report["display_spoof"] = {"ok":False,"error":str(e)}
    try: report["attachments"] = detect_hidden_attachments(msg)
    except Exception as e: report["attachments"] = {"ok":False,"error":str(e)}

    try:
        from_addr=None; m=re.search(r"<([^>]+@[^>]+)>", report["from"] or "")
        if m: from_addr=m.group(1)
        else:
            if report["from"] and "@" in report["from"]: from_addr = report["from"].strip()
        report["mismatches"]=[]
        if report["return_path"] and from_addr:
            rp = re.sub(r"[<>]","", report["return_path"]).strip()
            if "@" in rp:
                if rp.split("@")[-1].lower() != from_addr.split("@")[-1].lower():
                    report["mismatches"].append({"type":"domain_mismatch"})
    except Exception:
        pass

    subj, body = extract_subject_and_body(msg)
    report["subject"]=subj
    report["body_snippet"]=body[:400]
    report["full_body"]=body
    return {"ok":True,"report":report}

# Flask app
app = Flask(__name__)
CORS(app) 

@app.route("/")
def index():
    return render_template(
        "index.html",
        model_name=MODEL_NAME,
        model_accuracy=MODEL_ACCURACY,
        scapy=str(HAVE_SCAPY),
        nlp_status=nlp_load_status
    )

@app.route("/analyze", methods=["POST"])
def route_analyze():
    raw_bytes = None
    if "raw" in request.files:
        raw_bytes = request.files["raw"].read()
    else:
        text = request.form.get("raw") or request.get_data(as_text=True) or ""
        raw_bytes = text.encode("utf-8", errors="ignore")

    if 'pcap' in request.files and HAVE_SCAPY:
        try:
            pcapf = request.files['pcap']
            bio = io.BytesIO(pcapf.read())
            pkts = rdpcap(bio)
            streams = {}
            for p in pkts:
                try:
                    if p.haslayer("TCP") and p.haslayer("Raw") and p.haslayer("IP"):
                        sport=int(p["TCP"].sport); dport=int(p["TCP"].dport)
                        if sport in (25,587) or dport in (25,587):
                            k=(p["IP"].src, p["IP"].dst, sport, dport)
                            streams.setdefault(k,b"")
                            streams[k]+=bytes(p["Raw"].load)
                except Exception:
                    continue
            cand=None; maxl=0
            for k,v in streams.items():
                if len(v)>maxl: maxl=len(v); cand=v
            if cand and (not raw_bytes or len(raw_bytes)<30):
                raw_bytes = cand
        except Exception:
            pass

    if not raw_bytes:
        return jsonify(ok=False, error="No data provided")

    res = analyze_bytes(raw_bytes)
    if not res.get("ok"):
        return jsonify(ok=False, error=res.get("error"))
    report = res["report"]

    nlp_res = None
    if nlp_pipeline is not None:
        try:
            text = (report.get("subject","") + "\n\n" + report.get("full_body","")).strip()
            nlp_res = nlp_classify(text)
        except Exception as e:
            nlp_res = {"ok":False,"error":str(e)}

    assessment = compute_risk(report, nlp_result=nlp_res)
    out = {"ok":True,"report":report,"nlp":nlp_res,"assessment":assessment}
    return jsonify(out)

class PDF(FPDF):
    def header(self):
        # Look for static/logo 1.png
        logo_path = os.path.join(app.static_folder, 'logo 1.png')
        if os.path.exists(logo_path):
            self.image(logo_path, 10, 8, 30)
        
        self.set_font('Arial', 'B', 16)
        self.cell(0, 10, 'SILENTCELL FORENSICS', 0, 1, 'C') 
        self.set_font('Arial', 'I', 10)
        self.cell(0, 5, 'UNCOVER THE UNSEEN', 0, 1, 'C')
        self.set_font('Arial', 'I', 10)
        self.cell(0, 5, 'Automated Email Analysis Report', 0, 1, 'C')
        self.ln(15) 

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 11)
        self.set_fill_color(240, 240, 240)
        self.cell(0, 8, f"  {title}", 0, 1, 'L', 1) 

    def chapter_body(self, body):
        self.set_font('Arial', '', 10)
        self.multi_cell(0, 5, body)
        self.ln(3)

    def add_report_section(self, title, data):
        self.chapter_title(title)
        self.chapter_body(data)

def sanitize_for_pdf(text):
    if not isinstance(text, str):
        text = str(text)
    return text.encode('latin-1', 'replace').decode('latin-1')

@app.route("/export", methods=["POST"])
def route_export():
    try:
        payload = request.get_json(force=True)
        if not payload:
            return jsonify(ok=False, error="no payload"), 400

        r = payload.get("report", {})
        a = payload.get("assessment", {})

        pdf = PDF()
        pdf.add_page()
        
        pdf.add_report_section("Verdict", sanitize_for_pdf(f"Verdict: {a.get('verdict')} | Score: {a.get('score')}"))
        pdf.add_report_section("From", sanitize_for_pdf(r.get("from")))
        pdf.add_report_section("Return-Path", sanitize_for_pdf(r.get("return_path")))
        pdf.add_report_section("Received IPs", sanitize_for_pdf(", ".join(r.get("received_ips", []) or ["N/A"])))
        pdf.add_report_section("SPF", sanitize_for_pdf(r.get("spf", {}).get("result") or r.get("spf", {}).get("error", "N/A")))
        dkim_status = str(r.get("dkim", {}).get("verified")) if r.get("dkim", {}).get("ok") else r.get("dkim", {}).get("error", "N/A")
        pdf.add_report_section("DKIM", sanitize_for_pdf(dkim_status))
        pdf.add_report_section("DMARC", sanitize_for_pdf(r.get("dmarc", {}).get("record") or r.get("dmarc", {}).get("error", "N/A")))

        reasons = "\n".join([f"- {reason}" for reason in a.get("reasons", [])])
        pdf.add_report_section("Reasons", sanitize_for_pdf(reasons))

        pdf.add_report_section("Subject", sanitize_for_pdf(r.get("subject") or ""))
        pdf.add_report_section("Body snippet", sanitize_for_pdf(r.get("full_body") or ""))
        
        pdf_bytes = pdf.output(dest='S').encode('latin-1')
        
        return send_file(
            io.BytesIO(pdf_bytes),
            as_attachment=True,
            download_name="forensic_report.pdf",
            mimetype="application/pdf"
        )
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500

if __name__ == "__main__":
    print("Attempting to load NLP model on startup...")
    load_nlp_model()
    print(nlp_load_status)
    print("Starting Flask application...")
    app.run(debug=True, port=5000)