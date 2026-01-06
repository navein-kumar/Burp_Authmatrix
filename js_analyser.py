# -*- coding: utf-8 -*-
"""
JS Analyzer Enhanced - Single File
Enhanced by CodeSecure Solutions (www.codesecure.in)
Original by Jenish Sojitra (@_jensec)

Features: Original URLs tab, Progress status, Bulk scan, Full secrets, CSV export, Burp native viewer
"""

from burp import IBurpExtender, IContextMenuFactory, ITab, IMessageEditorController
from javax.swing import (
    JPanel, JScrollPane, JTabbedPane, JButton, JLabel,
    JTable, JComboBox, JTextField, BorderFactory, JSplitPane,
    JFileChooser, JOptionPane, JMenuItem, JPopupMenu, JProgressBar, SwingUtilities
)
from javax.swing.table import DefaultTableModel
from javax.swing.event import ListSelectionListener
from java.awt import BorderLayout, FlowLayout, Font, Dimension, Toolkit, Color
from java.awt.datatransfer import StringSelection
from java.awt.event import ActionListener, KeyListener, MouseAdapter
from java.util import ArrayList
from java.io import PrintWriter, File, FileWriter, BufferedWriter
import re
import json


# ==================== PATTERNS ====================
ENDPOINT_PATTERNS = [
    re.compile(r'["\']((?:https?:)?//[^"\']+/api/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/api/v?\d*/[a-zA-Z0-9/_-]{2,})["\']', re.IGNORECASE),
    re.compile(r'["\'](/v\d+/[a-zA-Z0-9/_-]{2,})["\']', re.IGNORECASE),
    re.compile(r'["\'](/rest/[a-zA-Z0-9/_-]{2,})["\']', re.IGNORECASE),
    re.compile(r'["\'](/graphql[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/oauth[0-9]*/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/auth[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/login[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/logout[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/token[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/callback[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/admin[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/dashboard[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/internal[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/config[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/upload[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/user[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/account[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/settings[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/\.well-known/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
]

URL_PATTERNS = [
    re.compile(r'["\'](https?://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](wss?://[^\s"\'<>]{10,})["\']'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.s3[a-zA-Z0-9.-]*\.amazonaws\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.blob\.core\.windows\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://storage\.googleapis\.com/[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.firebaseio\.com[^\s"\'<>]*)'),
]

SECRET_PATTERNS = [
    # AWS
    (re.compile(r'(AKIA[0-9A-Z]{16})'), "AWS Access Key"),
    (re.compile(r'(ASIA[0-9A-Z]{16})'), "AWS Temp Key"),
    # Google
    (re.compile(r'(AIza[0-9A-Za-z\-_]{35})'), "Google API Key"),
    (re.compile(r'(ya29\.[0-9A-Za-z\-_]+)'), "Google OAuth"),
    # Stripe
    (re.compile(r'(sk_live_[0-9a-zA-Z]{24,})'), "Stripe Live Key"),
    (re.compile(r'(sk_test_[0-9a-zA-Z]{24,})'), "Stripe Test Key"),
    (re.compile(r'(pk_live_[0-9a-zA-Z]{24,})'), "Stripe Pub Key"),
    (re.compile(r'(rk_live_[0-9a-zA-Z]{24,})'), "Stripe Restricted"),
    # GitHub
    (re.compile(r'(ghp_[0-9a-zA-Z]{36})'), "GitHub PAT"),
    (re.compile(r'(gho_[0-9a-zA-Z]{36})'), "GitHub OAuth"),
    (re.compile(r'(ghu_[0-9a-zA-Z]{36})'), "GitHub User Token"),
    (re.compile(r'(ghs_[0-9a-zA-Z]{36})'), "GitHub Server Token"),
    (re.compile(r'(github_pat_[0-9a-zA-Z_]{22,})'), "GitHub PAT v2"),
    # Slack
    (re.compile(r'(xox[baprs]-[0-9a-zA-Z\-]{10,48})'), "Slack Token"),
    (re.compile(r'(xapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-z0-9]+)'), "Slack App Token"),
    # JWT
    (re.compile(r'(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)'), "JWT Token"),
    # Private Keys
    (re.compile(r'(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?:\sBLOCK)?-----)'), "Private Key"),
    (re.compile(r'(-----BEGIN CERTIFICATE-----)'), "Certificate"),
    # Database
    (re.compile(r'(mongodb(?:\+srv)?://[^\s"\'<>]+)'), "MongoDB URI"),
    (re.compile(r'(postgres(?:ql)?://[^\s"\'<>]+)'), "PostgreSQL URI"),
    (re.compile(r'(mysql://[^\s"\'<>]+)'), "MySQL URI"),
    (re.compile(r'(redis://[^\s"\'<>]+)'), "Redis URI"),
    (re.compile(r'(amqp://[^\s"\'<>]+)'), "RabbitMQ URI"),
    # OpenAI
    (re.compile(r'(sk-[a-zA-Z0-9]{20,})'), "OpenAI API Key"),
    # SendGrid
    (re.compile(r'(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})'), "SendGrid API Key"),
    # Twilio
    (re.compile(r'(AC[a-zA-Z0-9]{32})'), "Twilio Account SID"),
    (re.compile(r'(SK[a-zA-Z0-9]{32})'), "Twilio API Key"),
    # Mailgun
    (re.compile(r'(key-[0-9a-zA-Z]{32})'), "Mailgun API Key"),
    # Square
    (re.compile(r'(sq0csp-[0-9A-Za-z\-_]{43})'), "Square OAuth Secret"),
    (re.compile(r'(sq0atp-[0-9A-Za-z\-_]{22})'), "Square Access Token"),
    # Shopify
    (re.compile(r'(shppa_[a-fA-F0-9]{32})'), "Shopify Private App"),
    (re.compile(r'(shpat_[a-fA-F0-9]{32})'), "Shopify Access Token"),
    # Heroku
    (re.compile(r'(heroku[a-zA-Z0-9\-_]{20,})'), "Heroku API Key"),
    # DigitalOcean
    (re.compile(r'(dop_v1_[a-fA-F0-9]{64})'), "DigitalOcean PAT"),
    (re.compile(r'(doo_v1_[a-fA-F0-9]{64})'), "DigitalOcean OAuth"),
    # NPM
    (re.compile(r'(npm_[A-Za-z0-9]{36})'), "NPM Token"),
    # PyPI
    (re.compile(r'(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,})'), "PyPI Token"),
    # Auth tokens
    (re.compile(r'(bearer\s+[a-zA-Z0-9\-_\.]{20,})', re.IGNORECASE), "Bearer Token"),
    (re.compile(r'(basic\s+[a-zA-Z0-9+/=]{20,})', re.IGNORECASE), "Basic Auth"),
    # Generic secrets
    (re.compile(r'api[_-]?key["\'\s:=]+["\']?([a-zA-Z0-9\-_]{16,})["\']?', re.IGNORECASE), "API Key"),
    (re.compile(r'api[_-]?secret["\'\s:=]+["\']?([a-zA-Z0-9\-_]{16,})["\']?', re.IGNORECASE), "API Secret"),
    (re.compile(r'secret[_-]?key["\'\s:=]+["\']?([a-zA-Z0-9\-_]{16,})["\']?', re.IGNORECASE), "Secret Key"),
    (re.compile(r'access[_-]?token["\'\s:=]+["\']?([a-zA-Z0-9\-_\.]{20,})["\']?', re.IGNORECASE), "Access Token"),
    (re.compile(r'refresh[_-]?token["\'\s:=]+["\']?([a-zA-Z0-9\-_\.]{20,})["\']?', re.IGNORECASE), "Refresh Token"),
    (re.compile(r'client[_-]?secret["\'\s:=]+["\']?([a-zA-Z0-9\-_]{16,})["\']?', re.IGNORECASE), "Client Secret"),
    (re.compile(r'password["\'\s:=]+["\']?([^"\'<>\s]{8,})["\']?', re.IGNORECASE), "Password"),
    
    # ==================== WEBHOOKS ====================
    # Discord
    (re.compile(r'(https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+)'), "Discord Webhook"),
    # Slack
    (re.compile(r'(https?://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+)'), "Slack Webhook"),
    (re.compile(r'(https?://hooks\.slack\.com/workflows/T[A-Z0-9]+/[A-Z0-9]+/[0-9]+/[a-zA-Z0-9]+)'), "Slack Workflow Webhook"),
    # Microsoft Teams
    (re.compile(r'(https?://[a-zA-Z0-9-]+\.webhook\.office\.com/webhookb2/[a-zA-Z0-9-]+@[a-zA-Z0-9-]+/[a-zA-Z0-9]+/[a-zA-Z0-9-]+/[a-zA-Z0-9-]+)'), "MS Teams Webhook"),
    (re.compile(r'(https?://outlook\.office\.com/webhook/[a-zA-Z0-9-]+)'), "MS Teams Webhook (old)"),
    # n8n
    (re.compile(r'(https?://[a-zA-Z0-9.-]+/webhook(?:-test)?/[a-zA-Z0-9-]+)'), "n8n Webhook"),
    (re.compile(r'(https?://[a-zA-Z0-9.-]+\.app\.n8n\.cloud/webhook(?:-test)?/[a-zA-Z0-9-]+)'), "n8n Cloud Webhook"),
    # Mattermost
    (re.compile(r'(https?://[a-zA-Z0-9.-]+/hooks/[a-zA-Z0-9]+)'), "Mattermost Webhook"),
    # Zapier
    (re.compile(r'(https?://hooks\.zapier\.com/hooks/catch/[0-9]+/[a-zA-Z0-9]+)'), "Zapier Webhook"),
    # IFTTT
    (re.compile(r'(https?://maker\.ifttt\.com/trigger/[a-zA-Z0-9_]+/with/key/[a-zA-Z0-9_-]+)'), "IFTTT Webhook"),
    # Pipedream
    (re.compile(r'(https?://[a-zA-Z0-9]+\.m\.pipedream\.net)'), "Pipedream Webhook"),
    # Make (Integromat)
    (re.compile(r'(https?://hook\.(?:us\.|eu\.)?make\.com/[a-zA-Z0-9]+)'), "Make/Integromat Webhook"),
    (re.compile(r'(https?://hook\.(?:us\.|eu\.)?integromat\.com/[a-zA-Z0-9]+)'), "Integromat Webhook"),
    # Telegram Bot
    (re.compile(r'(https?://api\.telegram\.org/bot[0-9]+:[a-zA-Z0-9_-]+)'), "Telegram Bot API"),
    # GitHub Webhook
    (re.compile(r'(https?://api\.github\.com/repos/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+/hooks)'), "GitHub Webhook"),
    # GitLab Webhook
    (re.compile(r'(https?://gitlab\.com/api/v4/projects/[0-9]+/hooks)'), "GitLab Webhook"),
    # Bitbucket Webhook
    (re.compile(r'(https?://api\.bitbucket\.org/2\.0/repositories/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+/hooks)'), "Bitbucket Webhook"),
    # Jira Webhook
    (re.compile(r'(https?://[a-zA-Z0-9.-]+\.atlassian\.net/rest/webhooks)'), "Jira Webhook"),
    # Twilio Webhook
    (re.compile(r'(https?://[a-zA-Z0-9.-]+/twilio/webhook)'), "Twilio Webhook"),
    # Stripe Webhook
    (re.compile(r'(whsec_[a-zA-Z0-9]+)'), "Stripe Webhook Secret"),
    # SendGrid Webhook
    (re.compile(r'(https?://api\.sendgrid\.com/v3/user/webhooks)'), "SendGrid Webhook"),
    # Mailchimp Webhook
    (re.compile(r'(https?://[a-z0-9]+\.api\.mailchimp\.com/3\.0/lists/[a-z0-9]+/webhooks)'), "Mailchimp Webhook"),
    # PagerDuty
    (re.compile(r'(https?://events\.pagerduty\.com/v2/enqueue)'), "PagerDuty Webhook"),
    # Datadog
    (re.compile(r'(https?://http-intake\.logs\.[a-z0-9]+\.datadoghq\.com)'), "Datadog Webhook"),
    # Generic Webhook patterns
    (re.compile(r'(https?://[a-zA-Z0-9.-]+/webhook[s]?/[a-zA-Z0-9/_-]+)', re.IGNORECASE), "Generic Webhook"),
    (re.compile(r'(https?://[a-zA-Z0-9.-]+/api/webhook[s]?/[a-zA-Z0-9/_-]+)', re.IGNORECASE), "API Webhook"),
    (re.compile(r'(https?://[a-zA-Z0-9.-]+/callback[s]?/[a-zA-Z0-9/_-]+)', re.IGNORECASE), "Callback URL"),
    (re.compile(r'webhook[_-]?url["\'\s:=]+["\']?(https?://[^\s"\'<>]+)["\']?', re.IGNORECASE), "Webhook URL"),
    (re.compile(r'webhook[_-]?secret["\'\s:=]+["\']?([a-zA-Z0-9\-_]{16,})["\']?', re.IGNORECASE), "Webhook Secret"),
]

EMAIL_PATTERN = re.compile(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})')

FILE_PATTERNS = re.compile(
    r'["\']([a-zA-Z0-9_/.-]+\.(?:'
    r'sql|csv|xlsx|json|xml|yaml|yml|env|bak|backup|key|pem|crt|pdf|zip|tar|gz|sh|ps1|py'
    r'))["\']', re.IGNORECASE
)

NOISE_DOMAINS = {
    'www.w3.org', 'schemas.openxmlformats.org', 'schemas.microsoft.com',
    'purl.org', 'example.com', 'test.com', 'localhost', '127.0.0.1',
    'npmjs.org', 'reactjs.org', 'angular.io', 'vuejs.org',
}

NOISE_PATTERNS = [
    re.compile(r'^\.\.?/'), re.compile(r'^[a-z]{2}(-[a-z]{2})?\.js$'),
    re.compile(r'^xl/'), re.compile(r'^docProps/'), re.compile(r'^_rels/'),
    re.compile(r'\.xml$'), re.compile(r'^webpack'), re.compile(r'^http://$'),
]


# ==================== MAIN EXTENSION ====================
class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IMessageEditorController):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("JS Analyzer")
        
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        
        self.all_findings = []
        self.seen_values = set()
        self.http_messages = {}
        self._current_message = None
        
        # Scanned URLs list
        self.scanned_urls = []
        
        self.panel = ResultsPanel(callbacks, self)
        
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)
        
        self._stdout.println("[JS Analyzer] Loaded - Select requests > Right-click > Analyze JS")
    
    def getHttpService(self):
        return self._current_message.getHttpService() if self._current_message else None
    
    def getRequest(self):
        return self._current_message.getRequest() if self._current_message else None
    
    def getResponse(self):
        return self._current_message.getResponse() if self._current_message else None
    
    def getTabCaption(self):
        return "JS Analyzer"
    
    def getUiComponent(self):
        return self.panel
    
    def createMenuItems(self, invocation):
        menu = ArrayList()
        messages = invocation.getSelectedMessages()
        if messages and len(messages) > 0:
            item = JMenuItem("Analyze JS (%d selected)" % len(messages))
            item.addActionListener(AnalyzeAction(self, messages))
            menu.add(item)
        return menu
    
    def analyze_messages(self, messages):
        """Analyze multiple messages with progress."""
        total = len(messages)
        
        # Update UI - Starting
        self.panel.update_status("Starting scan...", 0, total)
        
        for i, msg in enumerate(messages):
            # Update progress
            self.panel.update_status("Scanning %d/%d" % (i+1, total), i+1, total)
            self.analyze_response(msg)
        
        # Done
        self.panel.update_status("Scan complete! (%d URLs)" % total, total, total)
        self._stdout.println("[JS Analyzer] Scan complete: %d URLs" % total)
    
    def analyze_response(self, message_info):
        response = message_info.getResponse()
        if not response:
            return
        
        try:
            req_info = self._helpers.analyzeRequest(message_info)
            url = str(req_info.getUrl())
            source_name = url.split('/')[-1].split('?')[0] if '/' in url else url
            if len(source_name) > 50:
                source_name = source_name[:50]
            
            self.http_messages[source_name] = message_info
            
            # Add to scanned URLs
            resp_info = self._helpers.analyzeResponse(response)
            status = resp_info.getStatusCode()
            length = len(response)
            self.scanned_urls.append({
                "url": url,
                "source": source_name,
                "status": status,
                "length": length
            })
            self.panel.add_scanned_url(url, source_name, status, length)
            
        except Exception as e:
            self._stdout.println("[JS Analyzer] Error: " + str(e))
            url = "Unknown"
            source_name = "Unknown"
        
        resp_info = self._helpers.analyzeResponse(response)
        body_offset = resp_info.getBodyOffset()
        body = self._helpers.bytesToString(response[body_offset:])
        
        if len(body) < 50:
            return
        
        new_findings = []
        
        # Endpoints
        for pattern in ENDPOINT_PATTERNS:
            for match in pattern.finditer(body):
                value = match.group(1).strip()
                if self._valid_endpoint(value):
                    start = body_offset + match.start(1)
                    end = body_offset + match.end(1)
                    f = self._add("endpoints", value, source_name, url, "", start, end)
                    if f: new_findings.append(f)
        
        # URLs
        for pattern in URL_PATTERNS:
            for match in pattern.finditer(body):
                value = match.group(1).strip() if match.lastindex else match.group(0).strip()
                if self._is_valid_url(value):
                    start = body_offset + match.start(1) if match.lastindex else body_offset + match.start(0)
                    end = body_offset + match.end(1) if match.lastindex else body_offset + match.end(0)
                    f = self._add("urls", value, source_name, url, "", start, end)
                    if f: new_findings.append(f)
        
        # Secrets
        for pattern, stype in SECRET_PATTERNS:
            for match in pattern.finditer(body):
                value = match.group(1).strip()
                if self._valid_secret(value):
                    start = body_offset + match.start(1)
                    end = body_offset + match.end(1)
                    f = self._add("secrets", value, source_name, url, stype, start, end)
                    if f: new_findings.append(f)
        
        # Emails
        for match in EMAIL_PATTERN.finditer(body):
            value = match.group(1).strip()
            if self._valid_email(value):
                start = body_offset + match.start(1)
                end = body_offset + match.end(1)
                f = self._add("emails", value, source_name, url, "", start, end)
                if f: new_findings.append(f)
        
        # Files
        for match in FILE_PATTERNS.finditer(body):
            value = match.group(1).strip()
            if self._valid_file(value):
                start = body_offset + match.start(1)
                end = body_offset + match.end(1)
                f = self._add("files", value, source_name, url, "", start, end)
                if f: new_findings.append(f)
        
        if new_findings:
            self.panel.add_findings(new_findings, source_name)
    
    def _add(self, cat, value, source, url, stype, start, end):
        key = cat + ":" + value
        if key in self.seen_values:
            return None
        self.seen_values.add(key)
        f = {
            "category": cat, "value": value, "source": source, 
            "full_url": url, "secret_type": stype, "start": start, "end": end
        }
        self.all_findings.append(f)
        return f
    
    def _valid_endpoint(self, v):
        if not v or len(v) < 3 or not v.startswith('/'):
            return False
        for p in NOISE_PATTERNS:
            if p.search(v):
                return False
        return True
    
    def _is_valid_url(self, v):
        if not v or len(v) < 15:
            return False
        vl = v.lower()
        for d in NOISE_DOMAINS:
            if d in vl:
                return False
        if '{' in v or 'undefined' in vl or vl.startswith('data:'):
            return False
        if any(vl.endswith(x) for x in ['.css', '.png', '.jpg', '.gif', '.svg', '.woff', '.ico']):
            return False
        return True
    
    def _valid_secret(self, v):
        if not v or len(v) < 8:
            return False
        vl = v.lower()
        if any(x in vl for x in ['example', 'placeholder', 'your_', 'xxxx', 'test', 'dummy', 'sample', 'foo', 'bar']):
            return False
        return True
    
    def _valid_email(self, v):
        if not v or '@' not in v:
            return False
        domain = v.split('@')[-1].lower()
        if domain in {'example.com', 'test.com', 'domain.com', 'email.com'}:
            return False
        return True
    
    def _valid_file(self, v):
        if not v or len(v) < 3:
            return False
        vl = v.lower()
        if any(x in vl for x in ['package.json', 'webpack', 'node_modules', '.min.', 'polyfill']):
            return False
        return True
    
    def get_http_message(self, source):
        return self.http_messages.get(source)
    
    def set_current_message(self, msg):
        self._current_message = msg
    
    def clear_results(self):
        self.all_findings = []
        self.seen_values = set()
        self.http_messages = {}
        self.scanned_urls = []
        self._current_message = None


class AnalyzeAction(ActionListener):
    def __init__(self, ext, messages):
        self.ext = ext
        self.messages = messages
    
    def actionPerformed(self, e):
        import threading
        def run():
            self.ext.analyze_messages(self.messages)
        t = threading.Thread(target=run)
        t.start()


# ==================== UI PANEL ====================
class ResultsPanel(JPanel):
    
    def __init__(self, callbacks, extender):
        JPanel.__init__(self)
        self.callbacks = callbacks
        self.extender = extender
        self.findings = {"endpoints": [], "urls": [], "secrets": [], "emails": [], "files": []}
        self.sources = set()
        self._build_ui()
    
    def _build_ui(self):
        self.setLayout(BorderLayout(5, 5))
        
        # Header with stats and controls
        header = JPanel(BorderLayout())
        header.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        
        # Left - Stats
        left = JPanel(FlowLayout(FlowLayout.LEFT, 5, 0))
        left.add(JLabel("JS Analyzer Enhanced"))
        self.stats = JLabel("| E:0 | U:0 | S:0 | M:0 | F:0")
        left.add(self.stats)
        header.add(left, BorderLayout.WEST)
        
        # Center - Progress
        center = JPanel(FlowLayout(FlowLayout.CENTER, 5, 0))
        self.status_label = JLabel("Ready")
        self.status_label.setFont(Font("SansSerif", Font.BOLD, 11))
        center.add(self.status_label)
        self.progress_bar = JProgressBar(0, 100)
        self.progress_bar.setPreferredSize(Dimension(150, 20))
        self.progress_bar.setStringPainted(True)
        center.add(self.progress_bar)
        header.add(center, BorderLayout.CENTER)
        
        # Right - Controls
        right = JPanel(FlowLayout(FlowLayout.RIGHT, 5, 0))
        right.add(JLabel("Search:"))
        self.search = JTextField(10)
        self.search.addKeyListener(SearchListener(self))
        right.add(self.search)
        
        right.add(JLabel("Source:"))
        self.source_filter = JComboBox(["All"])
        self.source_filter.setPreferredSize(Dimension(100, 25))
        self.source_filter.addActionListener(FilterListener(self))
        right.add(self.source_filter)
        
        for txt, action in [("Copy All", CopyAllAction(self)), ("CSV", CSVAction(self)), 
                            ("JSON", JSONAction(self)), ("Clear", ClearAction(self))]:
            b = JButton(txt)
            b.addActionListener(action)
            right.add(b)
        
        header.add(right, BorderLayout.EAST)
        self.add(header, BorderLayout.NORTH)
        
        # Main split
        split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        split.setResizeWeight(0.5)
        
        # Category tabs - Original first
        self.tabs = JTabbedPane()
        self.tables = {}
        self.models = {}
        
        # Original URLs tab (FIRST)
        orig_panel = JPanel(BorderLayout())
        orig_cols = ["URL", "Source", "Status", "Length"]
        self.orig_model = TableModel(orig_cols, 0)
        self.orig_table = JTable(self.orig_model)
        self.orig_table.setAutoCreateRowSorter(True)
        self.orig_table.setFont(Font("Monospaced", Font.PLAIN, 11))
        self.orig_table.getColumnModel().getColumn(0).setPreferredWidth(500)
        self.orig_table.getColumnModel().getColumn(1).setPreferredWidth(150)
        self.orig_table.getColumnModel().getColumn(2).setPreferredWidth(50)
        self.orig_table.getColumnModel().getColumn(3).setPreferredWidth(80)
        self.orig_table.getSelectionModel().addListSelectionListener(OriginalSelectionListener(self))
        self.orig_table.addMouseListener(OriginalMouseListener(self, self.orig_table))
        orig_panel.add(JScrollPane(self.orig_table), BorderLayout.CENTER)
        self.tabs.addTab("Original (0)", orig_panel)
        
        # Finding tabs
        for title, key in [("Endpoints", "endpoints"), ("URLs", "urls"), ("Secrets", "secrets"), 
                           ("Emails", "emails"), ("Files", "files")]:
            p = JPanel(BorderLayout())
            cols = ["Value", "Type", "Source", "URL"] if key == "secrets" else ["Value", "Source", "URL"]
            m = TableModel(cols, 0)
            self.models[key] = m
            t = JTable(m)
            t.setAutoCreateRowSorter(True)
            t.setFont(Font("Monospaced", Font.PLAIN, 12))
            t.getSelectionModel().addListSelectionListener(SelectionListener(self, key))
            t.addMouseListener(TableMouseListener(self, t, key))
            self.tables[key] = t
            p.add(JScrollPane(t), BorderLayout.CENTER)
            self.tabs.addTab(title + " (0)", p)
        
        split.setTopComponent(self.tabs)
        
        # Burp native viewer
        rr_tabs = JTabbedPane()
        self.request_editor = self.callbacks.createMessageEditor(self.extender, False)
        self.response_editor = self.callbacks.createMessageEditor(self.extender, False)
        rr_tabs.addTab("Request", self.request_editor.getComponent())
        rr_tabs.addTab("Response", self.response_editor.getComponent())
        split.setBottomComponent(rr_tabs)
        
        self.add(split, BorderLayout.CENTER)
    
    def update_status(self, text, current, total):
        """Update progress bar and status from any thread."""
        def update():
            self.status_label.setText(text)
            if total > 0:
                percent = int((current * 100) / total)
                self.progress_bar.setValue(percent)
                self.progress_bar.setString("%d/%d" % (current, total))
            else:
                self.progress_bar.setValue(0)
                self.progress_bar.setString("")
        SwingUtilities.invokeLater(update)
    
    def add_scanned_url(self, url, source, status, length):
        """Add URL to Original tab."""
        def update():
            self.orig_model.addRow([url, source, str(status), str(length)])
            self.tabs.setTitleAt(0, "Original (%d)" % self.orig_model.getRowCount())
        SwingUtilities.invokeLater(update)
    
    def add_findings(self, new_findings, source):
        def update():
            if source and source not in self.sources:
                self.sources.add(source)
                self.source_filter.addItem(source)
            
            for f in new_findings:
                cat = f.get("category", "")
                if cat in self.findings:
                    self.findings[cat].append(f)
            
            self._refresh()
        SwingUtilities.invokeLater(update)
    
    def _refresh(self):
        src = str(self.source_filter.getSelectedItem())
        search = self.search.getText().lower().strip()
        
        titles = ["Endpoints", "URLs", "Secrets", "Emails", "Files"]
        keys = ["endpoints", "urls", "secrets", "emails", "files"]
        
        for i, (title, key) in enumerate(zip(titles, keys)):
            m = self.models[key]
            m.setRowCount(0)
            count = 0
            for item in self.findings.get(key, []):
                if src != "All" and item.get("source") != src:
                    continue
                if search and search not in item.get("value", "").lower():
                    continue
                
                if key == "secrets":
                    m.addRow([item.get("value"), item.get("secret_type"), item.get("source"), item.get("full_url")])
                else:
                    m.addRow([item.get("value"), item.get("source"), item.get("full_url")])
                count += 1
            
            # Tab index is +1 because Original is first
            self.tabs.setTitleAt(i + 1, "%s (%d)" % (title, count))
        
        self._update_stats()
    
    def _update_stats(self):
        e, u, s, m, f = [len(self.findings.get(k, [])) for k in ["endpoints", "urls", "secrets", "emails", "files"]]
        self.stats.setText("| E:%d | U:%d | S:%d | M:%d | F:%d" % (e, u, s, m, f))
    
    def _current_key(self):
        idx = self.tabs.getSelectedIndex()
        if idx == 0:  # Original tab
            return "original"
        keys = ["endpoints", "urls", "secrets", "emails", "files"]
        return keys[idx - 1] if 0 < idx <= len(keys) else None
    
    def _current_table(self):
        key = self._current_key()
        if key == "original":
            return self.orig_table
        return self.tables.get(key) if key else None
    
    def show_request_response(self, source, value=None):
        """Display request/response with highlighting."""
        finding = None
        if value:
            for cat_findings in self.findings.values():
                for f in cat_findings:
                    if f.get("source") == source and f.get("value") == value:
                        finding = f
                        break
                if finding:
                    break
        
        msg = self.extender.get_http_message(source)
        if msg:
            self.extender.set_current_message(msg)
            
            if msg.getRequest():
                self.request_editor.setMessage(msg.getRequest(), True)
            
            if msg.getResponse():
                if finding and finding.get("start", 0) > 0:
                    try:
                        markers = ArrayList()
                        markers.add([finding.get("start"), finding.get("end")])
                        marked_msg = self.callbacks.applyMarkers(msg, None, markers)
                        self.response_editor.setMessage(marked_msg.getResponse(), False)
                    except:
                        self.response_editor.setMessage(msg.getResponse(), False)
                else:
                    self.response_editor.setMessage(msg.getResponse(), False)
    
    def delete_selected(self, table, key):
        row = table.getSelectedRow()
        if row >= 0:
            model_row = table.convertRowIndexToModel(row)
            value = table.getModel().getValueAt(model_row, 0)
            self.findings[key] = [f for f in self.findings[key] if f.get("value") != value]
            self.extender.seen_values.discard(key + ":" + str(value))
            self._refresh()
    
    def delete_original(self, table):
        row = table.getSelectedRow()
        if row >= 0:
            model_row = table.convertRowIndexToModel(row)
            self.orig_model.removeRow(model_row)
            self.tabs.setTitleAt(0, "Original (%d)" % self.orig_model.getRowCount())
    
    def copy_value(self, table, col=0):
        row = table.getSelectedRow()
        if row >= 0:
            model_row = table.convertRowIndexToModel(row)
            value = table.getModel().getValueAt(model_row, col)
            self._copy(str(value))
    
    def copy_row(self, table):
        row = table.getSelectedRow()
        if row >= 0:
            model_row = table.convertRowIndexToModel(row)
            m = table.getModel()
            data = [str(m.getValueAt(model_row, i)) for i in range(m.getColumnCount())]
            self._copy(" | ".join(data))
    
    def _copy(self, text):
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(text), None)
    
    def copy_all(self):
        t = self._current_table()
        if t:
            m = t.getModel()
            vals = [str(m.getValueAt(i, 0)) for i in range(m.getRowCount())]
            self._copy("\n".join(vals))
    
    def export_csv(self):
        ch = JFileChooser()
        ch.setSelectedFile(File("js_findings.csv"))
        if ch.showSaveDialog(self) == JFileChooser.APPROVE_OPTION:
            path = ch.getSelectedFile().getAbsolutePath()
            if not path.endswith('.csv'): path += '.csv'
            try:
                w = BufferedWriter(FileWriter(path))
                w.write("Category,Value,Type,Source,URL\n")
                
                # Original URLs
                for i in range(self.orig_model.getRowCount()):
                    url = str(self.orig_model.getValueAt(i, 0)).replace('"', '""')
                    src = str(self.orig_model.getValueAt(i, 1)).replace('"', '""')
                    w.write('"original","%s","","%s","%s"\n' % (url, src, url))
                
                # Findings
                for cat, items in self.findings.items():
                    for item in items:
                        v = item.get("value", "").replace('"', '""')
                        st = item.get("secret_type", "").replace('"', '""')
                        s = item.get("source", "").replace('"', '""')
                        u = item.get("full_url", "").replace('"', '""')
                        w.write('"%s","%s","%s","%s","%s"\n' % (cat, v, st, s, u))
                w.close()
                JOptionPane.showMessageDialog(self, "Saved: " + path)
            except Exception as e:
                JOptionPane.showMessageDialog(self, "Error: " + str(e))
    
    def export_json(self):
        ch = JFileChooser()
        ch.setSelectedFile(File("js_findings.json"))
        if ch.showSaveDialog(self) == JFileChooser.APPROVE_OPTION:
            path = ch.getSelectedFile().getAbsolutePath()
            if not path.endswith('.json'): path += '.json'
            try:
                export = {"original_urls": self.extender.scanned_urls}
                for cat, items in self.findings.items():
                    export[cat] = [{"value": i.get("value"), "source": i.get("source"), 
                                   "url": i.get("full_url"), "type": i.get("secret_type", "")} for i in items]
                fp = open(path, 'w')
                json.dump(export, fp, indent=2)
                fp.close()
                JOptionPane.showMessageDialog(self, "Saved: " + path)
            except Exception as e:
                JOptionPane.showMessageDialog(self, "Error: " + str(e))
    
    def clear_all(self):
        for k in self.findings: self.findings[k] = []
        self.sources = set()
        self.source_filter.removeAllItems()
        self.source_filter.addItem("All")
        self.search.setText("")
        self.orig_model.setRowCount(0)
        self.tabs.setTitleAt(0, "Original (0)")
        self.request_editor.setMessage(None, True)
        self.response_editor.setMessage(None, False)
        self.status_label.setText("Ready")
        self.progress_bar.setValue(0)
        self.progress_bar.setString("")
        self.extender.clear_results()
        self._refresh()


class TableModel(DefaultTableModel):
    def __init__(self, cols, rows):
        DefaultTableModel.__init__(self, cols, rows)
    def isCellEditable(self, r, c):
        return False


class OriginalSelectionListener(ListSelectionListener):
    def __init__(self, panel):
        self.panel = panel
    def valueChanged(self, e):
        if e.getValueIsAdjusting(): return
        t = self.panel.orig_table
        if t.getSelectedRow() >= 0:
            row = t.convertRowIndexToModel(t.getSelectedRow())
            src = t.getModel().getValueAt(row, 1)
            if src:
                self.panel.show_request_response(str(src))


class SelectionListener(ListSelectionListener):
    def __init__(self, panel, key):
        self.panel = panel
        self.key = key
    def valueChanged(self, e):
        if e.getValueIsAdjusting(): return
        t = self.panel.tables.get(self.key)
        if t and t.getSelectedRow() >= 0:
            row = t.convertRowIndexToModel(t.getSelectedRow())
            src_col = 2 if self.key == "secrets" else 1
            src = t.getModel().getValueAt(row, src_col)
            value = t.getModel().getValueAt(row, 0)
            if src:
                self.panel.show_request_response(str(src), str(value))


class OriginalMouseListener(MouseAdapter):
    def __init__(self, panel, table):
        self.panel = panel
        self.table = table
    def mousePressed(self, e): self._popup(e)
    def mouseReleased(self, e): self._popup(e)
    def _popup(self, e):
        if e.isPopupTrigger():
            row = self.table.rowAtPoint(e.getPoint())
            if row >= 0:
                self.table.setRowSelectionInterval(row, row)
            popup = JPopupMenu()
            for txt, col in [("Copy URL", 0), ("Copy Source", 1)]:
                item = JMenuItem(txt)
                item.addActionListener(CopyColAction(self.panel, self.table, col))
                popup.add(item)
            popup.addSeparator()
            delete = JMenuItem("Delete")
            delete.addActionListener(DeleteOrigAction(self.panel, self.table))
            popup.add(delete)
            popup.show(e.getComponent(), e.getX(), e.getY())


class TableMouseListener(MouseAdapter):
    def __init__(self, panel, table, key):
        self.panel = panel
        self.table = table
        self.key = key
    def mousePressed(self, e): self._popup(e)
    def mouseReleased(self, e): self._popup(e)
    def _popup(self, e):
        if e.isPopupTrigger():
            row = self.table.rowAtPoint(e.getPoint())
            if row >= 0:
                self.table.setRowSelectionInterval(row, row)
            popup = JPopupMenu()
            for txt, action in [("Copy Value", PopupAction(self.panel, self.table, self.key, "value")),
                               ("Copy URL", PopupAction(self.panel, self.table, self.key, "url")),
                               ("Copy Source", PopupAction(self.panel, self.table, self.key, "source")),
                               ("Copy Row", PopupAction(self.panel, self.table, self.key, "row"))]:
                item = JMenuItem(txt)
                item.addActionListener(action)
                popup.add(item)
            popup.addSeparator()
            delete = JMenuItem("Delete")
            delete.addActionListener(PopupAction(self.panel, self.table, self.key, "delete"))
            popup.add(delete)
            popup.show(e.getComponent(), e.getX(), e.getY())


class PopupAction(ActionListener):
    def __init__(self, panel, table, key, action):
        self.panel, self.table, self.key, self.action = panel, table, key, action
    def actionPerformed(self, e):
        if self.action == "value":
            self.panel.copy_value(self.table, 0)
        elif self.action == "url":
            col = 3 if self.key == "secrets" else 2
            self.panel.copy_value(self.table, col)
        elif self.action == "source":
            col = 2 if self.key == "secrets" else 1
            self.panel.copy_value(self.table, col)
        elif self.action == "row":
            self.panel.copy_row(self.table)
        elif self.action == "delete":
            self.panel.delete_selected(self.table, self.key)


class CopyColAction(ActionListener):
    def __init__(self, panel, table, col):
        self.panel, self.table, self.col = panel, table, col
    def actionPerformed(self, e):
        self.panel.copy_value(self.table, self.col)


class DeleteOrigAction(ActionListener):
    def __init__(self, panel, table):
        self.panel, self.table = panel, table
    def actionPerformed(self, e):
        self.panel.delete_original(self.table)


class SearchListener(KeyListener):
    def __init__(self, p): self.p = p
    def keyPressed(self, e): pass
    def keyReleased(self, e): self.p._refresh()
    def keyTyped(self, e): pass


class FilterListener(ActionListener):
    def __init__(self, p): self.p = p
    def actionPerformed(self, e): self.p._refresh()


class CopyAllAction(ActionListener):
    def __init__(self, p): self.p = p
    def actionPerformed(self, e): self.p.copy_all()


class CSVAction(ActionListener):
    def __init__(self, p): self.p = p
    def actionPerformed(self, e): self.p.export_csv()


class JSONAction(ActionListener):
    def __init__(self, p): self.p = p
    def actionPerformed(self, e): self.p.export_json()


class ClearAction(ActionListener):
    def __init__(self, p): self.p = p
    def actionPerformed(self, e): self.p.clear_all()
