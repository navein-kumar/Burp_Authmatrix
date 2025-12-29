# IDORPathComparer v3 - Burp Suite Extension for IDOR Detection
# Compare URLs/Paths between sessions with Request/Response viewer
# Author: CodeSecure Solutions

# ============ DEBUG FLAG ============
DEBUG = False  # Set to True to enable debug output
# ====================================

from burp import IBurpExtender, ITab, IContextMenuFactory, IHttpListener, IMessageEditorController
from javax.swing import (JPanel, JTable, JScrollPane, JButton, JSplitPane, 
                         JLabel, JTextField, JComboBox, BorderFactory, JFileChooser,
                         JOptionPane, SwingConstants, Box, BoxLayout, JCheckBox,
                         ListSelectionModel, JPopupMenu, JMenuItem, JTextArea,
                         JTabbedPane, SwingUtilities, DefaultComboBoxModel)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.swing.event import ListSelectionListener
from java.awt import BorderLayout, FlowLayout, Color, Dimension, Font
from java.awt.event import MouseAdapter
from java.util import ArrayList
from java.lang import Thread, Runnable
import re
import csv
from collections import defaultdict


def debug(msg):
    """Print debug message if DEBUG is enabled"""
    if DEBUG:
        print(msg)


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IHttpListener, IMessageEditorController):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("IDOR Path Comparer")
        
        # Storage
        self.session_data = defaultdict(list)
        self.captured_sessions = set()
        self.comparison_results = []
        
        # Current selected request for message editor
        self._current_request = None
        self._current_response = None
        
        # Create UI
        self._create_ui()
        
        # Register
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)
        
        print("[+] IDOR Path Comparer v3 loaded!")
        
    def _create_ui(self):
        self._panel = JPanel(BorderLayout())
        
        # === TOP CONTROL PANEL ===
        control_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        control_panel.setBorder(BorderFactory.createTitledBorder("Session Selection"))
        
        control_panel.add(JLabel("Session 1:"))
        self.session1_combo = JComboBox()
        self.session1_combo.setPreferredSize(Dimension(120, 25))
        control_panel.add(self.session1_combo)
        
        control_panel.add(JLabel("Session 2:"))
        self.session2_combo = JComboBox()
        self.session2_combo.setPreferredSize(Dimension(120, 25))
        control_panel.add(self.session2_combo)
        
        compare_btn = JButton("Compare", actionPerformed=self._compare_sessions)
        control_panel.add(compare_btn)
        
        refresh_btn = JButton("Refresh", actionPerformed=self._refresh_sessions)
        control_panel.add(refresh_btn)
        
        clear_btn = JButton("Clear", actionPerformed=self._clear_data)
        control_panel.add(clear_btn)
        
        delete_session_btn = JButton("Delete Session", actionPerformed=self._delete_session)
        control_panel.add(delete_session_btn)
        
        export_btn = JButton("Export CSV", actionPerformed=self._export_csv)
        control_panel.add(export_btn)
        
        # Auto-capture checkbox (disabled by default)
        self.auto_capture = JCheckBox("Auto-capture", False)
        self.auto_capture.setToolTipText("Auto-capture requests with X-Session-Tag or X-PwnFox-Color headers")
        control_panel.add(self.auto_capture)
        
        # === FILTER PANEL WITH ALL COLUMN TOGGLES ===
        filter_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        filter_panel.setBorder(BorderFactory.createTitledBorder("Filters & View"))
        
        filter_panel.add(JLabel("Filter:"))
        self.filter_field = JTextField(12)
        filter_panel.add(self.filter_field)
        
        filter_btn = JButton("Apply", actionPerformed=self._apply_filter)
        filter_panel.add(filter_btn)
        
        self.show_ids_only = JCheckBox("IDs only", False, actionPerformed=self._apply_filter)
        filter_panel.add(self.show_ids_only)
        
        self.show_diff_only = JCheckBox("Diff only", True, actionPerformed=self._apply_filter)
        filter_panel.add(self.show_diff_only)
        
        # ALL Column visibility toggles
        filter_panel.add(JLabel(" | Show:"))
        
        self.show_num_col = JCheckBox("#", True, actionPerformed=self._toggle_columns)
        filter_panel.add(self.show_num_col)
        
        self.show_status_col = JCheckBox("Status", False, actionPerformed=self._toggle_columns)
        filter_panel.add(self.show_status_col)
        
        self.show_method_col = JCheckBox("Method", True, actionPerformed=self._toggle_columns)
        filter_panel.add(self.show_method_col)
        
        self.show_host_col = JCheckBox("Host", False, actionPerformed=self._toggle_columns)
        filter_panel.add(self.show_host_col)
        
        self.show_path_col = JCheckBox("Path", True, actionPerformed=self._toggle_columns)
        filter_panel.add(self.show_path_col)
        
        self.show_ids_col = JCheckBox("IDs", False, actionPerformed=self._toggle_columns)
        filter_panel.add(self.show_ids_col)
        
        self.show_url_col = JCheckBox("URL", False, actionPerformed=self._toggle_columns)
        filter_panel.add(self.show_url_col)
        
        self.show_params_col = JCheckBox("Params", False, actionPerformed=self._toggle_columns)
        filter_panel.add(self.show_params_col)
        
        # Top panels
        top_panel = JPanel()
        top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
        top_panel.add(control_panel)
        top_panel.add(filter_panel)
        
        # === SESSION 1 TABLE (Red) ===
        session1_panel = JPanel(BorderLayout())
        self.session1_label = JLabel("Session 1")
        self.session1_label.setBorder(BorderFactory.createEmptyBorder(3, 5, 3, 5))
        self.session1_label.setForeground(Color(180, 0, 0))
        self.session1_label.setFont(self.session1_label.getFont().deriveFont(Font.BOLD))
        session1_panel.add(self.session1_label, BorderLayout.NORTH)
        
        self.session1_model = DefaultTableModel(
            ["#", "Status", "Method", "Host", "Path", "IDs", "Full URL", "Params"],
            0
        )
        self.session1_table = JTable(self.session1_model)
        self.session1_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.session1_table.setAutoCreateRowSorter(True)
        self.session1_table.getColumnModel().getColumn(1).setCellRenderer(StatusCellRenderer())
        self.session1_table.getSelectionModel().addListSelectionListener(
            TableSelectionListener(self, self.session1_table, self.session1_model, 1))
        self._setup_table_menu(self.session1_table, self.session1_model)
        
        session1_scroll = JScrollPane(self.session1_table)
        session1_scroll.setBorder(BorderFactory.createMatteBorder(2, 2, 2, 2, Color(200, 50, 50)))
        session1_panel.add(session1_scroll, BorderLayout.CENTER)
        
        # === SESSION 2 TABLE (Green) ===
        session2_panel = JPanel(BorderLayout())
        self.session2_label = JLabel("Session 2")
        self.session2_label.setBorder(BorderFactory.createEmptyBorder(3, 5, 3, 5))
        self.session2_label.setForeground(Color(0, 130, 0))
        self.session2_label.setFont(self.session2_label.getFont().deriveFont(Font.BOLD))
        session2_panel.add(self.session2_label, BorderLayout.NORTH)
        
        self.session2_model = DefaultTableModel(
            ["#", "Status", "Method", "Host", "Path", "IDs", "Full URL", "Params"],
            0
        )
        self.session2_table = JTable(self.session2_model)
        self.session2_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.session2_table.setAutoCreateRowSorter(True)
        self.session2_table.getColumnModel().getColumn(1).setCellRenderer(StatusCellRenderer())
        self.session2_table.getSelectionModel().addListSelectionListener(
            TableSelectionListener(self, self.session2_table, self.session2_model, 2))
        self._setup_table_menu(self.session2_table, self.session2_model)
        
        session2_scroll = JScrollPane(self.session2_table)
        session2_scroll.setBorder(BorderFactory.createMatteBorder(2, 2, 2, 2, Color(50, 150, 50)))
        session2_panel.add(session2_scroll, BorderLayout.CENTER)
        
        # Split pane for two session tables
        tables_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, session1_panel, session2_panel)
        tables_split.setResizeWeight(0.5)
        tables_split.setDividerSize(5)
        
        # === REQUEST/RESPONSE VIEWER PANEL ===
        viewer_panel = JPanel(BorderLayout())
        viewer_panel.setBorder(BorderFactory.createTitledBorder("Request / Response Viewer"))
        
        # Session tabs (Original, Session1, Session2)
        self.session_tabs = JTabbedPane()
        
        # Original tab
        original_panel = JPanel(BorderLayout())
        self.original_req_resp_tabs = JTabbedPane()
        self.original_request_editor = self._callbacks.createMessageEditor(self, True)
        self.original_response_editor = self._callbacks.createMessageEditor(self, False)
        self.original_req_resp_tabs.addTab("Request", self.original_request_editor.getComponent())
        self.original_req_resp_tabs.addTab("Response", self.original_response_editor.getComponent())
        original_panel.add(self.original_req_resp_tabs, BorderLayout.CENTER)
        self.session_tabs.addTab("Original", original_panel)
        
        # Modified/Resend tab
        modified_panel = JPanel(BorderLayout())
        self.modified_req_resp_tabs = JTabbedPane()
        self.modified_request_editor = self._callbacks.createMessageEditor(self, True)
        self.modified_response_editor = self._callbacks.createMessageEditor(self, False)
        self.modified_req_resp_tabs.addTab("Request", self.modified_request_editor.getComponent())
        self.modified_req_resp_tabs.addTab("Response", self.modified_response_editor.getComponent())
        
        # Send button panel with color feedback buttons
        send_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        self.send_btn = JButton("Send Request", actionPerformed=self._send_modified_request)
        self.send_btn.setOpaque(True)
        send_panel.add(self.send_btn)
        
        self.reset_btn = JButton("Reset to Original", actionPerformed=self._reset_to_original)
        self.reset_btn.setOpaque(True)
        send_panel.add(self.reset_btn)
        
        self.send_repeater_btn = JButton("Send to Repeater", actionPerformed=self._send_current_to_repeater)
        self.send_repeater_btn.setOpaque(True)
        send_panel.add(self.send_repeater_btn)
        
        # Store default button color
        self._default_btn_color = self.send_btn.getBackground()
        
        modified_panel.add(send_panel, BorderLayout.NORTH)
        modified_panel.add(self.modified_req_resp_tabs, BorderLayout.CENTER)
        self.session_tabs.addTab("Edit & Send", modified_panel)
        
        viewer_panel.add(self.session_tabs, BorderLayout.CENTER)
        
        # Stats label
        self.stats_label = JLabel("Click Compare to see results")
        self.stats_label.setBorder(BorderFactory.createEmptyBorder(3, 5, 3, 5))
        viewer_panel.add(self.stats_label, BorderLayout.SOUTH)
        
        # === MAIN SPLIT: Tables on top, Viewer on bottom ===
        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, tables_split, viewer_panel)
        main_split.setResizeWeight(0.5)
        main_split.setDividerSize(5)
        
        # Main layout
        self._panel.add(top_panel, BorderLayout.NORTH)
        self._panel.add(main_split, BorderLayout.CENTER)
        
    def _toggle_columns(self, event=None):
        """Show/hide columns based on checkboxes"""
        column_config = [
            (0, self.show_num_col, 40),       # #
            (1, self.show_status_col, 80),    # Status
            (2, self.show_method_col, 60),    # Method
            (3, self.show_host_col, 150),     # Host
            (4, self.show_path_col, 400),     # Path (with params)
            (5, self.show_ids_col, 120),      # IDs
            (6, self.show_url_col, 300),      # Full URL
            (7, self.show_params_col, 150),   # Params
        ]
        
        for table in [self.session1_table, self.session2_table]:
            for col_idx, checkbox, default_width in column_config:
                col = table.getColumnModel().getColumn(col_idx)
                if checkbox.isSelected():
                    col.setMinWidth(20)
                    col.setMaxWidth(5000)  # Allow much wider columns
                    col.setPreferredWidth(default_width)
                    col.setResizable(True)
                else:
                    col.setMinWidth(0)
                    col.setMaxWidth(0)
                    col.setPreferredWidth(0)
                    col.setResizable(False)
            
            # Enable auto-resize off so columns can be manually resized
            from javax.swing import JTable
            table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
                    
            table.revalidate()
            table.repaint()
            
    def _setup_table_menu(self, table, model):
        """Setup right-click menu"""
        popup = JPopupMenu()
        
        send_repeater = JMenuItem("Send to Repeater", 
            actionPerformed=lambda e: self._send_table_to_repeater(table, model))
        popup.add(send_repeater)
        
        copy_urls = JMenuItem("Copy URLs", 
            actionPerformed=lambda e: self._copy_table_urls(table, model))
        popup.add(copy_urls)
        
        copy_paths = JMenuItem("Copy Paths", 
            actionPerformed=lambda e: self._copy_table_paths(table, model))
        popup.add(copy_paths)
        
        popup.addSeparator()
        
        delete_item = JMenuItem("Delete Selected", 
            actionPerformed=lambda e: self._delete_selected_requests(table, model))
        popup.add(delete_item)
        
        class PopupListener(MouseAdapter):
            def __init__(self, tbl, pp):
                self.table = tbl
                self.popup = pp
                
            def mousePressed(self, e):
                if e.isPopupTrigger():
                    self.popup.show(e.getComponent(), e.getX(), e.getY())
                
            def mouseReleased(self, e):
                if e.isPopupTrigger():
                    self.popup.show(e.getComponent(), e.getX(), e.getY())
        
        table.addMouseListener(PopupListener(table, popup))
    
    def _set_button_color(self, button, color):
        """Set button background color on EDT"""
        def update():
            button.setBackground(color)
            button.repaint()
        SwingUtilities.invokeLater(update)
        
    def _reset_button_color(self, button, delay_ms=1500):
        """Reset button color after delay"""
        default_color = self._default_btn_color
        def reset():
            import time
            time.sleep(delay_ms / 1000.0)
            SwingUtilities.invokeLater(lambda: button.setBackground(default_color))
            SwingUtilities.invokeLater(lambda: button.repaint())
        Thread(lambda: reset()).start()
        
    def _load_request_to_viewer(self, url):
        """Load request/response into the viewer"""
        # Find the request data
        req_data = None
        for session_tag, requests in self.session_data.items():
            for req in requests:
                if req['full_url'] == url:
                    req_data = req
                    break
            if req_data:
                break
                
        if not req_data:
            return
            
        # Store current request info
        self._current_request = req_data.get('request')
        self._current_response = req_data.get('response')
        self._current_host = req_data.get('host')
        self._current_port = req_data.get('port')
        self._current_protocol = req_data.get('protocol')
        
        # Fix port if -1 or missing
        if not self._current_port or self._current_port == -1:
            if self._current_protocol and self._current_protocol.lower() == "https":
                self._current_port = 443
            else:
                self._current_port = 80
        
        debug("[*] Loaded: %s://%s:%d" % (self._current_protocol, self._current_host, self._current_port))
        
        # Set original request
        if self._current_request:
            self.original_request_editor.setMessage(self._current_request, True)
            self.modified_request_editor.setMessage(self._current_request, True)
        else:
            self.original_request_editor.setMessage(bytearray(), True)
            self.modified_request_editor.setMessage(bytearray(), True)
            
        # Set response in Original tab only (if available)
        if self._current_response:
            self.original_response_editor.setMessage(self._current_response, False)
        else:
            self.original_response_editor.setMessage(bytearray(), False)
            
        # Clear the Edit & Send response - will be populated after sending
        self.modified_response_editor.setMessage(bytearray(), False)
            
    def _send_modified_request(self, event):
        """Send the modified request and show response"""
        if not self._current_host:
            JOptionPane.showMessageDialog(self._panel, "No request selected")
            return
            
        # Get modified request from editor
        modified_request = self.modified_request_editor.getMessage()
        if not modified_request or len(modified_request) == 0:
            JOptionPane.showMessageDialog(self._panel, "No request to send")
            return
        
        # Set button to yellow (sending)
        self._set_button_color(self.send_btn, Color(255, 255, 150))
        
        # Fix port if needed
        port = self._current_port
        if not port or port == -1:
            port = 443 if self._current_protocol.lower() == "https" else 80
        
        # Store values for thread
        host = str(self._current_host)
        protocol = str(self._current_protocol)
        use_https = (protocol.lower() == "https")
        
        # Copy request bytes
        request_bytes = bytearray(modified_request)
        
        debug("[*] Sending to %s://%s:%d" % (protocol, host, port))
        debug("[*] Request size: %d bytes" % len(request_bytes))
        
        # References for the thread
        callbacks = self._callbacks
        helpers = self._helpers
        response_editor = self.modified_response_editor
        tabs = self.modified_req_resp_tabs
        panel = self._panel
        send_btn = self.send_btn
        default_color = self._default_btn_color
        extender = self
        
        class SendRequestRunnable(Runnable):
            def run(self):
                try:
                    debug("[*] Thread started - building HTTP service...")
                    http_service = helpers.buildHttpService(host, int(port), use_https)
                    
                    debug("[*] Making HTTP request...")
                    http_request_response = callbacks.makeHttpRequest(http_service, bytes(request_bytes))
                    
                    debug("[*] Request completed")
                    
                    if http_request_response is not None:
                        response_bytes = http_request_response.getResponse()
                        
                        if response_bytes is not None and len(response_bytes) > 0:
                            debug("[+] Response received: %d bytes" % len(response_bytes))
                            
                            # Update UI on EDT - green for success
                            resp = response_bytes
                            def update_ui():
                                response_editor.setMessage(resp, False)
                                tabs.setSelectedIndex(1)  # Switch to Response tab
                                send_btn.setBackground(Color(150, 255, 150))  # Green
                                debug("[+] Response displayed")
                            
                            SwingUtilities.invokeLater(update_ui)
                            extender._reset_button_color(send_btn)
                        else:
                            debug("[-] Empty response")
                            SwingUtilities.invokeLater(lambda: send_btn.setBackground(Color(255, 150, 150)))  # Red
                            extender._reset_button_color(send_btn)
                            SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(panel, "Empty response"))
                    else:
                        debug("[-] No response object returned")
                        SwingUtilities.invokeLater(lambda: send_btn.setBackground(Color(255, 150, 150)))  # Red
                        extender._reset_button_color(send_btn)
                        SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(panel, "No response received"))
                        
                except Exception as e:
                    import traceback
                    debug("[-] Exception in thread:")
                    traceback.print_exc()
                    SwingUtilities.invokeLater(lambda: send_btn.setBackground(Color(255, 150, 150)))  # Red
                    extender._reset_button_color(send_btn)
                    SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(panel, "Error: " + str(e)))
        
        # Run in background thread
        thread = Thread(SendRequestRunnable())
        thread.start()
        debug("[*] Request thread started")
            
    def _reset_to_original(self, event):
        """Reset modified request to original"""
        if self._current_request:
            self.modified_request_editor.setMessage(self._current_request, True)
            # Green flash for success
            self._set_button_color(self.reset_btn, Color(150, 255, 150))
            self._reset_button_color(self.reset_btn)
            
    def _send_current_to_repeater(self, event):
        """Send current request to Repeater"""
        if not self._current_host or not self._current_request:
            JOptionPane.showMessageDialog(self._panel, "No request selected")
            return
            
        use_https = (self._current_protocol.lower() == "https")
        request = self.modified_request_editor.getMessage()
        self._callbacks.sendToRepeater(
            self._current_host, 
            self._current_port, 
            use_https, 
            request,
            "IDOR-Compare"
        )
        # Green flash for success
        self._set_button_color(self.send_repeater_btn, Color(150, 255, 150))
        self._reset_button_color(self.send_repeater_btn)
        
    # IMessageEditorController implementation
    def getHttpService(self):
        if self._current_host:
            use_https = (self._current_protocol.lower() == "https")
            return self._helpers.buildHttpService(
                self._current_host, 
                self._current_port, 
                use_https
            )
        return None
        
    def getRequest(self):
        return self._current_request
        
    def getResponse(self):
        return self._current_response
        
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Auto-capture requests with session tags (only if enabled)"""
        if not messageIsRequest:
            return
        
        # Check if auto-capture is enabled
        if not self.auto_capture.isSelected():
            return
            
        request_info = self._helpers.analyzeRequest(messageInfo)
        headers = request_info.getHeaders()
        
        session_tag = None
        for header in headers:
            header_lower = header.lower()
            if header_lower.startswith("x-session-tag:"):
                session_tag = header.split(":", 1)[1].strip()
                break
            elif header_lower.startswith("x-pwnfox-color:"):
                session_tag = "X-Pwnfox-Color: " + header.split(":", 1)[1].strip()
                break
        
        if session_tag:
            url = request_info.getUrl()
            method = request_info.getMethod()
            path = url.getPath() if url.getPath() else "/"
            query = url.getQuery() if url.getQuery() else ""
            full_url = str(url)
            
            # Get response if available
            response = messageInfo.getResponse()
            
            request_data = {
                'method': method,
                'path': path,
                'query': query,
                'full_url': full_url,
                'host': url.getHost(),
                'port': url.getPort(),
                'protocol': url.getProtocol(),
                'request': messageInfo.getRequest(),
                'response': response,
                'ids': self._extract_ids(path + "?" + query if query else path)
            }
            
            self.session_data[session_tag].append(request_data)
            self.captured_sessions.add(session_tag)
            self._update_combos()
            
    def _extract_ids(self, path_with_query):
        """Extract potential IDs"""
        ids = []
        patterns = [
            r'/(\d+)',
            r'/([a-f0-9]{8,})',
            r'/([a-f0-9-]{36})',
            r'[?&]id=([^&]+)',
            r'[?&]user_id=([^&]+)',
            r'[?&]userId=([^&]+)',
            r'[?&]\w*[Ii]d=([^&]+)',
        ]
        for pattern in patterns:
            matches = re.findall(pattern, path_with_query, re.IGNORECASE)
            ids.extend(matches)
        return list(set(ids))
        
    def _normalize_path(self, path):
        """Normalize path by replacing IDs"""
        normalized = path
        normalized = re.sub(r'/\d+', '/{ID}', normalized)
        normalized = re.sub(r'/[a-f0-9-]{36}', '/{UUID}', normalized, flags=re.IGNORECASE)
        normalized = re.sub(r'/[a-f0-9]{8,}', '/{HEX}', normalized, flags=re.IGNORECASE)
        return normalized
        
    def _update_combos(self):
        """Update session dropdowns"""
        current1 = self.session1_combo.getSelectedItem()
        current2 = self.session2_combo.getSelectedItem()
        
        self.session1_combo.removeAllItems()
        self.session2_combo.removeAllItems()
        
        for session in sorted(self.captured_sessions):
            count = len(self.session_data[session])
            item = "%s (%d)" % (session, count)
            self.session1_combo.addItem(item)
            self.session2_combo.addItem(item)
            
        if current1:
            self.session1_combo.setSelectedItem(current1)
        if current2:
            self.session2_combo.setSelectedItem(current2)
            
    def _compare_sessions(self, event):
        """Compare two sessions"""
        sel1 = self.session1_combo.getSelectedItem()
        sel2 = self.session2_combo.getSelectedItem()
        
        if not sel1 or not sel2:
            JOptionPane.showMessageDialog(self._panel, "Select two sessions")
            return
            
        session1 = sel1.rsplit(" (", 1)[0]
        session2 = sel2.rsplit(" (", 1)[0]
        
        if session1 == session2:
            JOptionPane.showMessageDialog(self._panel, "Select different sessions")
            return
            
        # Update labels
        self.session1_label.setText("Session 1: " + session1)
        self.session2_label.setText("Session 2: " + session2)
            
        # Clear
        self.session1_model.setRowCount(0)
        self.session2_model.setRowCount(0)
        
        # Build path dictionaries
        paths1 = {}
        paths2 = {}
        
        for req in self.session_data[session1]:
            norm_path = self._normalize_path(req['path'])
            key = (req['method'], norm_path)
            if key not in paths1:
                paths1[key] = []
            paths1[key].append(req)
            
        for req in self.session_data[session2]:
            norm_path = self._normalize_path(req['path'])
            key = (req['method'], norm_path)
            if key not in paths2:
                paths2[key] = []
            paths2[key].append(req)
            
        all_paths = set(paths1.keys()) | set(paths2.keys())
        stats = {'only_session1': 0, 'only_session2': 0, 'both': 0, 'different_ids': 0}
        
        show_diff = self.show_diff_only.isSelected()
        show_ids = self.show_ids_only.isSelected()
        filter_text = self.filter_field.getText().strip().lower()
        
        # Serial number counters
        s1_serial = 0
        s2_serial = 0
        
        for key in sorted(all_paths):
            method, norm_path = key
            in_s1 = key in paths1
            in_s2 = key in paths2
            
            if filter_text and filter_text not in norm_path.lower():
                continue
            
            s1_ids = []
            s2_ids = []
            
            if in_s1:
                for req in paths1[key]:
                    s1_ids.extend(req['ids'])
            if in_s2:
                for req in paths2[key]:
                    s2_ids.extend(req['ids'])
                    
            s1_ids = list(set(s1_ids))
            s2_ids = list(set(s2_ids))
            
            # Determine status
            if in_s1 and in_s2:
                if set(s1_ids) != set(s2_ids) and (s1_ids or s2_ids):
                    status = "DIFF IDs"
                    stats['different_ids'] += 1
                else:
                    status = "Both"
                    stats['both'] += 1
            elif in_s1:
                status = "Only Here"
                stats['only_session1'] += 1
            else:
                status = "Only Here"
                stats['only_session2'] += 1
                
            # Apply filters
            if show_diff and status == "Both":
                continue
            if show_ids and not s1_ids and not s2_ids:
                continue
                
            # Add to tables with serial numbers
            if in_s1:
                for req in paths1[key]:
                    s1_serial += 1
                    # Build full path with query params
                    full_path = req['path']
                    if req['query']:
                        full_path = full_path + "?" + req['query']
                    self.session1_model.addRow([
                        s1_serial,
                        status if status != "Only Here" else "Only Here",
                        req['method'],
                        req['host'],
                        full_path,
                        ", ".join(req['ids']) if req['ids'] else "-",
                        req['full_url'],
                        req['query'] if req['query'] else "-"
                    ])
                    
            if in_s2:
                for req in paths2[key]:
                    s2_serial += 1
                    # Build full path with query params
                    full_path = req['path']
                    if req['query']:
                        full_path = full_path + "?" + req['query']
                    self.session2_model.addRow([
                        s2_serial,
                        status if status != "Only Here" else "Only Here",
                        req['method'],
                        req['host'],
                        full_path,
                        ", ".join(req['ids']) if req['ids'] else "-",
                        req['full_url'],
                        req['query'] if req['query'] else "-"
                    ])
            
        self.stats_label.setText(
            "%s=%d | %s=%d | Both=%d | DIFF IDs=%d" % (
                session1, stats['only_session1'],
                session2, stats['only_session2'],
                stats['both'], stats['different_ids']
            )
        )
        
        self._toggle_columns()
        
    def _apply_filter(self, event):
        self._compare_sessions(event)
        
    def _refresh_sessions(self, event):
        """Refresh session dropdown counts only - does NOT add new requests"""
        self._update_combos()
        total = sum(len(reqs) for reqs in self.session_data.values())
        JOptionPane.showMessageDialog(self._panel, 
            "Sessions: %d | Total requests: %d" % (len(self.captured_sessions), total))
        
    def _clear_data(self, event):
        if JOptionPane.showConfirmDialog(self._panel, "Clear all?", "Confirm", 
            JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION:
            self.session_data.clear()
            self.captured_sessions.clear()
            self.session1_model.setRowCount(0)
            self.session2_model.setRowCount(0)
            self._update_combos()
            self.stats_label.setText("Cleared")
            self.session1_label.setText("Session 1")
            self.session2_label.setText("Session 2")
            
    def _delete_session(self, event):
        """Delete a session tag and all its requests"""
        if not self.captured_sessions:
            JOptionPane.showMessageDialog(self._panel, "No sessions to delete")
            return
            
        # Create combo box with sessions
        session_combo = JComboBox()
        for tag in sorted(self.captured_sessions):
            count = len(self.session_data[tag])
            session_combo.addItem("%s (%d requests)" % (tag, count))
        
        result = JOptionPane.showConfirmDialog(
            self._panel,
            session_combo,
            "Select session to delete:",
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.WARNING_MESSAGE
        )
        
        if result != JOptionPane.OK_OPTION:
            return
            
        selected = session_combo.getSelectedItem()
        if not selected:
            return
            
        # Extract tag name (remove count)
        session_tag = selected.rsplit(" (", 1)[0]
        
        # Confirm deletion
        confirm = JOptionPane.showConfirmDialog(
            self._panel,
            "Delete session '%s' and all its requests?" % session_tag,
            "Confirm Delete",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE
        )
        
        if confirm == JOptionPane.YES_OPTION:
            # Remove from data
            if session_tag in self.session_data:
                del self.session_data[session_tag]
            self.captured_sessions.discard(session_tag)
            
            # Clear tables if deleted session was displayed
            self.session1_model.setRowCount(0)
            self.session2_model.setRowCount(0)
            
            self._update_combos()
            JOptionPane.showMessageDialog(self._panel, "Session '%s' deleted" % session_tag)
            
    def _export_csv(self, event):
        if self.session1_model.getRowCount() == 0 and self.session2_model.getRowCount() == 0:
            JOptionPane.showMessageDialog(self._panel, "No results")
            return
            
        chooser = JFileChooser()
        if chooser.showSaveDialog(self._panel) == JFileChooser.APPROVE_OPTION:
            filepath = chooser.getSelectedFile().getAbsolutePath()
            if not filepath.endswith('.csv'):
                filepath += '.csv'
                
            try:
                with open(filepath, 'wb') as f:
                    writer = csv.writer(f)
                    headers = ["#", "Status", "Method", "Host", "Path", "IDs", "Full URL", "Params"]
                    
                    writer.writerow([self.session1_label.getText()])
                    writer.writerow(headers)
                    for row in range(self.session1_model.getRowCount()):
                        writer.writerow([self.session1_model.getValueAt(row, col) or "" 
                                        for col in range(8)])
                        
                    writer.writerow([])
                    writer.writerow([self.session2_label.getText()])
                    writer.writerow(headers)
                    for row in range(self.session2_model.getRowCount()):
                        writer.writerow([self.session2_model.getValueAt(row, col) or "" 
                                        for col in range(8)])
                        
                JOptionPane.showMessageDialog(self._panel, "Exported: " + filepath)
            except Exception as e:
                JOptionPane.showMessageDialog(self._panel, "Error: " + str(e))
                
    def _send_table_to_repeater(self, table, model):
        rows = table.getSelectedRows()
        for row in rows:
            model_row = table.convertRowIndexToModel(row)
            url = model.getValueAt(model_row, 6)  # Full URL is now column 6
            if url and url != "-":
                for session_tag, requests in self.session_data.items():
                    for req in requests:
                        if req['full_url'] == url:
                            use_https = (req['protocol'].lower() == "https")
                            self._callbacks.sendToRepeater(
                                req['host'], req['port'], use_https, req['request'],
                                "IDOR-" + req['method']
                            )
                            return
                            
    def _copy_table_urls(self, table, model):
        rows = table.getSelectedRows()
        urls = [model.getValueAt(table.convertRowIndexToModel(r), 6)  # URL is column 6
                for r in rows if model.getValueAt(table.convertRowIndexToModel(r), 6) != "-"]
        if urls:
            from java.awt.datatransfer import StringSelection
            from java.awt import Toolkit
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                StringSelection("\n".join(urls)), None)
            
    def _copy_table_paths(self, table, model):
        rows = table.getSelectedRows()
        paths = [model.getValueAt(table.convertRowIndexToModel(r), 4) for r in rows]  # Path is column 4
        if paths:
            from java.awt.datatransfer import StringSelection
            from java.awt import Toolkit
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                StringSelection("\n".join(paths)), None)
                
    def _delete_selected_requests(self, table, model):
        """Delete selected requests from table and session data"""
        rows = table.getSelectedRows()
        if not rows:
            return
            
        # Get URLs to delete (need to collect before removing rows)
        urls_to_delete = []
        for row in rows:
            model_row = table.convertRowIndexToModel(row)
            url = model.getValueAt(model_row, 6)  # Full URL is column 6
            if url and url != "-":
                urls_to_delete.append(url)
        
        if not urls_to_delete:
            return
            
        # Remove from session_data
        for session_tag in list(self.session_data.keys()):
            self.session_data[session_tag] = [
                req for req in self.session_data[session_tag] 
                if req['full_url'] not in urls_to_delete
            ]
            # Remove empty sessions
            if not self.session_data[session_tag]:
                del self.session_data[session_tag]
                self.captured_sessions.discard(session_tag)
        
        # Remove rows from table (in reverse order to maintain indices)
        model_rows = sorted([table.convertRowIndexToModel(r) for r in rows], reverse=True)
        for model_row in model_rows:
            model.removeRow(model_row)
            
        # Update combos
        self._update_combos()
        
        debug("[*] Deleted %d request(s)" % len(urls_to_delete))
            
    def createMenuItems(self, invocation):
        menu_items = ArrayList()
        menu_item = JMenuItem("Send to IDOR Comparer", 
            actionPerformed=lambda x: self._add_from_context(invocation))
        menu_items.add(menu_item)
        return menu_items
        
    def _add_from_context(self, invocation):
        """Add requests from context menu with tag selection dialog"""
        messages = invocation.getSelectedMessages()
        
        # Create editable combo box with existing tags
        tag_combo = JComboBox()
        tag_combo.setEditable(True)  # Allow typing new tags
        
        # Add existing tags
        for tag in sorted(self.captured_sessions):
            tag_combo.addItem(tag)
        
        # If no existing tags, set a default
        if tag_combo.getItemCount() == 0:
            tag_combo.addItem("session1")
        
        # Show dialog
        result = JOptionPane.showConfirmDialog(
            self._panel,
            tag_combo,
            "Select existing tag or type new tag:",
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.PLAIN_MESSAGE
        )
        
        if result != JOptionPane.OK_OPTION:
            return
        
        # Get selected/typed tag
        session_tag = str(tag_combo.getSelectedItem()).strip() if tag_combo.getSelectedItem() else ""
            
        if not session_tag:
            return
            
        count = 0
        for message in messages:
            request = message.getRequest()
            if not request:
                continue
                
            request_info = self._helpers.analyzeRequest(message)
            url = request_info.getUrl()
            full_url = str(url)
            
            existing = [r['full_url'] for r in self.session_data[session_tag]]
            if full_url not in existing:
                self.session_data[session_tag].append({
                    'method': request_info.getMethod(),
                    'path': url.getPath() if url.getPath() else "/",
                    'query': url.getQuery() if url.getQuery() else "",
                    'full_url': full_url,
                    'host': url.getHost(),
                    'port': url.getPort(),
                    'protocol': url.getProtocol(),
                    'request': request,
                    'response': message.getResponse(),
                    'ids': self._extract_ids(str(url.getPath()))
                })
                count += 1
                
            self.captured_sessions.add(session_tag)
            
        self._update_combos()
        JOptionPane.showMessageDialog(self._panel, "Added %d to '%s'" % (count, session_tag))
            
    def getTabCaption(self):
        return "IDOR Comparer"
        
    def getUiComponent(self):
        return self._panel


class TableSelectionListener(ListSelectionListener):
    """Listen for table selection to update viewer"""
    def __init__(self, extender, table, model, session_num):
        self.extender = extender
        self.table = table
        self.model = model
        self.session_num = session_num
        
    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return
        row = self.table.getSelectedRow()
        if row >= 0:
            model_row = self.table.convertRowIndexToModel(row)
            url = self.model.getValueAt(model_row, 6)  # Full URL is now column 6
            if url and url != "-":
                self.extender._load_request_to_viewer(url)


class StatusCellRenderer(DefaultTableCellRenderer):
    """Color-code status column"""
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column)
        if not isSelected:
            if value and "DIFF" in str(value):
                c.setBackground(Color(255, 180, 180))
                c.setForeground(Color(139, 0, 0))
            elif value and "Only" in str(value):
                c.setBackground(Color(255, 255, 180))
                c.setForeground(Color(0, 0, 0))
            elif value and "Both" in str(value):
                c.setBackground(Color(180, 255, 180))
                c.setForeground(Color(0, 100, 0))
            else:
                c.setBackground(Color.WHITE)
                c.setForeground(Color.BLACK)
        else:
            c.setBackground(table.getSelectionBackground())
            c.setForeground(table.getSelectionForeground())
        return c
