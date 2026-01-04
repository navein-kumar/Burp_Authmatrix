# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IHttpRequestResponse, IHttpService
from javax.swing import (JPanel, JButton, JFileChooser, JScrollPane, JTextArea, 
                         JCheckBox, JOptionPane, JLabel, JTextField, JTable,
                         JComboBox, BorderFactory, BoxLayout, Box, JSplitPane,
                         ListSelectionModel, JTabbedPane, SwingConstants)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, GridLayout, FlowLayout, Dimension, GridBagLayout, GridBagConstraints, Insets, Font, Color
from java.net import URL
import java.util.Base64 as Base64
import java.io.File as File
from javax.xml.parsers import DocumentBuilderFactory
from javax.xml.transform import TransformerFactory, OutputKeys
from javax.xml.transform.dom import DOMSource
from javax.xml.transform.stream import StreamResult
import re
import array


class BurpExtender(IBurpExtender, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.callbacks.setExtensionName("Sitemap Import/Export v2")
        self.helper = callbacks.getHelpers()
        self.replacementRules = []
        self.loadedItems = []  # Store loaded items for preview
        self.currentPreviewIndex = 0

        # Main panel with tabs
        self.mainPanel = JPanel(BorderLayout())
        
        # Create tabbed pane
        tabbedPane = JTabbedPane()
        
        # Tab 1: Quick Presets (STEP 1)
        presetsPanel = self.createPresetsPanel()
        tabbedPane.addTab("1. Quick Presets", presetsPanel)
        
        # Tab 2: Custom Find & Replace (STEP 2)
        replacePanel = self.createReplacePanel()
        tabbedPane.addTab("2. Custom Rules", replacePanel)
        
        # Tab 3: Import/Export (STEP 3)
        importExportPanel = self.createImportExportPanel()
        tabbedPane.addTab("3. Import / Export", importExportPanel)
        
        self.mainPanel.add(tabbedPane, BorderLayout.CENTER)
        
        callbacks.addSuiteTab(self)

    def createPresetsPanel(self):
        panel = JPanel(BorderLayout())
        
        # Header
        headerLabel = JLabel("STEP 1: Set up common replacement rules", SwingConstants.CENTER)
        headerLabel.setFont(Font("Arial", Font.BOLD, 14))
        headerLabel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        panel.add(headerLabel, BorderLayout.NORTH)
        
        # Presets content
        presetsPanel = JPanel(GridLayout(0, 1, 10, 10))
        presetsPanel.setBorder(BorderFactory.createEmptyBorder(10, 20, 10, 20))
        
        # Preset 1: Host replacement (most common)
        hostPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        hostPanel.setBorder(BorderFactory.createTitledBorder("Host Replacement (URL + Headers)"))
        hostPanel.add(JLabel("Find:"))
        self.oldHostField = JTextField("yourgpt.ai", 20)
        hostPanel.add(self.oldHostField)
        hostPanel.add(JLabel("  Replace:"))
        self.newHostField = JTextField("d4ai.chat", 20)
        hostPanel.add(self.newHostField)
        addHostPreset = JButton("Add Rule", actionPerformed=self.onAddHostPreset)
        hostPanel.add(addHostPreset)
        presetsPanel.add(hostPanel)
        
        # Preset 2: Authorization token
        authPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        authPanel.setBorder(BorderFactory.createTitledBorder("Replace Authorization Token"))
        authPanel.add(JLabel("New Token:"))
        self.newAuthField = JTextField("Bearer eyJ...", 50)
        authPanel.add(self.newAuthField)
        addAuthPreset = JButton("Add Rule", actionPerformed=self.onAddAuthPreset)
        authPanel.add(addAuthPreset)
        presetsPanel.add(authPanel)
        
        # Preset 3: Remove header
        removeHeaderPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        removeHeaderPanel.setBorder(BorderFactory.createTitledBorder("Remove Header"))
        removeHeaderPanel.add(JLabel("Header Name:"))
        self.removeHeaderField = JTextField("X-Pwnfox-Color", 25)
        removeHeaderPanel.add(self.removeHeaderField)
        addRemovePreset = JButton("Add Rule", actionPerformed=self.onAddRemoveHeaderPreset)
        removeHeaderPanel.add(addRemovePreset)
        presetsPanel.add(removeHeaderPanel)
        
        # Quick buttons panel
        quickPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        quickPanel.setBorder(BorderFactory.createTitledBorder("Quick Actions"))
        
        http2to1Btn = JButton("HTTP/2 -> HTTP/1.1", actionPerformed=self.onHttp2to1)
        stripCookiesBtn = JButton("Strip Cookies", actionPerformed=self.onStripCookies)
        stripUABtn = JButton("Normalize User-Agent", actionPerformed=self.onNormalizeUA)
        
        quickPanel.add(http2to1Btn)
        quickPanel.add(stripCookiesBtn)
        quickPanel.add(stripUABtn)
        presetsPanel.add(quickPanel)
        
        # Active rules display
        rulesDisplayPanel = JPanel(BorderLayout())
        rulesDisplayPanel.setBorder(BorderFactory.createTitledBorder("Active Rules"))
        self.rulesDisplayArea = JTextArea(8, 60)
        self.rulesDisplayArea.setEditable(False)
        rulesDisplayPanel.add(JScrollPane(self.rulesDisplayArea), BorderLayout.CENTER)
        
        clearBtn = JButton("Clear All Rules", actionPerformed=self.onClearRules)
        rulesDisplayPanel.add(clearBtn, BorderLayout.SOUTH)
        presetsPanel.add(rulesDisplayPanel)
        
        panel.add(presetsPanel, BorderLayout.CENTER)
        
        # Instructions
        instructionsLabel = JLabel("<html><b>After adding rules, go to Tab 3 to import your XML file</b></html>", SwingConstants.CENTER)
        instructionsLabel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        panel.add(instructionsLabel, BorderLayout.SOUTH)
        
        return panel

    def createReplacePanel(self):
        panel = JPanel(BorderLayout())
        
        # Header
        headerLabel = JLabel("STEP 2: Add custom find/replace rules (Optional)", SwingConstants.CENTER)
        headerLabel.setFont(Font("Arial", Font.BOLD, 14))
        headerLabel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        panel.add(headerLabel, BorderLayout.NORTH)
        
        # Input panel for new rules
        inputPanel = JPanel(GridBagLayout())
        inputPanel.setBorder(BorderFactory.createTitledBorder("Add Custom Rule"))
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.fill = GridBagConstraints.HORIZONTAL
        
        # Find field
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.weightx = 0
        inputPanel.add(JLabel("Find:"), gbc)
        
        gbc.gridx = 1
        gbc.gridwidth = 3
        gbc.weightx = 1.0
        self.findField = JTextField(50)
        inputPanel.add(self.findField, gbc)
        
        # Replace field
        gbc.gridx = 0
        gbc.gridy = 1
        gbc.gridwidth = 1
        gbc.weightx = 0
        inputPanel.add(JLabel("Replace:"), gbc)
        
        gbc.gridx = 1
        gbc.gridwidth = 3
        gbc.weightx = 1.0
        self.replaceField = JTextField(50)
        inputPanel.add(self.replaceField, gbc)
        
        # Options row
        gbc.gridx = 0
        gbc.gridy = 2
        gbc.gridwidth = 4
        optionsPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.regexCheckBox = JCheckBox("Use Regex")
        self.caseSensitiveCheckBox = JCheckBox("Case Sensitive", True)
        addRuleButton = JButton("Add Rule", actionPerformed=self.onAddRule)
        
        optionsPanel.add(self.regexCheckBox)
        optionsPanel.add(self.caseSensitiveCheckBox)
        optionsPanel.add(addRuleButton)
        inputPanel.add(optionsPanel, gbc)
        
        panel.add(inputPanel, BorderLayout.NORTH)
        
        # Rules table
        self.rulesTableModel = DefaultTableModel(
            ["#", "Find", "Replace", "Regex", "Case"],
            0
        )
        self.rulesTable = JTable(self.rulesTableModel)
        self.rulesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.rulesTable.getColumnModel().getColumn(0).setPreferredWidth(30)
        self.rulesTable.getColumnModel().getColumn(3).setPreferredWidth(50)
        self.rulesTable.getColumnModel().getColumn(4).setPreferredWidth(50)
        
        tableScroll = JScrollPane(self.rulesTable)
        tableScroll.setBorder(BorderFactory.createTitledBorder("All Active Rules"))
        
        # Delete button
        tableButtonPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        deleteRuleButton = JButton("Delete Selected", actionPerformed=self.onDeleteRule)
        clearAllButton = JButton("Clear All", actionPerformed=self.onClearRules)
        tableButtonPanel.add(deleteRuleButton)
        tableButtonPanel.add(clearAllButton)
        
        tablePanel = JPanel(BorderLayout())
        tablePanel.add(tableScroll, BorderLayout.CENTER)
        tablePanel.add(tableButtonPanel, BorderLayout.SOUTH)
        
        panel.add(tablePanel, BorderLayout.CENTER)
        
        return panel

    def createImportExportPanel(self):
        panel = JPanel(BorderLayout())
        
        # Top section - Import and Export side by side
        topPanel = JPanel(GridLayout(1, 2, 20, 0))  # 1 row, 2 columns
        topPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        # ========== LEFT: IMPORT SECTION ==========
        importPanel = JPanel()
        importPanel.setLayout(BoxLayout(importPanel, BoxLayout.Y_AXIS))
        importPanel.setBorder(BorderFactory.createTitledBorder("IMPORT - XML File to Site Map"))
        
        # Row 1: File selection
        fileRow = JPanel(FlowLayout(FlowLayout.LEFT))
        selectFileBtn = JButton("Select XML File", actionPerformed=self.onSelectFile)
        self.selectedFileLabel = JLabel("No file selected")
        fileRow.add(selectFileBtn)
        fileRow.add(self.selectedFileLabel)
        importPanel.add(fileRow)
        
        # Row 2: Options and Import button
        importRow = JPanel(FlowLayout(FlowLayout.LEFT))
        self.applyRulesCheckBox = JCheckBox("Apply Rules", True)
        refreshBtn = JButton("Refresh Preview", actionPerformed=self.onRefreshPreview)
        refreshBtn.setToolTipText("Refresh preview with current rules")
        importBtn = JButton("IMPORT TO SITE MAP", actionPerformed=self.onImportClick)
        importBtn.setFont(Font("Arial", Font.BOLD, 11))
        importRow.add(self.applyRulesCheckBox)
        importRow.add(refreshBtn)
        importRow.add(importBtn)
        importPanel.add(importRow)
        
        topPanel.add(importPanel)
        
        # ========== RIGHT: EXPORT SECTION ==========
        exportPanel = JPanel()
        exportPanel.setLayout(BoxLayout(exportPanel, BoxLayout.Y_AXIS))
        exportPanel.setBorder(BorderFactory.createTitledBorder("EXPORT - Site Map to XML File"))
        
        # Row 1: Export button
        exportRow1 = JPanel(FlowLayout(FlowLayout.LEFT))
        exportBtn = JButton("Export Site Map to XML", actionPerformed=self.onSaveButtonClick)
        exportRow1.add(exportBtn)
        exportPanel.add(exportRow1)
        
        # Row 2: Options
        exportRow2 = JPanel(FlowLayout(FlowLayout.LEFT))
        self.inScopeOnlyCheckBox = JCheckBox("In Scope Only", False)
        self.inScopeOnlyCheckBox.setToolTipText("Export only items in Burp's target scope")
        exportRow2.add(self.inScopeOnlyCheckBox)
        exportPanel.add(exportRow2)
        
        topPanel.add(exportPanel)
        
        panel.add(topPanel, BorderLayout.NORTH)
        
        # Preview panel - side by side
        previewPanel = JPanel(BorderLayout())
        previewPanel.setBorder(BorderFactory.createTitledBorder("Preview: Original vs Modified"))
        
        # Navigation
        navPanel = JPanel(FlowLayout(FlowLayout.CENTER))
        self.prevBtn = JButton("<< Previous", actionPerformed=self.onPrevPreview)
        self.previewIndexLabel = JLabel("Request 0 / 0")
        self.nextBtn = JButton("Next >>", actionPerformed=self.onNextPreview)
        navPanel.add(self.prevBtn)
        navPanel.add(self.previewIndexLabel)
        navPanel.add(self.nextBtn)
        previewPanel.add(navPanel, BorderLayout.NORTH)
        
        # Side by side text areas
        splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        splitPane.setResizeWeight(0.5)
        
        # Original panel
        originalPanel = JPanel(BorderLayout())
        originalLabel = JLabel("ORIGINAL", SwingConstants.CENTER)
        originalLabel.setFont(Font("Arial", Font.BOLD, 12))
        originalLabel.setForeground(Color(150, 0, 0))
        originalPanel.add(originalLabel, BorderLayout.NORTH)
        self.originalArea = JTextArea(20, 50)
        self.originalArea.setEditable(False)
        self.originalArea.setFont(Font("Monospaced", Font.PLAIN, 11))
        originalPanel.add(JScrollPane(self.originalArea), BorderLayout.CENTER)
        
        # Modified panel
        modifiedPanel = JPanel(BorderLayout())
        modifiedLabel = JLabel("MODIFIED (After Rules Applied)", SwingConstants.CENTER)
        modifiedLabel.setFont(Font("Arial", Font.BOLD, 12))
        modifiedLabel.setForeground(Color(0, 120, 0))
        modifiedPanel.add(modifiedLabel, BorderLayout.NORTH)
        self.modifiedArea = JTextArea(20, 50)
        self.modifiedArea.setEditable(False)
        self.modifiedArea.setFont(Font("Monospaced", Font.PLAIN, 11))
        modifiedPanel.add(JScrollPane(self.modifiedArea), BorderLayout.CENTER)
        
        splitPane.setLeftComponent(originalPanel)
        splitPane.setRightComponent(modifiedPanel)
        
        previewPanel.add(splitPane, BorderLayout.CENTER)
        
        panel.add(previewPanel, BorderLayout.CENTER)
        
        # Log panel
        logPanel = JPanel(BorderLayout())
        logPanel.setBorder(BorderFactory.createTitledBorder("Log"))
        self.logArea = JTextArea(5, 80)
        self.logArea.setEditable(False)
        logPanel.add(JScrollPane(self.logArea), BorderLayout.CENTER)
        panel.add(logPanel, BorderLayout.SOUTH)
        
        return panel

    # ============ PRESET HANDLERS ============
    
    def onAddHostPreset(self, event):
        oldHost = self.oldHostField.getText().strip()
        newHost = self.newHostField.getText().strip()
        
        if not oldHost or not newHost:
            JOptionPane.showMessageDialog(self.mainPanel, "Both fields required")
            return
        
        # Single rule to replace all occurrences
        rule = {
            'find': oldHost,
            'replace': newHost,
            'regex': False,
            'case_sensitive': True
        }
        self.addRuleToList(rule)
        self.log("[+] Added host rule: {} -> {}".format(oldHost, newHost))

    def onAddAuthPreset(self, event):
        newAuth = self.newAuthField.getText().strip()
        if not newAuth:
            return
        
        rule = {
            'find': 'Authorization: .*',
            'replace': 'Authorization: ' + newAuth,
            'regex': True,
            'case_sensitive': True
        }
        self.addRuleToList(rule)
        self.log("[+] Added auth replacement rule")

    def onAddRemoveHeaderPreset(self, event):
        headerName = self.removeHeaderField.getText().strip()
        if not headerName:
            return
        
        rule = {
            'find': headerName + ':.*\\r\\n',
            'replace': '',
            'regex': True,
            'case_sensitive': False
        }
        self.addRuleToList(rule)
        self.log("[+] Added remove header rule: {}".format(headerName))

    def onStripCookies(self, event):
        rule = {
            'find': 'Cookie:.*\\r\\n',
            'replace': '',
            'regex': True,
            'case_sensitive': False
        }
        self.addRuleToList(rule)
        self.log("[+] Added strip cookies rule")

    def onNormalizeUA(self, event):
        newUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
        rule = {
            'find': 'User-Agent:.*',
            'replace': 'User-Agent: ' + newUA,
            'regex': True,
            'case_sensitive': True
        }
        self.addRuleToList(rule)
        self.log("[+] Added User-Agent normalization rule")

    def onHttp2to1(self, event):
        rule = {
            'find': ' HTTP/2',
            'replace': ' HTTP/1.1',
            'regex': False,
            'case_sensitive': True
        }
        self.addRuleToList(rule)
        self.log("[+] Added HTTP/2 -> HTTP/1.1 rule")

    # ============ CUSTOM RULE HANDLERS ============
    
    def onAddRule(self, event):
        find = self.findField.getText()
        replace = self.replaceField.getText()
        
        if not find:
            JOptionPane.showMessageDialog(self.mainPanel, "Find field cannot be empty")
            return
        
        rule = {
            'find': find,
            'replace': replace,
            'regex': self.regexCheckBox.isSelected(),
            'case_sensitive': self.caseSensitiveCheckBox.isSelected()
        }
        self.addRuleToList(rule)
        self.log("[+] Added custom rule: {} -> {}".format(find[:30], replace[:30]))
        
        # Clear fields
        self.findField.setText("")
        self.replaceField.setText("")

    def addRuleToList(self, rule):
        self.replacementRules.append(rule)
        
        # Update table
        rowNum = len(self.replacementRules)
        self.rulesTableModel.addRow([
            str(rowNum),
            rule['find'][:40] + "..." if len(rule['find']) > 40 else rule['find'],
            rule['replace'][:40] + "..." if len(rule['replace']) > 40 else rule['replace'],
            "Yes" if rule['regex'] else "No",
            "Yes" if rule['case_sensitive'] else "No"
        ])
        
        # Update display in presets tab
        self.updateRulesDisplay()

    def updateRulesDisplay(self):
        text = ""
        for i, rule in enumerate(self.replacementRules):
            text += "{}. {} -> {}\n".format(
                i + 1,
                rule['find'][:50],
                rule['replace'][:50] if rule['replace'] else "(remove)"
            )
        self.rulesDisplayArea.setText(text if text else "No rules defined")

    def onDeleteRule(self, event):
        selectedRow = self.rulesTable.getSelectedRow()
        if selectedRow >= 0:
            self.replacementRules.pop(selectedRow)
            self.rulesTableModel.removeRow(selectedRow)
            # Renumber
            for i in range(self.rulesTableModel.getRowCount()):
                self.rulesTableModel.setValueAt(str(i + 1), i, 0)
            self.updateRulesDisplay()
            self.log("[-] Deleted rule")

    def onClearRules(self, event):
        self.replacementRules = []
        self.rulesTableModel.setRowCount(0)
        self.updateRulesDisplay()
        self.log("[*] Cleared all rules")

    # ============ IMPORT/EXPORT HANDLERS ============
    
    def onSelectFile(self, event):
        fileChooser = JFileChooser()
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        returnValue = fileChooser.showOpenDialog(self.mainPanel)
        
        if returnValue == JFileChooser.APPROVE_OPTION:
            self.selectedFile = fileChooser.getSelectedFile()
            self.selectedFileLabel.setText(self.selectedFile.getName())
            self.log("[*] Selected: {}".format(self.selectedFile.getName()))
            
            # Load and show preview
            self.loadFileForPreview()

    def onRefreshPreview(self, event):
        """Refresh preview with current rules - does not reload file"""
        if self.loadedItems:
            self.updatePreview()
            self.log("[*] Preview refreshed with current rules")
        else:
            self.log("[!] No file loaded - select a file first")

    def loadFileForPreview(self):
        if not hasattr(self, 'selectedFile') or not self.selectedFile:
            return
        
        try:
            parser = XMLParser(self.selectedFile.getAbsolutePath())
            parser.parse()
            self.loadedItems = parser.getItems()
            self.currentPreviewIndex = 0
            self.updatePreview()
            self.log("[*] Loaded {} items for preview".format(len(self.loadedItems)))
        except Exception as e:
            self.log("[!] Error loading file: {}".format(str(e)))

    def updatePreview(self):
        if not self.loadedItems:
            self.originalArea.setText("No items loaded")
            self.modifiedArea.setText("No items loaded")
            self.previewIndexLabel.setText("Request 0 / 0")
            return
        
        total = len(self.loadedItems)
        idx = self.currentPreviewIndex
        
        self.previewIndexLabel.setText("Request {} / {}".format(idx + 1, total))
        
        item = self.loadedItems[idx]
        url = item[0]
        request_b64 = item[1]
        
        # Decode original using Java String
        try:
            from java.lang import String as JString
            request_bytes = Base64.getDecoder().decode(request_b64)
            original_text = JString(request_bytes, "ISO-8859-1").toString()
        except:
            original_text = "(decode error)"
        
        # Show original
        originalDisplay = "URL: {}\n{}\n{}".format(url, "=" * 60, original_text)
        self.originalArea.setText(originalDisplay)
        self.originalArea.setCaretPosition(0)
        
        # Apply rules and show modified
        if self.applyRulesCheckBox.isSelected() and self.replacementRules:
            modified_url = self.applyReplacements(url)
            modified_text = self.applyReplacements(original_text)
            modifiedDisplay = "URL: {}\n{}\n{}".format(modified_url, "=" * 60, modified_text)
        else:
            modifiedDisplay = "(No rules applied - same as original)"
        
        self.modifiedArea.setText(modifiedDisplay)
        self.modifiedArea.setCaretPosition(0)

    def onPrevPreview(self, event):
        if self.loadedItems and self.currentPreviewIndex > 0:
            self.currentPreviewIndex -= 1
            self.updatePreview()

    def onNextPreview(self, event):
        if self.loadedItems and self.currentPreviewIndex < len(self.loadedItems) - 1:
            self.currentPreviewIndex += 1
            self.updatePreview()

    def onImportClick(self, event):
        if not hasattr(self, 'selectedFile') or not self.selectedFile:
            JOptionPane.showMessageDialog(self.mainPanel, "Please select an XML file first")
            return
        
        # Confirm import
        result = JOptionPane.showConfirmDialog(
            self.mainPanel,
            "Import {} items to Site Map?\nRules applied: {}".format(
                len(self.loadedItems), 
                len(self.replacementRules) if self.applyRulesCheckBox.isSelected() else 0
            ),
            "Confirm Import",
            JOptionPane.YES_NO_OPTION
        )
        
        if result != JOptionPane.YES_OPTION:
            return
        
        # Do import
        imported = 0
        errors = 0
        
        for item in self.loadedItems:
            try:
                url = item[0]
                request_b64 = item[1]
                response_b64 = item[2]
                color = item[3]
                comment = item[4]
                
                # Apply rules
                if self.applyRulesCheckBox.isSelected() and self.replacementRules:
                    url, request_b64, response_b64 = self.applyReplacementsToItem(url, request_b64, response_b64)
                
                # Add to site map
                self.addToSiteMap(url, request_b64, response_b64, color, comment)
                imported += 1
            except Exception as e:
                errors += 1
                self.log("[!] Error importing item: {}".format(str(e)))
        
        self.log("[+] IMPORT COMPLETE: {} items imported, {} errors".format(imported, errors))
        JOptionPane.showMessageDialog(
            self.mainPanel,
            "Import Complete!\n\n{} items imported to Site Map\n{} errors".format(imported, errors)
        )

    def onSaveButtonClick(self, event):
        fileChooser = JFileChooser()
        returnValue = fileChooser.showSaveDialog(self.mainPanel)

        if returnValue == JFileChooser.APPROVE_OPTION:
            saveFile = fileChooser.getSelectedFile()
            filePath = saveFile.getAbsolutePath()
            if not filePath.endswith('.xml'):
                filePath += '.xml'
            self.saveSiteMapToFile(filePath)

    # ============ CORE FUNCTIONS ============
    
    def applyReplacements(self, text):
        result = text
        for rule in self.replacementRules:
            find = rule['find']
            replace = rule['replace']
            
            try:
                if rule['regex']:
                    flags = 0 if rule['case_sensitive'] else re.IGNORECASE
                    flags |= re.MULTILINE
                    result = re.sub(find, replace, result, flags=flags)
                else:
                    if rule['case_sensitive']:
                        result = result.replace(find, replace)
                    else:
                        pattern = re.compile(re.escape(find), re.IGNORECASE)
                        result = pattern.sub(replace, result)
            except Exception as e:
                # If replacement fails, continue with original
                pass
        
        return result

    def applyReplacementsToItem(self, url, request_b64, response_b64):
        # Decode using Java - safer for binary data
        try:
            from java.lang import String as JString
            request_bytes = Base64.getDecoder().decode(request_b64)
            # Use ISO-8859-1 encoding to preserve all byte values as characters
            request_text = JString(request_bytes, "ISO-8859-1").toString()
        except Exception as e:
            self.log("[!] Decode request error: {}".format(str(e)))
            request_text = ""
        
        try:
            if response_b64:
                from java.lang import String as JString
                response_bytes = Base64.getDecoder().decode(response_b64)
                response_text = JString(response_bytes, "ISO-8859-1").toString()
            else:
                response_text = ""
        except Exception as e:
            self.log("[!] Decode response error: {}".format(str(e)))
            response_text = ""
        
        # Apply rules (string replacements)
        new_url = self.applyReplacements(url)
        new_request = self.applyReplacements(request_text)
        new_response = self.applyReplacements(response_text)
        
        # Re-encode to base64
        new_request_b64 = self.stringToBase64(new_request)
        new_response_b64 = self.stringToBase64(new_response) if new_response else ""
        
        return new_url, new_request_b64, new_response_b64
    
    def stringToBase64(self, text):
        """Convert string to base64 using Java - handles all characters"""
        try:
            from java.lang import String as JString
            # Create Java string and get bytes as ISO-8859-1 (preserves byte values 0-255)
            java_str = JString(text)
            java_bytes = java_str.getBytes("ISO-8859-1")
            return Base64.getEncoder().encodeToString(java_bytes)
        except Exception as e1:
            try:
                # Fallback: build Java byte array manually
                from jarray import array as jarray
                byte_list = []
                for c in text:
                    code = ord(c)
                    if code < 128:
                        byte_list.append(code)
                    elif code < 256:
                        byte_list.append(code - 256)  # Convert to signed byte
                    else:
                        byte_list.append(63)  # '?' for chars > 255
                
                java_byte_array = jarray(byte_list, 'b')
                return Base64.getEncoder().encodeToString(java_byte_array)
            except Exception as e2:
                try:
                    # Last resort: UTF-8
                    from java.lang import String as JString
                    java_str = JString(text)
                    return Base64.getEncoder().encodeToString(java_str.getBytes("UTF-8"))
                except Exception as e3:
                    return ""

    def addToSiteMap(self, url, request, response, color="", comment=""):
        try:
            req_bytes = Base64.getDecoder().decode(request)
            resp_bytes = Base64.getDecoder().decode(response) if response else None
            
            requestResponse = HttpRequestResponse(
                req_bytes,
                resp_bytes,
                HttpService(url),
                color,
                comment
            )
            self.callbacks.addToSiteMap(requestResponse)
        except Exception as e:
            raise e

    def saveSiteMapToFile(self, file_path):
        siteMapItems = self.callbacks.getSiteMap("")
        factory = DocumentBuilderFactory.newInstance()
        builder = factory.newDocumentBuilder()
        document = builder.newDocument()

        root = document.createElement("items")
        document.appendChild(root)

        count = 0
        skipped = 0
        inScopeOnly = self.inScopeOnlyCheckBox.isSelected()
        
        for item in siteMapItems:
            try:
                protocol = item.getHttpService().getProtocol()
                host = item.getHttpService().getHost()
                port = str(item.getHttpService().getPort())
                url = protocol + "://" + host
                if (protocol == "https" and port != "443") or (protocol == "http" and port != "80"):
                    url += ":{}".format(port)
                
                # Check scope if enabled
                if inScopeOnly:
                    try:
                        if not self.callbacks.isInScope(URL(url)):
                            skipped += 1
                            continue
                    except:
                        pass
                    
                request = Base64.getEncoder().encodeToString(item.getRequest()) if item.getRequest() else ""
                response = Base64.getEncoder().encodeToString(item.getResponse()) if item.getResponse() else ""
                comment = item.getComment() if item.getComment() else ""
                color = item.getHighlight() if item.getHighlight() else ""

                itemElement = document.createElement("item")
                root.appendChild(itemElement)

                self.createElementWithText(document, itemElement, "time", "")
                self.createElementWithText(document, itemElement, "url", url)
                hostElement = self.createElementWithText(document, itemElement, "host", host)
                hostElement.setAttribute("ip", "")
                self.createElementWithText(document, itemElement, "port", port)
                self.createElementWithText(document, itemElement, "protocol", protocol)
                self.createElementWithText(document, itemElement, "method", "")
                self.createElementWithText(document, itemElement, "path", "")
                self.createElementWithText(document, itemElement, "extension", "")
                requestElement = self.createElementWithText(document, itemElement, "request", request)
                requestElement.setAttribute("base64", "true")
                self.createElementWithText(document, itemElement, "status", "")
                self.createElementWithText(document, itemElement, "responselength", str(len(response)))
                self.createElementWithText(document, itemElement, "mimetype", "")
                responseElement = self.createElementWithText(document, itemElement, "response", response)
                responseElement.setAttribute("base64", "true")
                self.createElementWithText(document, itemElement, "comment", comment)
                self.createElementWithText(document, itemElement, "color", color)
                count += 1
            except:
                pass

        transformer = TransformerFactory.newInstance().newTransformer()
        transformer.setOutputProperty(OutputKeys.INDENT, "yes")
        source = DOMSource(document)
        result = StreamResult(File(file_path))
        transformer.transform(source, result)

        scopeMsg = " (in-scope only)" if inScopeOnly else ""
        self.log("[+] Exported {} items{} to {}".format(count, scopeMsg, file_path))
        if skipped > 0:
            self.log("[*] Skipped {} out-of-scope items".format(skipped))
        JOptionPane.showMessageDialog(self.mainPanel, "Exported {} items{}".format(count, scopeMsg))

    def createElementWithText(self, document, parent, tag_name, text):
        element = document.createElement(tag_name)
        element.appendChild(document.createTextNode(text))
        parent.appendChild(element)
        return element

    def log(self, message):
        self.logArea.append(message + "\n")
        self.logArea.setCaretPosition(self.logArea.getDocument().getLength())

    def getTabCaption(self):
        return "Sitemap Import/Export"

    def getUiComponent(self):
        return self.mainPanel


class XMLParser:
    def __init__(self, file_path):
        self.items = []
        self.file_path = file_path

    def getItems(self):
        return self.items

    def parse(self):
        factory = DocumentBuilderFactory.newInstance()
        builder = factory.newDocumentBuilder()
        document = builder.parse(File(self.file_path))

        items = document.getElementsByTagName("item")

        for i in range(items.getLength()):
            item = items.item(i)
            url = self._get_tag_text(item, "url")
            request = self._get_tag_text(item, "request")
            response = self._get_tag_text(item, "response")
            color = self._get_tag_text(item, "color")
            comment = self._get_tag_text(item, "comment")

            self.items.append([url, request, response, color, comment])

    def _get_tag_text(self, element, tag_name):
        tag = element.getElementsByTagName(tag_name).item(0)
        if tag and tag.getFirstChild():
            return tag.getFirstChild().getNodeValue().strip()
        return ""


class HttpService(IHttpService):
    def __init__(self, url):
        x = URL(url)
        self._protocol = x.getProtocol()
        self._host = x.getHost()
        self._port = x.getPort() if x.getPort() != -1 else (80 if self._protocol == "http" else 443)

    def getHost(self):
        return self._host

    def getPort(self):
        return self._port

    def getProtocol(self):
        return self._protocol


class HttpRequestResponse(IHttpRequestResponse):
    def __init__(self, request, response, httpService, color, comment):
        self.req = request
        self.resp = response
        self.serv = httpService
        self.color = color
        self.cmt = comment

    def getRequest(self):
        return self.req

    def getResponse(self):
        return self.resp

    def getHttpService(self):
        return self.serv

    def getComment(self):
        return self.cmt

    def getHighlight(self):
        return self.color

    def setHighlight(self, color):
        self.color = color

    def setComment(self, cmt):
        self.cmt = cmt

    def setHttpService(self, httpService):
        self.serv = httpService

    def setRequest(self, message):
        self.req = message

    def setResponse(self, message):
        self.resp = message
