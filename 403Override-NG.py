from burp import IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController, IHttpListener, IScanIssue
from javax.swing import JPanel, JTable, JScrollPane, JSplitPane, JLabel, JTextField, JTabbedPane, JTextArea, SwingUtilities, ListSelectionModel, JButton, JFileChooser, BorderFactory, JCheckBox
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer, TableRowSorter
from java.awt import BorderLayout, GridLayout, FlowLayout, Color, Font
from java.util import ArrayList
from javax.swing import JMenuItem
from java.util.concurrent import Executors
from java.util.concurrent.atomic import AtomicInteger
import java.lang.Exception as JavaException
import java.lang.InterruptedException as InterruptedException
from java.lang import Integer as JInt, String as JStr
from java.io import PrintWriter, File
import threading
import time
import re

# --- CUSTOM DATA MODELS ---
class TaskTableModel(DefaultTableModel):
    def __init__(self, col_names, rows):
        DefaultTableModel.__init__(self, col_names, rows)
    def getColumnClass(self, col):
        if col == 0: return JInt 
        return JStr

class AttemptTableModel(DefaultTableModel):
    def __init__(self, col_names, rows):
        DefaultTableModel.__init__(self, col_names, rows)
    def getColumnClass(self, col):
        if col in [0, 2, 3]: return JInt 
        return JStr

# --- CUSTOM COLOR RENDERER ---
class RowColorRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        component = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        if not isSelected:
            component.setBackground(table.getBackground())
            component.setForeground(table.getForeground())
            component.setFont(table.getFont()) 
            try:
                payload_val = str(table.getValueAt(row, 1))
                status_val = str(table.getValueAt(row, 2))
                diff_val = str(table.getValueAt(row, 4))
                
                if payload_val == "[BASELINE] Original Request":
                    component.setBackground(Color(100, 100, 100))
                    component.setForeground(Color.WHITE)
                    return component
                
                if status_val.startswith("2"): component.setForeground(Color(0, 150, 0)) 
                elif status_val.startswith("3"): component.setForeground(Color(200, 100, 0)) 
                elif status_val == "404": component.setForeground(Color(128, 0, 128)) 
                elif status_val == "405": component.setForeground(Color(0, 0, 200)) 
                elif status_val in ["401", "403"]: component.setForeground(Color(200, 0, 0)) 
                elif status_val.startswith("4"): component.setForeground(Color(150, 80, 0)) 
                elif status_val.startswith("5"): component.setForeground(Color(150, 0, 150)) 
                
                if diff_val == "YES":
                    component.setFont(component.getFont().deriveFont(Font.BOLD)) 
            except Exception:
                pass
        return component

# --- BURP EXTENDER MAIN CLASS ---
class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.setExtensionName("403Override NG v1")
        callbacks.getExtensionFilename()
        
        self.tasks = [] 
        self.current_task = None
        self.current_attempt = None
        self.auto_scanned_endpoints = set() 

        self.init_ui()
        self.load_settings() 
        
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self) 
        self.log("INFO", "403Override NG v1 Loaded. Developed by @touhidshaikh22.")

    def init_ui(self):
        self.tabs = JTabbedPane()

        # --- 1. Scanner Tab ---
        self.scanner_panel = JPanel(BorderLayout())
        
        action_bar = JPanel(FlowLayout(FlowLayout.LEFT))
        self.btn_cancel = JButton("Stop/Cancel Scan", actionPerformed=self.cancel_task)
        self.btn_export = JButton("Export to CSV", actionPerformed=self.export_csv)
        self.btn_cancel.setEnabled(False)
        self.btn_export.setEnabled(False)
        action_bar.add(self.btn_cancel)
        action_bar.add(self.btn_export)
        self.scanner_panel.add(action_bar, BorderLayout.NORTH)
        
        self.task_model = TaskTableModel(["ID", "Method", "Host", "Path", "Status Code", "Scan Status"], 0)
        self.task_table = JTable(self.task_model)
        self.task_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.task_sorter = TableRowSorter(self.task_model)
        self.task_table.setRowSorter(self.task_sorter)
        self.task_table.getSelectionModel().addListSelectionListener(self.task_selection_changed)
        
        self.attempt_model = AttemptTableModel(["ID", "Payload", "Status Code", "Content Length", "Diff"], 0)
        self.attempt_table = JTable(self.attempt_model)
        self.attempt_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.attempt_sorter = TableRowSorter(self.attempt_model)
        self.attempt_table.setRowSorter(self.attempt_sorter)
        self.attempt_table.getSelectionModel().addListSelectionListener(self.attempt_selection_changed)
        
        renderer = RowColorRenderer()
        for i in range(self.attempt_table.getColumnCount()):
            self.attempt_table.getColumnModel().getColumn(i).setCellRenderer(renderer)

        self.request_viewer = self._callbacks.createMessageEditor(self, False)
        self.response_viewer = self._callbacks.createMessageEditor(self, False)
        
        table_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, JScrollPane(self.task_table), JScrollPane(self.attempt_table))
        table_split.setResizeWeight(0.4)
        message_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, self.request_viewer.getComponent(), self.response_viewer.getComponent())
        message_split.setResizeWeight(0.5)
        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, table_split, message_split)
        main_split.setResizeWeight(0.5)
        self.scanner_panel.add(main_split, BorderLayout.CENTER)

        legend_panel = JPanel(FlowLayout(FlowLayout.CENTER, 20, 5))
        legend_panel.setBorder(BorderFactory.createTitledBorder("Response Color Ledger"))
        def create_lbl(text, color, bold=False):
            lbl = JLabel(text)
            lbl.setForeground(color)
            if bold: lbl.setFont(lbl.getFont().deriveFont(Font.BOLD))
            return lbl

        legend_panel.add(create_lbl("Bypass Found (Bold Text)", Color(0, 0, 0), True)) 
        legend_panel.add(create_lbl("2xx OK", Color(0, 150, 0)))
        legend_panel.add(create_lbl("3xx Redirect", Color(200, 100, 0)))
        legend_panel.add(create_lbl("401/403 Denied", Color(200, 0, 0)))
        legend_panel.add(create_lbl("404 Not Found", Color(128, 0, 128)))
        legend_panel.add(create_lbl("405 Bad Method", Color(0, 0, 200)))
        legend_panel.add(create_lbl("5xx Error", Color(150, 0, 150)))
        self.scanner_panel.add(legend_panel, BorderLayout.SOUTH)

        # --- 2. Configuration Tab ---
        self.config_panel = JPanel(BorderLayout())
        form_panel = JPanel(GridLayout(0, 3, 10, 10)) 
        
        self.chk_auto_scan = JCheckBox("Enable Auto-Scan on Proxy 401/403 responses", True)
        form_panel.add(self.chk_auto_scan)
        form_panel.add(JLabel(""))
        form_panel.add(JLabel(""))

        self.txt_headers = JTextField("X-Custom-IP-Authorization, X-Forwarded-For, X-Forward-For, X-Remote-IP, X-Originating-IP, X-Remote-Addr, X-Client-IP, X-Real-IP, X-Original-URL, X-Host, Referer, X-ProxyUser-Ip, Client-IP, True-Client-IP, Cluster-Client-IP") # Default Header Payloads
        self.txt_ips = JTextField("127.0.0.1, localhost, 0x7F000001, 169.254.169.254, 127.1, ::1, 0, 172.16.0.0, 192.168.1.0") # Default IP Payloads
        self.txt_trailings = JTextField("/, ..;/, /..;/, %20, %09, %00, .json, ?, ??, #, /.") # Default Path Trailing Payloads
        self.txt_parsers = JTextField("..;/, ;/, %2e/, %2e%2e/, //, /./") # NEW FIELD: Parser Normalization Payloads
        self.txt_methods = JTextField("GET, POST, PUT, TRACE") # Default Methods to Test
        self.txt_threads = JTextField("5") # FIELD: Concurrent Threads
        self.txt_delay = JTextField("0") # FIELD: Delay between requests
        self.txt_tolerance = JTextField("2") # FIELD: Diff Tolerance

        self.txt_ignore_regex = JTextField("") # FIELD: Ignore Regex

        form_panel.add(JLabel("Headers (String or FILE):"))
        form_panel.add(self.txt_headers)
        form_panel.add(JButton("Browse File...", actionPerformed=lambda x: self.browse_file(self.txt_headers)))
        
        form_panel.add(JLabel("IP Payloads (String or FILE):"))
        form_panel.add(self.txt_ips)
        form_panel.add(JButton("Browse File...", actionPerformed=lambda x: self.browse_file(self.txt_ips)))
        
        form_panel.add(JLabel("Path Trailings [Appended] (String or FILE):"))
        form_panel.add(self.txt_trailings)
        form_panel.add(JButton("Browse File...", actionPerformed=lambda x: self.browse_file(self.txt_trailings)))

        form_panel.add(JLabel("Parser Normalization [Injected] (String or FILE):"))
        form_panel.add(self.txt_parsers)
        form_panel.add(JButton("Browse File...", actionPerformed=lambda x: self.browse_file(self.txt_parsers)))
        
        form_panel.add(JLabel("Methods to Test:"))
        form_panel.add(self.txt_methods)
        form_panel.add(JLabel("")) 
        
        form_panel.add(JLabel("Concurrent Threads:"))
        form_panel.add(self.txt_threads)
        form_panel.add(JLabel(""))
        
        form_panel.add(JLabel("Delay between requests (ms):"))
        form_panel.add(self.txt_delay)
        form_panel.add(JLabel(""))

        form_panel.add(JLabel("Diff Tolerance (Bytes change to trigger YES):"))
        form_panel.add(self.txt_tolerance)
        form_panel.add(JLabel(""))

        form_panel.add(JLabel("Ignore Regex (e.g. csrf_token=\"[^\"]+\"):"))
        form_panel.add(self.txt_ignore_regex)
        form_panel.add(JLabel(""))
        
        form_panel.add(JLabel("Configuration State:"))
        form_panel.add(JButton("Save Settings as Default", actionPerformed=self.save_settings))
        form_panel.add(JButton("Reload Settings", actionPerformed=lambda x: self.load_settings()))
        
        wrapper_panel = JPanel(BorderLayout())
        wrapper_panel.add(form_panel, BorderLayout.NORTH)
        self.config_panel.add(wrapper_panel, BorderLayout.CENTER)

        # --- 3. Debug Log Tab ---
        self.log_panel = JPanel(BorderLayout())
        self.log_area = JTextArea()
        self.log_area.setEditable(False)
        self.log_panel.add(JScrollPane(self.log_area), BorderLayout.CENTER)

        self.tabs.addTab("Scanner", self.scanner_panel)
        self.tabs.addTab("Configuration", self.config_panel)
        self.tabs.addTab("Debug Log", self.log_panel)

    def log(self, level, message):
        timestamp = time.strftime("%H:%M:%S")
        formatted_msg = "[{}] [{}] {}\n".format(timestamp, level, message)
        if level == "ERROR":
            self.stderr.println(formatted_msg)
        else:
            self.stdout.println(formatted_msg)
        def update_ui():
            self.log_area.append(formatted_msg)
            self.log_area.setCaretPosition(self.log_area.getDocument().getLength())
        SwingUtilities.invokeLater(update_ui)

    # --- HTTP LISTENER (PASSIVE AUTO-SCAN) ---
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest or not self.chk_auto_scan.isSelected(): return
        if toolFlag != self._callbacks.TOOL_PROXY: return 
        
        resp = messageInfo.getResponse()
        if not resp: return
        
        status = self._helpers.analyzeResponse(resp).getStatusCode()
        if status in [401, 403]:
            req_info = self._helpers.analyzeRequest(messageInfo)
            url = req_info.getUrl()
            
            endpoint_id = str(url.getHost()) + str(url.getPath())
            if endpoint_id not in self.auto_scanned_endpoints:
                self.auto_scanned_endpoints.add(endpoint_id)
                self.log("INFO", "[AUTO-SCAN] Triggered by Proxy for blocked endpoint: " + str(url))
                self.trigger_scan([messageInfo])

    # --- SETTINGS & WORDLIST HANDLERS ---
    def browse_file(self, target_textfield):
        chooser = JFileChooser()
        ret = chooser.showOpenDialog(self.config_panel)
        if ret == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            target_textfield.setText("FILE:" + file_path)

    def read_input(self, text_val):
        if text_val.startswith("FILE:"):
            filepath = text_val[5:]
            try:
                with open(filepath, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.log("ERROR", "Failed to load wordlist {}: {}".format(filepath, str(e)))
                return []
        else:
            return [x.strip() for x in text_val.split(",") if x.strip()]

    def save_settings(self, event):
        self._callbacks.saveExtensionSetting("403_autoscan", str(self.chk_auto_scan.isSelected()))
        self._callbacks.saveExtensionSetting("403_headers", self.txt_headers.getText())
        self._callbacks.saveExtensionSetting("403_ips", self.txt_ips.getText())
        self._callbacks.saveExtensionSetting("403_trailings", self.txt_trailings.getText())
        self._callbacks.saveExtensionSetting("403_parsers", self.txt_parsers.getText())
        self._callbacks.saveExtensionSetting("403_methods", self.txt_methods.getText())
        self._callbacks.saveExtensionSetting("403_threads", self.txt_threads.getText())
        self._callbacks.saveExtensionSetting("403_delay", self.txt_delay.getText())
        self._callbacks.saveExtensionSetting("403_tolerance", self.txt_tolerance.getText())
        self._callbacks.saveExtensionSetting("403_ignore_regex", self.txt_ignore_regex.getText())
        self.log("INFO", "Settings successfully saved to Burp's persistent storage.")

    def load_settings(self):
        a = self._callbacks.loadExtensionSetting("403_autoscan")
        if a: self.chk_auto_scan.setSelected(a == "True")
        h = self._callbacks.loadExtensionSetting("403_headers")
        if h: self.txt_headers.setText(h)
        i = self._callbacks.loadExtensionSetting("403_ips")
        if i: self.txt_ips.setText(i)
        t = self._callbacks.loadExtensionSetting("403_trailings")
        if t: self.txt_trailings.setText(t)
        p = self._callbacks.loadExtensionSetting("403_parsers")
        if p: self.txt_parsers.setText(p)
        m = self._callbacks.loadExtensionSetting("403_methods")
        if m: self.txt_methods.setText(m)
        th = self._callbacks.loadExtensionSetting("403_threads")
        if th: self.txt_threads.setText(th)
        d = self._callbacks.loadExtensionSetting("403_delay")
        if d: self.txt_delay.setText(d)
        tol = self._callbacks.loadExtensionSetting("403_tolerance")
        if tol: self.txt_tolerance.setText(tol)
        reg = self._callbacks.loadExtensionSetting("403_ignore_regex")
        if reg: self.txt_ignore_regex.setText(reg)

    # --- UI EVENT HANDLERS ---
    def task_selection_changed(self, event):
        if not event.getValueIsAdjusting():
            view_row = self.task_table.getSelectedRow()
            if view_row != -1:
                model_row = self.task_table.convertRowIndexToModel(view_row)
                self.current_task = self.tasks[model_row]
                self.current_attempt = None
                
                self.btn_export.setEnabled(True)
                self.btn_cancel.setEnabled(not self.current_task.is_completed and not self.current_task.is_cancelled)
                self.attempt_table.clearSelection()
                self.refresh_attempts_table()
                
                if self.current_task and self.current_task.base_rr:
                    self.request_viewer.setMessage(self.current_task.base_rr.getRequest(), True)
                    resp = self.current_task.base_rr.getResponse()
                    self.response_viewer.setMessage(resp if resp else bytearray(), False)

    def attempt_selection_changed(self, event):
        if not event.getValueIsAdjusting() and self.current_task:
            view_row = self.attempt_table.getSelectedRow()
            if view_row != -1:
                model_row = self.attempt_table.convertRowIndexToModel(view_row)
                
                if model_row == 0:
                    self.current_attempt = None
                    self.request_viewer.setMessage(self.current_task.base_rr.getRequest(), True)
                    resp = self.current_task.base_rr.getResponse()
                    self.response_viewer.setMessage(resp if resp else bytearray(), False)
                else:
                    att_idx = model_row - 1
                    if att_idx < len(self.current_task.attempts):
                        self.current_attempt = self.current_task.attempts[att_idx]
                        if self.current_attempt:
                            self.request_viewer.setMessage(self.current_attempt.getRequest(), True)
                            resp = self.current_attempt.getResponse()
                            self.response_viewer.setMessage(resp if resp else bytearray(), False)

    def refresh_attempts_table(self):
        def update_ui():
            selected_view_row = self.attempt_table.getSelectedRow()
            self.attempt_model.setRowCount(0)
            
            if self.current_task:
                base_status, base_len = 0, 0
                if self.current_task.base_rr and self.current_task.base_rr.getResponse():
                    resp = self._helpers.analyzeResponse(self.current_task.base_rr.getResponse())
                    base_status = int(resp.getStatusCode())

                    base_len = self.current_task.normalized_base_len 
                
                self.attempt_model.addRow([0, "[BASELINE] Original Request", base_status, base_len, "N/A"])
                
                for i, att in enumerate(self.current_task.attempts):
                    diff_label = "YES" if att.is_diff else "No"
                    self.attempt_model.addRow([i+1, att.payload, int(att.status), int(att.length), diff_label])
            
            if selected_view_row != -1 and selected_view_row < self.attempt_table.getRowCount():
                self.attempt_table.setRowSelectionInterval(selected_view_row, selected_view_row)
                
        SwingUtilities.invokeLater(update_ui)

    def cancel_task(self, event):
        if self.current_task and not self.current_task.is_completed:
            self.current_task.is_cancelled = True
            if self.current_task.executor:
                self.current_task.executor.shutdownNow() 
            self.log("INFO", "Scan Task Cancelled explicitly by user.")
            self.btn_cancel.setEnabled(False)
            row_idx = self.tasks.index(self.current_task)
            def update_status():
                self.task_model.setValueAt("Cancelled", row_idx, 5)
            SwingUtilities.invokeLater(update_status)

    def export_csv(self, event):
        if not self.current_task or len(self.current_task.attempts) == 0:
            self.log("ERROR", "No attempts to export.")
            return
        chooser = JFileChooser()
        ret = chooser.showSaveDialog(self.scanner_panel)
        if ret == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            if not file_path.endswith(".csv"): file_path += ".csv"
            try:
                with open(file_path, 'w') as f:
                    f.write("ID,Payload,Status,Norm_Length,Diff\n")
                    for i, att in enumerate(self.current_task.attempts):
                        diff_str = "YES" if att.is_diff else "NO"
                        safe_payload = '"{}"'.format(att.payload.replace('"', '""'))
                        f.write("{},{},{},{},{}\n".format(i+1, safe_payload, att.status, att.length, diff_str))
                self.log("SUCCESS", "Results successfully exported to " + file_path)
            except Exception as e:
                self.log("ERROR", "Failed to export CSV: " + str(e))

    # --- CORE LOGIC ---
    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Send to 403Override", actionPerformed=lambda x: self.trigger_scan(invocation.getSelectedMessages())))
        return menu_list

    def trigger_scan(self, messages):
        try:
            config = {
                "ips": self.read_input(self.txt_ips.getText()),
                "headers": self.read_input(self.txt_headers.getText()),
                "trailings": self.read_input(self.txt_trailings.getText()),
                "parsers": self.read_input(self.txt_parsers.getText()),
                "methods": self.read_input(self.txt_methods.getText()),
                "threads": int(self.txt_threads.getText()),
                "delay": int(self.txt_delay.getText()),
                "tolerance": int(self.txt_tolerance.getText()),
                "ignore_regex": self.txt_ignore_regex.getText().strip()
            }
        except ValueError:
            self.log("ERROR", "Invalid configuration. Threads, Delay, and Tolerance must be numeric.")
            return

        for msg in messages:
            req_info = self._helpers.analyzeRequest(msg)
            orig_status = "Unknown"
            if msg.getResponse():
                orig_status = str(self._helpers.analyzeResponse(msg.getResponse()).getStatusCode())

            task = ScanTask(msg, req_info)
            self.tasks.append(task)
            
            row_idx = len(self.tasks) - 1
            def sync_add_task(row_idx=row_idx, meth=req_info.getMethod(), hst=req_info.getUrl().getHost(), pth=req_info.getUrl().getPath(), stat=orig_status):
                self.task_model.addRow([row_idx + 1, meth, hst, pth, stat, "Starting..."])
            SwingUtilities.invokeLater(sync_add_task)
            
            self.log("INFO", "Scan task initiated for: " + str(req_info.getUrl()))
            threading.Thread(target=self.run_logic, args=(task, row_idx, config)).start()

    def run_logic(self, task, row_idx, config):
        try:
            # 1. Compile Ignore Regex (if provided)
            ignore_pattern = None
            if config["ignore_regex"]:
                try:
                    ignore_pattern = re.compile(config["ignore_regex"])
                except Exception as e:
                    self.log("ERROR", "Invalid Ignore Regex compiled: " + str(e))

            base_req_bytes = task.base_rr.getRequest()
            http_service = task.base_rr.getHttpService()
            base_req_info = self._helpers.analyzeRequest(http_service, base_req_bytes)
            
            # 2. Extract and Normalize Baseline Data
            if task.base_rr.getResponse():
                base_resp_info = self._helpers.analyzeResponse(task.base_rr.getResponse())
                base_status = base_resp_info.getStatusCode()
                
                # Extract the body specifically to normalize it
                body_offset = base_resp_info.getBodyOffset()
                base_body_bytes = task.base_rr.getResponse()[body_offset:]
                base_body_str = self._helpers.bytesToString(base_body_bytes)
                
                if ignore_pattern:
                    base_body_str = ignore_pattern.sub('', base_body_str)
                
                base_len = len(base_body_str)
            else:
                base_status = 0
                base_len = 0
            
            # Store it so the UI can retrieve it later without reprocessing
            task.normalized_base_len = base_len
            
            orig_path = base_req_info.getUrl().getPath()
            orig_query = base_req_info.getUrl().getQuery()
            
            thread_count = config["threads"]
            delay_ms = config["delay"]
            tolerance = config["tolerance"]

            total_phase1 = len(config["methods"]) * len(config["headers"]) * len(config["ips"])
            
            phase2_variations = set()
            for t in config["trailings"]: phase2_variations.add(orig_path + t)
            phase2_variations.add(orig_path + "//")
            phase2_variations.add("/." + orig_path + "/./")
            phase2_variations.add("/%2e" + orig_path)
            total_phase2 = len(config["methods"]) * len(phase2_variations)

            phase3_variations = set()
            slash_indices = [i for i, ltr in enumerate(orig_path) if ltr == '/']
            for norm in config["parsers"]:
                for idx in slash_indices:
                    var = orig_path[:idx+1] + norm + orig_path[idx+1:]
                    var = var.replace("///", "//")
                    phase3_variations.add(var)
                if orig_path.startswith("/"):
                    phase3_variations.add(norm + orig_path[1:])
                    phase3_variations.add("/" + norm + orig_path[1:])
                    phase3_variations.add(norm + orig_path)
            total_phase3 = len(config["methods"]) * len(phase3_variations)

            phase4_variations = set()
            if len(orig_path) > 1: 
                phase4_variations.add(orig_path.upper()) 
                phase4_variations.add(orig_path.title()) 
                phase4_variations.add(orig_path.replace('/', '//')) 
                phase4_variations.add(orig_path.replace('/', '%2f')) 
                phase4_variations.add(orig_path.replace('/', '%252f')) 
                phase4_variations.add(orig_path + "%00") 
            total_phase4 = len(config["methods"]) * len(phase4_variations)

            task.total_payloads = total_phase1 + total_phase2 + total_phase3 + total_phase4

            executor = Executors.newFixedThreadPool(thread_count)
            task.executor = executor 
            
            self.log("INFO", "Queueing {} payloads for {}. Threads: {}".format(task.total_payloads, base_req_info.getUrl(), thread_count))

            orig_uri = orig_path + ("?" + orig_query if orig_query else "")

            for m in config["methods"]:
                for h in config["headers"]:
                    for ip in config["ips"]:
                        executor.submit(lambda m=m, uri=orig_uri, h=h, ip=ip, p="Header | {}: {}".format(h, ip): 
                            self.execute_request(task, row_idx, base_req_bytes, base_req_info, base_status, base_len, m, uri, h, ip, p, delay_ms, http_service, tolerance, ignore_pattern))

            for m in config["methods"]:
                for pv in phase2_variations:
                    new_uri = pv + ("?" + orig_query if orig_query else "")
                    executor.submit(lambda m=m, uri=new_uri, p="Trailing Path | {}".format(pv): 
                        self.execute_request(task, row_idx, base_req_bytes, base_req_info, base_status, base_len, m, uri, None, None, p, delay_ms, http_service, tolerance, ignore_pattern))

            for m in config["methods"]:
                for pv in phase3_variations:
                    new_uri = pv + ("?" + orig_query if orig_query else "")
                    executor.submit(lambda m=m, uri=new_uri, p="Parser Injection | {}".format(pv): 
                        self.execute_request(task, row_idx, base_req_bytes, base_req_info, base_status, base_len, m, uri, None, None, p, delay_ms, http_service, tolerance, ignore_pattern))

            for m in config["methods"]:
                for pv in phase4_variations:
                    new_uri = pv + ("?" + orig_query if orig_query else "")
                    executor.submit(lambda m=m, uri=new_uri, p="Adv Mutation | {}".format(pv): 
                        self.execute_request(task, row_idx, base_req_bytes, base_req_info, base_status, base_len, m, uri, None, None, p, delay_ms, http_service, tolerance, ignore_pattern))

            executor.shutdown()
            while not executor.isTerminated() and not task.is_cancelled:
                time.sleep(0.5)
            
            task.is_completed = True
            
            def final_update():
                if not task.is_cancelled:
                    self.task_model.setValueAt("Completed", row_idx, 5)
                if self.current_task == task:
                    self.btn_cancel.setEnabled(False)
            SwingUtilities.invokeLater(final_update)

        except Exception as e:
            self.log("ERROR", "Python Exception in run_logic: " + str(e))
        except JavaException as e:
            self.log("ERROR", "Java Exception in run_logic: " + str(e))

    def update_progress_ui(self, task, row_idx):
        completed = task.completed_payloads.incrementAndGet()
        if completed % 5 == 0 or completed == task.total_payloads:
            def sync_ui():
                if not task.is_cancelled:
                    self.task_model.setValueAt("In Progress ({}/{})".format(completed, task.total_payloads), row_idx, 5)
            SwingUtilities.invokeLater(sync_ui)

    def execute_request(self, task, row_idx, base_req_bytes, base_req_info, base_status, base_len, method, new_uri, header_name, ip_val, payload_name, delay_ms, http_service, tolerance, ignore_pattern):
        if task.is_cancelled: return
        try:
            if delay_ms > 0: time.sleep(delay_ms / 1000.0)
            
            body_offset = base_req_info.getBodyOffset()
            body_bytes = base_req_bytes[body_offset:]
            
            new_headers = list(base_req_info.getHeaders())
            first_line = new_headers[0]
            parts = first_line.split(" ", 2)
            if len(parts) == 3:
                new_headers[0] = "{} {} {}".format(method, new_uri, parts[2])
            
            if header_name and ip_val:
                new_headers.append("{}: {}".format(header_name, ip_val))
            
            req_bytes = self._helpers.buildHttpMessage(new_headers, body_bytes)
            resp_rr = self._callbacks.makeHttpRequest(http_service, req_bytes)
            
            if resp_rr.getResponse():
                analyzed = self._helpers.analyzeResponse(resp_rr.getResponse())
                curr_status = analyzed.getStatusCode()
                
                # --- APPLY DYNAMIC NORMALIZATION ---
                curr_body_offset = analyzed.getBodyOffset()
                curr_body_str = self._helpers.bytesToString(resp_rr.getResponse()[curr_body_offset:])
                
                if ignore_pattern:
                    curr_body_str = ignore_pattern.sub('', curr_body_str)
                
                curr_len = len(curr_body_str)
                
                is_diff = (curr_status != base_status or abs(curr_len - base_len) > tolerance)
                
                display_payload = "[{}] {}".format(method, payload_name)
                
                if is_diff:
                    self.log("SUCCESS", "Bypass found! [{}] resulted in Status: {} (Orig: {})".format(display_payload, curr_status, base_status))
                    
                    # Only create a Burp Dashboard Issue IF it is marked as a Diff AND the status code is 2xx, 3xx, or 5xx. Ignore 4xx.
                    curr_str = str(curr_status)
                    if curr_str.startswith("2") or curr_str.startswith("3") or curr_str.startswith("5"):
                        detail = """
                        <b>403Override Automaton Detected a potential bypass!</b><br><br>
                        <b>Original Status:</b> {}<br>
                        <b>Bypassed Status:</b> {}<br>
                        <b>Payload Applied:</b> {}<br><br>
                        <i>Please review the attached Request/Response pairs. The first is the original blocked request. The second is the modified request that achieved the bypass.</i>
                        """.format(base_status, curr_status, display_payload)
                        
                        issue = BypassScanIssue(
                            http_service,
                            base_req_info.getUrl(),
                            [task.base_rr, resp_rr], 
                            "403/401 Authorization Bypass Detected",
                            detail,
                            "Information"
                        )
                        self._callbacks.addScanIssue(issue)
                
                attempt = Attempt(resp_rr, display_payload, curr_status, curr_len, is_diff)
                task.attempts.append(attempt)
                
                if self.current_task == task:
                    self.refresh_attempts_table()
                    
        except InterruptedException: pass 
        except Exception as e: pass 
        except JavaException as e: pass
        finally:
            self.update_progress_ui(task, row_idx)

    def getTabCaption(self): return "403Override"
    def getUiComponent(self): return self.tabs
    def getHttpService(self): 
        if self.current_attempt: return self.current_attempt.getHttpService()
        if self.current_task: return self.current_task.base_rr.getHttpService()
        return None
    def getRequest(self): 
        if self.current_attempt: return self.current_attempt.getRequest()
        if self.current_task: return self.current_task.base_rr.getRequest()
        return None
    def getResponse(self): 
        if self.current_attempt: return self.current_attempt.getResponse()
        if self.current_task: return self.current_task.base_rr.getResponse()
        return None

# --- CUSTOM DATA MODELS ---
class ScanTask:
    def __init__(self, base_rr, req_info):
        self.base_rr = base_rr
        self.req_info = req_info
        self.attempts = []
        self.executor = None
        self.is_cancelled = False
        self.is_completed = False
        self.total_payloads = 0
        self.completed_payloads = AtomicInteger(0)
        self.normalized_base_len = 0 

class Attempt:
    def __init__(self, rr, payload, status, length, is_diff):
        self.rr = rr
        self.payload = payload
        self.status = status
        self.length = length
        self.is_diff = is_diff
    def getRequest(self): return self.rr.getRequest()
    def getResponse(self): return self.rr.getResponse()
    def getHttpService(self): return self.rr.getHttpService()

# --- SCAN ISSUE IMPLEMENTATION ---
class BypassScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self): return self._url
    def getIssueName(self): return self._name
    def getIssueType(self): return 0x08000000 
    def getSeverity(self): return self._severity
    def getConfidence(self): return "Certain"
    def getIssueBackground(self): return "The 403Override extension automatically mutated parameters, headers, or paths to bypass a 401/403 access control restriction."
    def getRemediationBackground(self): return "Review the backend routing rules and proxy normalization configurations to ensure they align, and validate authorization headers globally."
    def getIssueDetail(self): return self._detail
    def getRemediationDetail(self): return None
    def getHttpMessages(self): return self._httpMessages
    def getHttpService(self): return self._httpService