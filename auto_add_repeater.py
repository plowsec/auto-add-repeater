from burp import IBurpExtender, IHttpListener, IProxyListener, ITab
from java.io import PrintWriter, File
from javax.swing import JButton, JPanel, JLabel, JCheckBox, JTextField, JScrollPane, BoxLayout
from java.awt import FlowLayout, BorderLayout
from javax.swing import Box
import json
import os
import traceback


class BurpExtender(IBurpExtender, IHttpListener, IProxyListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Auto Repeater Tab Creator")

        self._callbacks.registerHttpListener(self)
        self._callbacks.registerProxyListener(self)

        self._stdout = PrintWriter(callbacks.getStdout(), True)

        # Default configuration
        self.config = {
            'require_parameters': True,
            'ignored_parameters': ['__VIEWSTATE', 'token', 'csrf', '__RequestVerificationToken',
                                   'authenticity_token', '_csrf', 'nonce', 'timestamp']
        }

        self.storage_file = self.get_storage_file_path()
        self.config_file = self.storage_file.replace('.json', '_config.json')

        self.load_config()
        self._processed_requests = self.load_processed_requests()

        self.setupUI()

        self._stdout.println("[+] Extension loaded successfully!")
        self._stdout.println("[+] Using storage file: %s" % self.storage_file)
        self._stdout.println("[+] Loaded %d previously processed requests" % len(self._processed_requests))

    def log(self, message):
        self._stdout.println("[*] %s" % message)

    def log_error(self, message):
        self.log(message)
        """Helper method for error logging"""
        self._stdout.println("[!] ERROR: %s" % message)
        traceback.print_exc(file=self._stdout)

    def setupUI(self):
        try:
            self.panel = JPanel()
            self.panel.setLayout(BoxLayout(self.panel, BoxLayout.Y_AXIS))

            self.require_params_checkbox = JCheckBox("Only process requests with parameters",
                                                     self.config['require_parameters'])
            self.require_params_checkbox.addActionListener(lambda x: self.updateConfig())

            params_panel = JPanel(FlowLayout(FlowLayout.LEFT))
            params_panel.add(JLabel("Ignored parameters (comma-separated):"))
            self.ignored_params_field = JTextField(
                ','.join(self.config['ignored_parameters']),
                30
            )
            self.ignored_params_field.addActionListener(lambda x: self.updateConfig())
            params_panel.add(self.ignored_params_field)

            button_panel = JPanel(FlowLayout(FlowLayout.LEFT))
            process_history_button = JButton("Process Existing History",
                                             actionPerformed=lambda x: self.processExistingHistory())
            clear_history_button = JButton("Clear Processed History",
                                           actionPerformed=lambda x: self.clear_processed_requests())
            button_panel.add(process_history_button)
            button_panel.add(clear_history_button)

            self.panel.add(self.require_params_checkbox)
            self.panel.add(params_panel)
            self.panel.add(button_panel)

            self._callbacks.customizeUiComponent(self.panel)
            self._callbacks.addSuiteTab(self)

            self.log("UI setup completed successfully")
        except Exception as e:
            self.log_error("Error setting up UI: %s" % str(e))

    def getTabCaption(self):
        return "Add to Repeater"

    def getUiComponent(self):
        return self.panel

    def updateConfig(self):
        try:
            self.config['require_parameters'] = self.require_params_checkbox.isSelected()
            self.config['ignored_parameters'] = [
                p.strip() for p in self.ignored_params_field.getText().split(',')
                if p.strip()
            ]
            self.save_config()
            self.log("Configuration updated")
        except Exception as e:
            self.log_error("Error updating config: %s" % str(e))

    def load_config(self):
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    saved_config = json.load(f)
                    self.config.update(saved_config)
                    self.log("Configuration loaded from: %s" % self.config_file)
        except Exception as e:
            self.log_error("Error loading config: %s" % str(e))

    def save_config(self):
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f)
                self.log("Configuration saved to: %s" % self.config_file)
        except Exception as e:
            self.log_error("Error saving config: %s" % str(e))

    def get_storage_file_path(self):
        try:
            project_file = self._callbacks.saveConfigAsJson("")
            project_data = json.loads(project_file)

            if "project_options" in project_data:
                burp_project_file = project_data["project_options"].get("connections", {}).get("project_file", "")

                if burp_project_file:
                    project_name = os.path.splitext(os.path.basename(burp_project_file))[0]
                    return os.path.join(
                        os.path.expanduser("~"),
                        ".burp_auto_repeater_%s.json" % project_name
                    )

            return os.path.join(
                os.path.expanduser("~"),
                ".burp_auto_repeater_default.json"
            )

        except Exception as e:
            self.log_error("Error getting project file path: %s" % str(e))
            return os.path.join(
                os.path.expanduser("~"),
                ".burp_auto_repeater_default.json"
            )

    def load_processed_requests(self):
        try:
            if os.path.exists(self.storage_file):
                with open(self.storage_file, 'r') as f:
                    data = set(json.load(f))
                    self.log("Loaded %d processed requests from storage" % len(data))
                    return data
            return set()
        except Exception as e:
            self.log_error("Error loading processed requests: %s" % str(e))
            return set()

    def save_processed_requests(self):
        try:
            with open(self.storage_file, 'w') as f:
                json.dump(list(self._processed_requests), f)
                self.log("Saved %d processed requests to storage" % len(self._processed_requests))
        except Exception as e:
            self.log_error("Error saving processed requests: %s" % str(e))

    def create_request_identifier(self, messageInfo):
        try:
            request = messageInfo.getRequest()
            service = messageInfo.getHttpService()

            identifier = "%s://%s:%s" % (
                service.getProtocol(),
                service.getHost(),
                service.getPort()
            )

            analyzed_request = self._helpers.analyzeRequest(messageInfo.getHttpService(), request)

            identifier += "%s:%s" % (
                analyzed_request.getMethod(),
                analyzed_request.getUrl().getPath()
            )

            self.log("Created identifier: %s" % identifier)
            return identifier
        except Exception as e:
            self.log_error("Error creating request identifier: %s" % str(e))
            return None

    def create_tab_name(self, messageInfo):
        try:
            analyzed_request = self._helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest())
            url = analyzed_request.getUrl()

            path = url.getPath()
            path_parts = path.split('/')
            last_path = path_parts[-1] if path_parts else ''

            params = analyzed_request.getParameters()
            param_names = [p.getName() for p in params if p.getName() not in self.config['ignored_parameters']]

            if param_names:
                param_short = ''.join(p[0] for p in param_names[:3])
                tab_name = "%s_%s" % (last_path[:8], param_short)
            else:
                tab_name = last_path[:12]

            # counter for uniqueness
            base_name = tab_name
            counter = len(self._processed_requests) + 1
            tab_name = "%s_%d" % (base_name, counter)

            # max length
            tab_name = tab_name[:15]

            #self.log("Created tab name: %s" % tab_name)
            return tab_name
        except Exception as e:
            self.log_error("Error creating tab name: %s" % str(e))
            return "Auto_%d" % len(self._processed_requests)

    def has_valid_parameters(self, messageInfo):
        try:
            analyzed_request = self._helpers.analyzeRequest(
                messageInfo.getHttpService(),
                messageInfo.getRequest()
            )
            params = analyzed_request.getParameters()

            valid_params = [p for p in params if p.getName() not in self.config['ignored_parameters']]
            has_valid = len(valid_params) > 0
            #self.log("Request has %d valid parameters" % len(valid_params))
            return has_valid
        except Exception as e:
            self.log_error("Error checking parameters: %s" % str(e))
            return False

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            if not messageIsRequest:
                return

            if not self._callbacks.isInScope(self._helpers.analyzeRequest(messageInfo).getUrl()):
                #self.log("Request not in scope, skipping: " + messageInfo.getUrl().toString())
                return

            if self.config['require_parameters'] and not self.has_valid_parameters(messageInfo):
                #self.log("Request has no valid parameters, skipping")
                return

            request_identifier = self.create_request_identifier(messageInfo)
            #self.log("Processing request: %s" % request_identifier)
            if request_identifier in self._processed_requests:
                #self.log("Request already processed, skipping")
                return

            self._processed_requests.add(request_identifier)
            self.save_processed_requests()

            tab_name = self.create_tab_name(messageInfo)

            self._callbacks.sendToRepeater(
                messageInfo.getHttpService().getHost(),
                messageInfo.getHttpService().getPort(),
                messageInfo.getHttpService().getProtocol() == "https",
                messageInfo.getRequest(),
                tab_name
            )
            #self.log("Created new repeater tab: %s" % tab_name)
        except Exception as e:
            self.log_error("Error processing HTTP message: %s" % str(e))

    def processProxyMessage(self, messageIsRequest, message):
        try:
            if messageIsRequest:
                messageInfo = message.getMessageInfo()
                self.processHttpMessage(self._callbacks.TOOL_PROXY, True, messageInfo)
        except Exception as e:
            self.log_error("Error processing proxy message: %s" % str(e))

    def processExistingHistory(self):
        try:
            self.log("Starting to process existing history...")
            proxy_history = self._callbacks.getProxyHistory()
            self.log("Found %d items in proxy history" % len(proxy_history))

            processed_count = 0
            for messageInfo in proxy_history:
                try:

                    self.processHttpMessage(self._callbacks.TOOL_PROXY, True, messageInfo)
                    processed_count += 1
                    if processed_count % 100 == 0:
                        self.log("Processed %d requests..." % processed_count)
                except:
                    self.log("Error processing history item: %s" % messageInfo.getUrl().toString())
                    self.log(traceback.format_exc())

            self.log("Finished processing existing history. Processed %d requests total." % processed_count)
        except Exception as e:
            self.log_error("Error processing existing history: %s" % str(e))

    def clear_processed_requests(self):
        try:
            self._processed_requests.clear()
            self.save_processed_requests()
            self.log("Cleared processed requests history")
        except Exception as e:
            self.log_error("Error clearing processed requests: %s" % str(e))