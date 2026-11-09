import json

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ai.providers import PROVIDERS, list_models, needs_key, test_connection
from gui import pipeline
from gui.charts import build_charts
from gui.data import load_scan_data, score_of, urlhaus_urls, vt_detections
from gui.settings_store import config_from_settings, load_settings, save_settings
from gui.widgets import ChartCard, StatTile
from gui.workers import QtLogHandler, TaskWorker
from mitre.attack import techniques_for_sources
from utils.logger import logger

STAGES = {"collect": "Collecting subdomains", "enrich": "Resolving and enriching", "analyse": "AI analysis"}

INTEL_LABELS = {"shodan": "Shodan API", "virustotal": "VirusTotal", "urlhaus": "URLhaus"}


class ScanTab(QWidget):
    def __init__(self):
        super().__init__()
        root = QVBoxLayout(self)

        controls = QHBoxLayout()
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("Target domain, e.g. example.com")
        self.analyse_checkbox = QCheckBox("Run AI analysis")
        self.analyse_checkbox.setChecked(True)
        self.start_button = QPushButton("Start Scan")
        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)
        controls.addWidget(self.domain_input, 1)
        controls.addWidget(self.analyse_checkbox)
        controls.addWidget(self.start_button)
        controls.addWidget(self.stop_button)
        root.addLayout(controls)

        self.provider_label = QLabel()
        self.provider_label.setObjectName("statusLabel")
        root.addWidget(self.provider_label)
        self.intel_label = QLabel()
        self.intel_label.setObjectName("statusLabel")
        root.addWidget(self.intel_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        root.addWidget(self.progress_bar)
        self.stage_label = QLabel("Idle.")
        self.stage_label.setObjectName("statusLabel")
        root.addWidget(self.stage_label)

        tiles = QGridLayout()
        self.tiles = {
            "found": StatTile("Subdomains found"),
            "resolved": StatTile("Resolved to an IP"),
            "with_evidence": StatTile("With InternetDB data"),
            "analysed": StatTile("Analysed by AI"),
            "failed": StatTile("Failed AI calls"),
            "flagged": StatTile("Flagged by VT / URLhaus"),
        }
        for i, tile in enumerate(self.tiles.values()):
            tiles.addWidget(tile, 0, i)
        root.addLayout(tiles)

        root.addWidget(QLabel("Log"))
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(5000)
        root.addWidget(self.log_view, 1)

    def set_running(self, running):
        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running)
        self.domain_input.setEnabled(not running)
        self.analyse_checkbox.setEnabled(not running)

    def show_summary(self, summary):
        for key, tile in self.tiles.items():
            tile.set_value(summary.get(key))


class ResultsTab(QWidget):
    COLUMNS = ["Subdomain", "Score", "VT detections", "URLhaus URLs", "Reason", "Model"]

    def __init__(self):
        super().__init__()
        root = QVBoxLayout(self)

        controls = QHBoxLayout()
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter by subdomain...")
        self.reanalyse_button = QPushButton("Re-run AI Analysis")
        self.reanalyse_button.setToolTip("Analyse the current target's evidence again with the selected AI provider")
        controls.addWidget(self.filter_input, 1)
        controls.addWidget(self.reanalyse_button)
        root.addLayout(controls)

        splitter = QSplitter()
        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(0, 220)
        self.table.setColumnWidth(1, 60)
        self.table.setColumnWidth(2, 95)
        self.table.setColumnWidth(3, 95)
        self.table.setColumnWidth(4, 340)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSortingEnabled(True)
        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setPlaceholderText("Select a subdomain to see the AI reasoning, suggestions and InternetDB evidence.")
        splitter.addWidget(self.table)
        splitter.addWidget(self.detail)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        root.addWidget(splitter, 1)

        self.scan = None
        self.filter_input.textChanged.connect(self._fill)
        self.table.itemSelectionChanged.connect(self._show_detail)

    def set_data(self, scan):
        self.scan = scan
        self._fill()

    def _fill(self):
        if not self.scan:
            return
        query = self.filter_input.text().strip().lower()
        rows = [r for r in self.scan.results if query in r["subdomain"].lower()]
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(rows))
        for i, result in enumerate(rows):
            subdomain_item = QTableWidgetItem(result["subdomain"])
            subdomain_item.setData(Qt.UserRole, result["subdomain"])
            record = self.scan.evidence.get(result["subdomain"], {})
            values = [
                subdomain_item,
                self._number(score_of(result)),
                self._number(vt_detections(record)) if "virustotal" in record else QTableWidgetItem("-"),
                self._number(urlhaus_urls(record)) if "urlhaus" in record else QTableWidgetItem("-"),
                QTableWidgetItem(" ".join(str(result.get("reason") or "").split())[:200]),
                QTableWidgetItem(f"{result.get('provider', '')}:{result.get('model', '')}".strip(":")),
            ]
            for col, item in enumerate(values):
                self.table.setItem(i, col, item)
        self.table.setSortingEnabled(True)
        self.table.sortItems(1, Qt.DescendingOrder)

    @staticmethod
    def _number(value):
        item = QTableWidgetItem()
        item.setData(Qt.DisplayRole, value)
        return item

    def _show_detail(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows or not self.scan:
            return
        subdomain = self.table.item(rows[0].row(), 0).data(Qt.UserRole)
        result = next((r for r in self.scan.results if r["subdomain"] == subdomain), {})
        record = self.scan.evidence.get(subdomain, {})
        lines = [
            subdomain,
            f"Score: {result.get('score')} / 10    Model: {result.get('provider', '-')}:{result.get('model', '-')}",
            "",
            "Reason:",
            str(result.get("reason") or "-"),
            "",
            "Suggested manual investigation:",
        ]
        lines += [f"  - {s}" for s in result.get("suggestions") or []] or ["  -"]
        lines += ["", "MITRE ATT&CK techniques used to collect this evidence:"]
        lines += [f"  {t['id']}  {t['name']}" for t in techniques_for_sources(record)]
        vt = record.get("virustotal")
        if vt:
            lines += ["", f"VirusTotal: {vt.get('malicious', 0)} malicious, {vt.get('suspicious', 0)} suspicious "
                          f"of {vt.get('vendors_total', 0)} vendors"]
            if vt.get("flagged_by"):
                lines.append("  Flagged by: " + ", ".join(vt["flagged_by"]))
        uh = record.get("urlhaus")
        if uh:
            lines += ["", f"URLhaus: {uh.get('url_count', 0)} malware URL(s), {uh.get('online', 0)} online"]
            lines += [f"  {u.get('status')}  {u.get('threat')}  {u.get('url')}" for u in uh.get("urls") or []]
        sh = record.get("shodan")
        if sh:
            lines += ["", f"Shodan API: {sh.get('org') or '-'} · {sh.get('os') or 'OS unknown'}"]
            for service in sh.get("services") or []:
                product = " ".join(str(v) for v in (service.get("product"), service.get("version")) if v)
                lines.append(f"  {service.get('port')}/{service.get('transport')}  {product or service.get('module') or ''}")
        lines += ["", "Raw evidence:", json.dumps(record, indent=2) if record else "  (none)"]
        self.detail.setPlainText("\n".join(lines))


class ChartsTab(QWidget):
    def __init__(self):
        super().__init__()
        outer = QVBoxLayout(self)
        controls = QHBoxLayout()
        self.summary_label = QLabel("Charts appear after a scan.")
        self.summary_label.setObjectName("statusLabel")
        self.refresh_button = QPushButton("Refresh")
        controls.addWidget(self.summary_label, 1)
        controls.addWidget(self.refresh_button)
        outer.addLayout(controls)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        container = QWidget()
        grid = QGridLayout(container)
        grid.setSpacing(12)
        scroll.setWidget(container)
        outer.addWidget(scroll, 1)
        self.cards = [ChartCard() for _ in range(9)]
        for i, card in enumerate(self.cards[:8]):
            grid.addWidget(card, i // 2, i % 2)
        grid.addWidget(self.cards[8], 4, 0, 1, 2)

    def set_data(self, scan):
        for card, chart in zip(self.cards, build_charts(scan)):
            card.set_chart(chart)
        summary = scan.summary
        parts = [summary.get("domain") or "Current output folder"]
        if summary.get("finished"):
            parts.append(f"scanned {summary['finished'].replace('T', ' ')[:16]} UTC")
        parts.append(f"{len(scan.subdomains)} subdomains, {len(scan.evidence)} with evidence, {len(scan.results)} analysed")
        self.summary_label.setText(" · ".join(parts))


class ProviderTab(QWidget):
    def __init__(self, settings):
        super().__init__()
        self.settings = settings
        self.current = settings["provider"]
        root = QVBoxLayout(self)

        box = QGroupBox("AI provider")
        form = QFormLayout(box)
        self.provider_combo = QComboBox()
        for name, info in PROVIDERS.items():
            self.provider_combo.addItem(info["label"], name)
        self.model_combo = QComboBox()
        self.model_combo.setEditable(True)
        self.model_combo.setMinimumWidth(320)
        self.refresh_models_button = QPushButton("Refresh models")
        model_row = QHBoxLayout()
        model_row.addWidget(self.model_combo, 1)
        model_row.addWidget(self.refresh_models_button)
        self.base_url_input = QLineEdit()
        self.key_input = QLineEdit()
        self.key_input.setEchoMode(QLineEdit.Password)
        self.key_label = QLabel("API key:")
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(10, 3600)
        self.timeout_spin.setSuffix(" s")
        self.timeout_spin.setValue(int(settings.get("timeout") or 300))
        self.remember_keys = QCheckBox("Remember API keys on this computer (stored in plain text)")
        self.remember_keys.setChecked(bool(settings.get("remember_keys")))
        self.hint_label = QLabel()
        self.hint_label.setWordWrap(True)
        self.hint_label.setObjectName("statusLabel")

        form.addRow("Provider:", self.provider_combo)
        form.addRow("Model:", model_row)
        form.addRow("Server / base URL:", self.base_url_input)
        form.addRow(self.key_label, self.key_input)
        form.addRow("Request timeout:", self.timeout_spin)
        form.addRow(self.remember_keys)
        form.addRow(self.hint_label)
        root.addWidget(box)

        intel_box = QGroupBox("Threat intelligence API keys (optional)")
        intel_form = QFormLayout(intel_box)
        self.intel_inputs = {}
        for name, label in INTEL_LABELS.items():
            field = QLineEdit(settings["intel_keys"].get(name, ""))
            field.setEchoMode(QLineEdit.Password)
            self.intel_inputs[name] = field
            intel_form.addRow(f"{label} key:", field)
        intel_hint = QLabel(
            "Without a key that source is skipped. Shodan adds detailed services to InternetDB; VirusTotal "
            "checks each subdomain against 70+ antivirus vendors (free key: 4 lookups per minute, so large "
            "scans take longer); URLhaus checks for known malware-distribution URLs (free Auth-Key from abuse.ch)."
        )
        intel_hint.setWordWrap(True)
        intel_hint.setObjectName("statusLabel")
        intel_form.addRow(intel_hint)
        root.addWidget(intel_box)

        buttons = QHBoxLayout()
        self.test_button = QPushButton("Test Connection")
        self.save_button = QPushButton("Save")
        buttons.addWidget(self.test_button)
        buttons.addWidget(self.save_button)
        buttons.addStretch(1)
        root.addLayout(buttons)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        root.addWidget(self.status_label)
        root.addStretch(1)

        self.provider_combo.setCurrentIndex(max(self.provider_combo.findData(self.current), 0))
        self._load_fields(self.current)
        self.provider_combo.currentIndexChanged.connect(self._provider_changed)

    def _load_fields(self, name):
        values = self.settings["providers"][name]
        self.model_combo.clear()
        self.model_combo.addItem(values["model"])
        self.model_combo.setCurrentText(values["model"])
        self.base_url_input.setText(values["base_url"])
        self.key_input.setText(values["api_key"])
        has_key = needs_key(name)
        self.key_input.setVisible(has_key)
        self.key_label.setVisible(has_key)
        if name == "ollama":
            self.hint_label.setText(
                "Runs on your own machine, no API key. Install Ollama from ollama.com, run 'ollama pull <model>', "
                "keep 'ollama serve' running, then press Refresh models and pick an installed model."
            )
        elif name == "openrouter":
            self.hint_label.setText(
                "Needs an OpenRouter API key. 'openrouter/free' picks a free model automatically; "
                "Refresh models lists every model, free ones (':free') first."
            )
        else:
            self.hint_label.setText("Needs an OrcaRouter API key. Refresh models lists the models your key can use.")

    def store_fields(self):
        self.settings["providers"][self.current] = {
            "model": self.model_combo.currentText().strip(),
            "base_url": self.base_url_input.text().strip(),
            "api_key": self.key_input.text().strip(),
        }
        self.settings["provider"] = self.current
        self.settings["timeout"] = self.timeout_spin.value()
        self.settings["remember_keys"] = self.remember_keys.isChecked()
        self.settings["intel_keys"] = {name: field.text().strip() for name, field in self.intel_inputs.items()}

    def _provider_changed(self):
        self.store_fields()
        self.current = self.provider_combo.currentData()
        self.settings["provider"] = self.current
        self._load_fields(self.current)
        self.status_label.setText("")

    def config(self):
        self.store_fields()
        return config_from_settings(self.settings)

    def set_models(self, models):
        current = self.model_combo.currentText()
        self.model_combo.clear()
        self.model_combo.addItems(models)
        self.model_combo.setCurrentText(current if current in models or not models else models[0])
        self.status_label.setText(f"{len(models)} model(s) available." if models else "No models found.")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("R-AI-D - Passive Reconnaissance & AI Triage")
        self.resize(1320, 880)
        self.settings = load_settings()
        self.worker = None
        self.helper = None

        self.scan_tab = ScanTab()
        self.results_tab = ResultsTab()
        self.charts_tab = ChartsTab()
        self.provider_tab = ProviderTab(self.settings)
        tabs = QTabWidget()
        tabs.addTab(self.scan_tab, "Scan")
        tabs.addTab(self.results_tab, "Results")
        tabs.addTab(self.charts_tab, "Charts")
        tabs.addTab(self.provider_tab, "Settings")
        self.setCentralWidget(tabs)

        self.log_handler = QtLogHandler()
        self.log_handler.bridge.message.connect(self.scan_tab.log_view.appendPlainText)
        logger.addHandler(self.log_handler)

        self.scan_tab.start_button.clicked.connect(self.start_scan)
        self.scan_tab.domain_input.returnPressed.connect(self.start_scan)
        self.scan_tab.stop_button.clicked.connect(self.stop)
        self.results_tab.reanalyse_button.clicked.connect(self.reanalyse)
        self.charts_tab.refresh_button.clicked.connect(self.refresh_data)
        self.provider_tab.save_button.clicked.connect(self.save_provider)
        self.provider_tab.test_button.clicked.connect(self.test_provider)
        self.provider_tab.refresh_models_button.clicked.connect(self.refresh_models)
        self.provider_tab.provider_combo.currentIndexChanged.connect(self._update_provider_label)

        self._update_provider_label()
        summary = pipeline.load_summary()
        if summary.get("domain"):
            self.scan_tab.domain_input.setText(summary["domain"])
        self.scan_tab.show_summary(summary)
        self.refresh_data()

    def _update_provider_label(self):
        config = self.provider_tab.config()
        self.scan_tab.provider_label.setText(f"AI provider: {PROVIDERS[config.provider]['label']} · model {config.model}")
        enabled = [INTEL_LABELS[n] for n, key in self.settings["intel_keys"].items() if key]
        self.scan_tab.intel_label.setText(
            "Threat intelligence: InternetDB" + "".join(f", {name}" for name in enabled)
            + ("" if len(enabled) == 3 else " (add API keys in Settings for the others)")
        )

    def _busy(self):
        return self.worker is not None and self.worker.isRunning()

    def _set_busy(self, busy):
        self.scan_tab.set_running(busy)
        self.results_tab.reanalyse_button.setEnabled(not busy)

    def refresh_data(self):
        scan = load_scan_data()
        self.results_tab.set_data(scan)
        self.charts_tab.set_data(scan)

    def _check_provider(self, config):
        if not config.model:
            return "Choose a model in the Settings tab first."
        if needs_key(config.provider) and not config.api_key:
            return f"Enter your {PROVIDERS[config.provider]['label']} API key in the Settings tab first."
        return None

    def _start(self, task, *args, **kwargs):
        self.worker = TaskWorker(task, *args, with_progress=True, **kwargs)
        self.worker.progress.connect(self._on_progress)
        self.worker.finished_ok.connect(self._on_finished)
        self.worker.failed.connect(self._on_failed)
        self._set_busy(True)
        self.scan_tab.progress_bar.setValue(0)
        self.worker.start()

    def start_scan(self):
        if self._busy():
            return
        domain = pipeline.normalize_domain(self.scan_tab.domain_input.text())
        if not pipeline.is_valid_domain(domain):
            QMessageBox.warning(self, "Invalid domain", f"'{domain}' is not a valid domain name.")
            return
        config = None
        if self.scan_tab.analyse_checkbox.isChecked():
            config = self.provider_tab.config()
            problem = self._check_provider(config)
            if problem:
                QMessageBox.warning(self, "AI provider not ready", problem)
                return
        self.provider_tab.store_fields()
        self._update_provider_label()
        self.scan_tab.show_summary({})
        self.scan_tab.stage_label.setText(f"Scanning {domain}...")
        self._start(pipeline.run_scan, domain, config, dict(self.settings["intel_keys"]))

    def reanalyse(self):
        if self._busy():
            return
        config = self.provider_tab.config()
        problem = self._check_provider(config)
        if problem:
            QMessageBox.warning(self, "AI provider not ready", problem)
            return
        self.scan_tab.stage_label.setText(f"Re-running AI analysis with {config.label}...")
        self._start(pipeline.reanalyze, config)

    def stop(self):
        if self._busy():
            self.worker.cancel()
            self.scan_tab.stage_label.setText("Stopping after the current request...")

    def _on_progress(self, stage, done, total, text):
        self.scan_tab.progress_bar.setValue(int(100 * done / max(total, 1)))
        self.scan_tab.stage_label.setText(f"{STAGES.get(stage, stage)}: {done}/{total} · {text}")

    def _on_finished(self, summary):
        self._set_busy(False)
        self.scan_tab.progress_bar.setValue(100)
        self.scan_tab.show_summary(summary)
        aborted = summary.get("aborted")
        if summary.get("status") == "cancelled" or aborted == "cancelled":
            message = "Stopped. Partial results are shown."
        elif aborted and aborted != "AI analysis skipped":
            message = f"AI analysis stopped: {aborted}"
            QMessageBox.warning(self, "AI analysis stopped", aborted)
        elif summary.get("intel_errors"):
            message = "Done. Some threat-intelligence lookups failed: " + "; ".join(summary["intel_errors"].values())
        elif summary.get("failed"):
            message = f"Done. {summary['failed']} AI call(s) failed; see the log."
        else:
            message = "Done." + (f" Analysed with {summary['model']}." if summary.get("model") else "")
        self.scan_tab.stage_label.setText(message)
        self.refresh_data()

    def _on_failed(self, error):
        self._set_busy(False)
        self.scan_tab.stage_label.setText(f"Failed: {error}")
        QMessageBox.warning(self, "Error", error)

    def save_provider(self):
        self.provider_tab.store_fields()
        save_settings(self.settings)
        self._update_provider_label()
        self.provider_tab.status_label.setText("Saved.")

    def _run_helper(self, task, config, on_done, busy_text):
        if self.helper is not None and self.helper.isRunning():
            return
        self.provider_tab.status_label.setText(busy_text)
        self.helper = TaskWorker(task, config)
        self.helper.finished_ok.connect(on_done)
        self.helper.failed.connect(lambda e: self.provider_tab.status_label.setText(f"Failed: {e}"))
        self.helper.start()

    def test_provider(self):
        config = self.provider_tab.config()
        problem = self._check_provider(config)
        if problem:
            self.provider_tab.status_label.setText(problem)
            return
        self._update_provider_label()
        self._run_helper(test_connection, config,
                         lambda reply: self.provider_tab.status_label.setText(f"Connected to {config.label}. Reply: {reply}"),
                         f"Testing {config.label}...")

    def refresh_models(self):
        config = self.provider_tab.config()
        self._run_helper(list_models, config, self.provider_tab.set_models, "Loading models...")

    def closeEvent(self, event):
        running = [w for w in (self.worker, self.helper) if w is not None and w.isRunning()]
        if running:
            answer = QMessageBox.question(self, "Scan in progress", "A task is still running. Stop it and exit?")
            if answer != QMessageBox.Yes:
                event.ignore()
                return
            for worker in running:
                if hasattr(worker, "cancel"):
                    worker.cancel()
                worker.wait()
        logger.removeHandler(self.log_handler)
        self.provider_tab.store_fields()
        save_settings(self.settings)
        event.accept()
