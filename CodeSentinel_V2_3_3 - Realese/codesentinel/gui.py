import json
from pathlib import Path
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QBrush
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QPlainTextEdit, QFileDialog, QComboBox, QTableWidget,
    QTableWidgetItem, QMessageBox, QHeaderView)
from .analyzer import analyze, analyze_file, MAX_BYTES
from .project_engine import analyze_project

SEVERITY_COLORS = {
    'low': '#4ADE80',
    'medium': '#FACC15',
    'high': '#F87171',
    'critical': '#F87171',
}

STYLE = '''QWidget{background:#10141d;color:#e5eaf3;font-family:Segoe UI;font-size:13px}
QPlainTextEdit,QTableWidget,QComboBox{background:#171e2b;border:1px solid #344053;border-radius:7px;padding:7px}
QPushButton{background:#2463bb;color:white;border:0;border-radius:7px;padding:10px 15px;font-weight:600}
QPushButton:hover{background:#357ad9}QHeaderView::section{background:#263247;color:white;padding:7px;border:0}
'''
class DropEditor(QPlainTextEdit):
    def __init__(self, callback):
        super().__init__(); self.callback = callback; self.setAcceptDrops(True)
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls() and len(event.mimeData().urls()) == 1 and event.mimeData().urls()[0].isLocalFile():
            event.acceptProposedAction()
        else: super().dragEnterEvent(event)
    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if len(urls)==1 and urls[0].isLocalFile():
            self.callback(urls[0].toLocalFile()); event.acceptProposedAction()
        else: super().dropEvent(event)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__(); self.setWindowTitle('CodeSentinel V2.3.3 — Reliability Update'); self.resize(1000,740)
        self.current_file=None; self.result=None; self.project_result=None
        root=QWidget(); self.setCentralWidget(root); layout=QVBoxLayout(root); layout.setSpacing(12)
        title=QLabel('🛡 CodeSentinel'); title.setStyleSheet('font-size:27px;font-weight:bold;color:#7cb3ff'); layout.addWidget(title)
        layout.addWidget(QLabel("Don't trust us. Trust the CODE.  |  Static analysis — target code is never executed"))
        bar=QHBoxLayout(); layout.addLayout(bar)
        open_btn=QPushButton('Open file'); open_btn.clicked.connect(self.open_file); bar.addWidget(open_btn)
        project_btn=QPushButton('Scan folder'); project_btn.clicked.connect(self.scan_folder); bar.addWidget(project_btn)
        self.lang=QComboBox(); self.lang.addItems(['Python','Lua','JavaScript','Text']); bar.addWidget(self.lang)
        scan=QPushButton('Analyze code'); scan.clicked.connect(self.scan); bar.addWidget(scan)
        export=QPushButton('Export JSON'); export.clicked.connect(self.export); bar.addWidget(export)
        self.editor=DropEditor(self.load_file); self.editor.setPlaceholderText('Paste code here or drag a .py, .lua, .luau, .js, .txt file...'); layout.addWidget(self.editor,3)
        self.editor.textChanged.connect(lambda: self.clear_results('Code changed — analyze again'))
        self.lang.currentTextChanged.connect(lambda _: self.clear_results('Language changed — analyze again'))
        self.summary=QLabel('Ready. Paste code or open a file.'); layout.addWidget(self.summary)
        self.table=QTableWidget(0,4); self.table.setHorizontalHeaderLabels(['Severity','Line','Rule','Finding / explanation'])
        self.table.horizontalHeader().setSectionResizeMode(3,QHeaderView.Stretch); self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.table,2)
        self.setStyleSheet(STYLE)
    def clear_results(self, message='Ready. Paste code or open a file.'):
        self.result = None
        self.project_result = None
        self.table.setRowCount(0)
        self.summary.setText(message)
        self.summary.setStyleSheet('color:#FACC15;font-weight:600')

    def open_file(self):
        path,_=QFileDialog.getOpenFileName(self,'Choose source file','','Source files (*.py *.lua *.luau *.js *.txt)')
        if path:self.load_file(path)
    def load_file(self,path):
        try:
            p=Path(path)
            if p.suffix.lower() not in {'.py','.lua','.luau','.js','.txt'}: raise ValueError('Unsupported file extension.')
            if p.stat().st_size>MAX_BYTES: raise ValueError('File exceeds 2 MiB limit.')
            data=p.read_bytes()
            if b'\x00' in data:raise ValueError('Binary files are unsupported.')
            self.editor.setPlainText(data.decode('utf-8-sig',errors='replace'))
            self.current_file=str(p)
            self.lang.setCurrentText({'.py':'Python','.lua':'Lua','.luau':'Lua','.js':'JavaScript','.txt':'Text'}[p.suffix.lower()])
            self.clear_results(f'Loaded: {p.name} — click Analyze code')
        except Exception as exc: QMessageBox.warning(self,'Unable to open',str(exc))
    def scan(self):
        self.clear_results('Analyzing...')
        try:
            source = self.editor.toPlainText()
            filename = Path(self.current_file).name if self.current_file else 'pasted.txt'
            report = analyze(source, filename, self.lang.currentText())
            mismatch_info = report.get('language_mismatch')
            if mismatch_info:
                selected, detected = mismatch_info['selected'], mismatch_info['detected']
                response = QMessageBox.warning(
                    self, 'Possible language mismatch',
                    f'Possibly the wrong language selected.\n\nSelected: {selected}\nDetected: {detected}\n\n'
                    'The code appears to use syntax from a different language.\n'
                    'Would you like to switch and analyze again?',
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
                if response == QMessageBox.Yes:
                    self.lang.setCurrentText(detected)
                    self.scan()
                    return
                # Declined: never display old findings or imply a completed scan.
                if report['analysis_state'] == 'paused_language_mismatch':
                    self.result = report
                    self.summary.setText('Analysis paused — language mismatch. No security findings evaluated.')
                    return
            self.result = report
            for f in report['findings']:
                self.add_finding(f['severity'], str(f['line']), f['rule_id'],
                                 f['title'] + ' — ' + f['explanation'] + ' | ' + f['snippet'])
            self.summary.setText(f"{report['finding_count']} finding(s) | {report['status']} | SHA-256: {report['sha256'][:20]}…")
            severities = [f['severity'].lower() for f in report['findings']]
            priority = next((level for level in ('critical', 'high', 'medium', 'low') if level in severities), None)
            self.summary.setStyleSheet(f"color: {SEVERITY_COLORS.get(priority, '#FACC15') if report['analysis_complete'] else '#FACC15'}; font-weight: 600;")
        except Exception as exc:
            self.clear_results('Analysis failed — no report available')
            QMessageBox.warning(self, 'Analysis error', str(exc))
    def scan_folder(self):
        folder = QFileDialog.getExistingDirectory(self, 'Choose source folder (read-only scan)')
        if not folder: return
        self.clear_results('Scanning folder...')
        try:
            self.project_result = analyze_project(folder)
            self.result = None
            self.table.setRowCount(0)
            for report in self.project_result['reports']:
                for f in report['findings']:
                    self.add_finding(f['severity'], str(f['line']), f['rule_id'], report['file'] + ': ' + f['title'] + ' — ' + f['explanation'])
            for c in self.project_result['correlations']:
                self.add_finding(c['severity'], '—', c['rule_id'], c['title'] + ' — ' + c['explanation'] + ' [' + ', '.join(c['files']) + ']')
            r=self.project_result
            self.summary.setText(f"Project: {r['files_scanned']} files | {r['finding_count']} findings | {len(r['correlations'])} correlations | {r['status']}")
            self.summary.setStyleSheet('color:#FACC15;font-weight:600')
        except Exception as exc:
            self.clear_results('Project scan failed — no report available')
            QMessageBox.warning(self, 'Project scan error', str(exc))
    def add_finding(self, severity, line, rule, detail):
        row=self.table.rowCount(); self.table.insertRow(row)
        for col,value in enumerate((severity.upper(),line,rule,detail)):
            item=QTableWidgetItem(value)
            item.setForeground(QBrush(QColor(SEVERITY_COLORS.get(severity.lower(),'#E5EAF3'))))
            self.table.setItem(row,col,item)
    def export(self):
        if self.result is None and self.project_result is None: QMessageBox.information(self,'No report','Analyze code first.'); return
        path,_=QFileDialog.getSaveFileName(self,'Export report','codesentinel-report.json','JSON (*.json)')
        if path:
            try:Path(path).write_text(json.dumps(self.project_result if self.project_result is not None else self.result,indent=2,ensure_ascii=False),encoding='utf-8')
            except Exception as exc: QMessageBox.warning(self,'Export failed',str(exc))

def run():
    app=QApplication([]); window=MainWindow(); window.show(); app.exec()
