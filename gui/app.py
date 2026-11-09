import sys

from PySide6.QtWidgets import QApplication

from gui.main_window import MainWindow

STYLESHEET = """
QWidget { background-color: #10131a; color: #d7dde4; font-size: 10.5pt; }
#statTile { background-color: #1a1f2b; border-radius: 8px; padding: 8px; }
#statValue { font-size: 20pt; font-weight: bold; color: #4fd1c5; background: transparent; }
#statTitle { color: #9aa5b1; font-size: 9pt; background: transparent; }
#statusLabel { color: #9aa5b1; }
#chartCard { background-color: #1a1f2b; border: 1px solid #2a3040; border-radius: 8px; }
#chartCard QLabel { background-color: transparent; }
#chartTitle { font-size: 11.5pt; font-weight: bold; color: #f0efec; }
#chartSubtitle { color: #9aa5b1; font-size: 9pt; }
QTabWidget::pane { border: 1px solid #2a3040; }
QTabBar::tab { background: #1a1f2b; padding: 8px 16px; }
QTabBar::tab:selected { background: #2a3040; color: #4fd1c5; }
QPushButton { background-color: #2a3040; border: 1px solid #3a4258; padding: 6px 14px; border-radius: 4px; }
QPushButton:hover { background-color: #343c54; }
QPushButton:checked { background-color: #3a4258; }
QPushButton:disabled { color: #666; }
QLineEdit, QComboBox, QSpinBox, QPlainTextEdit, QTableWidget {
    background-color: #1a1f2b; border: 1px solid #3a4258; border-radius: 4px; padding: 4px;
}
QHeaderView::section { background-color: #2a3040; color: #d7dde4; padding: 4px; border: none; }
QProgressBar { border: 1px solid #3a4258; border-radius: 4px; text-align: center; }
QProgressBar::chunk { background-color: #4fd1c5; }
QGroupBox { border: 1px solid #2a3040; margin-top: 10px; padding-top: 12px; font-weight: bold; }
QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 4px; }
QToolTip { background-color: #2a3040; color: #f0efec; border: 1px solid #3a4258; padding: 4px; }
"""


def run_gui():
    app = QApplication(sys.argv)
    app.setApplicationName("R-AI-D")
    app.setStyleSheet(STYLESHEET)
    window = MainWindow()
    window.show()
    return app.exec()
