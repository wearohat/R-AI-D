from PySide6.QtCore import Qt
from PySide6.QtGui import QCursor
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSizePolicy,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QToolTip,
    QVBoxLayout,
    QWidget,
)
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg

from gui.charts import chart_tooltip, figure_to_png


class StatTile(QFrame):
    def __init__(self, title):
        super().__init__()
        self.setObjectName("statTile")
        layout = QVBoxLayout(self)
        self.value_label = QLabel("-")
        self.value_label.setObjectName("statValue")
        title_label = QLabel(title)
        title_label.setObjectName("statTitle")
        layout.addWidget(self.value_label)
        layout.addWidget(title_label)

    def set_value(self, value):
        self.value_label.setText("-" if value is None else str(value))


def _cell(value):
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.1f}" if not value.is_integer() else str(int(value))
    return str(value)


class ChartCard(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("chartCard")
        self.chart = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 12)

        header = QHBoxLayout()
        titles = QVBoxLayout()
        self.title_label = QLabel()
        self.title_label.setObjectName("chartTitle")
        self.subtitle_label = QLabel()
        self.subtitle_label.setObjectName("chartSubtitle")
        self.subtitle_label.setWordWrap(True)
        titles.addWidget(self.title_label)
        titles.addWidget(self.subtitle_label)
        header.addLayout(titles, 1)
        self.toggle_button = QPushButton("Table")
        self.toggle_button.setCheckable(True)
        self.toggle_button.toggled.connect(self._toggle)
        self.save_button = QPushButton("Save PNG")
        self.save_button.clicked.connect(self._save_png)
        header.addWidget(self.toggle_button, 0, Qt.AlignTop)
        header.addWidget(self.save_button, 0, Qt.AlignTop)
        layout.addLayout(header)

        self.stack = QStackedWidget()
        self.table = QTableWidget()
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.stack.addWidget(QWidget())
        self.stack.addWidget(self.table)
        layout.addWidget(self.stack)

    def set_chart(self, chart):
        self.chart = chart
        self.title_label.setText(chart.title)
        self.subtitle_label.setText(chart.subtitle)

        old = self.stack.widget(0)
        canvas = FigureCanvasQTAgg(chart.figure)
        canvas.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        canvas.setMinimumHeight(int(min(chart.figure.get_size_inches()[1] * chart.figure.dpi, 480)))
        canvas.mpl_connect("motion_notify_event", self._hover)
        self.stack.insertWidget(0, canvas)
        self.stack.removeWidget(old)
        old.deleteLater()

        self.table.clear()
        self.table.setColumnCount(len(chart.columns))
        self.table.setHorizontalHeaderLabels(chart.columns)
        self.table.setRowCount(len(chart.rows))
        for r, row in enumerate(chart.rows):
            for c, value in enumerate(row):
                item = QTableWidgetItem(_cell(value))
                if isinstance(value, (int, float)):
                    item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                self.table.setItem(r, c, item)

        self.toggle_button.setEnabled(not chart.empty)
        self.save_button.setEnabled(not chart.empty)
        self.stack.setCurrentIndex(1 if self.toggle_button.isChecked() and not chart.empty else 0)

    def _toggle(self, checked):
        self.toggle_button.setText("Chart" if checked else "Table")
        self.stack.setCurrentIndex(1 if checked else 0)

    def _hover(self, event):
        text = chart_tooltip(self.chart, event) if self.chart and event.inaxes else None
        if text:
            QToolTip.showText(QCursor.pos(), text, self)
        else:
            QToolTip.hideText()

    def _save_png(self):
        if not self.chart:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save chart", f"{self.chart.key}.png", "PNG image (*.png)")
        if path:
            with open(path, "wb") as f:
                f.write(figure_to_png(self.chart.figure, dpi=200))
