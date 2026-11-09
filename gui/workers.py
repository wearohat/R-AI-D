import logging

from PySide6.QtCore import QObject, QThread, Signal


class TaskWorker(QThread):
    progress = Signal(str, int, int, str)
    finished_ok = Signal(object)
    failed = Signal(str)

    def __init__(self, task, *args, **kwargs):
        super().__init__()
        self.task = task
        self.args = args
        self.kwargs = kwargs
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def is_cancelled(self):
        return self._cancel

    def _progress(self, stage, done, total, text):
        self.progress.emit(stage, done, total, str(text))

    def run(self):
        try:
            kwargs = dict(self.kwargs)
            if kwargs.pop("with_progress", False):
                kwargs["progress"] = self._progress
                kwargs["should_cancel"] = self.is_cancelled
            self.finished_ok.emit(self.task(*self.args, **kwargs))
        except Exception as e:
            self.failed.emit(str(e))


class LogBridge(QObject):
    message = Signal(str)


class QtLogHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.bridge = LogBridge()
        self.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))

    def emit(self, record):
        try:
            self.bridge.message.emit(self.format(record))
        except Exception:
            pass
