# BenguelaShield - Ponto de Entrada da Interface Grafica
import sys, os, logging, logging.handlers, threading, traceback

if getattr(sys, 'frozen', False):
    APPLICATION_PATH = os.path.dirname(sys.executable)
    sys.path.insert(0, APPLICATION_PATH)
else:
    APPLICATION_PATH = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, APPLICATION_PATH)

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt

if getattr(sys, 'frozen', False):
    log_dir = os.path.join(os.environ.get('PROGRAMDATA', r'C:\ProgramData'), 'BenguelaShield', 'logs')
else:
    log_dir = os.path.join(APPLICATION_PATH, 'logs')
os.makedirs(log_dir, exist_ok=True)

handler = logging.handlers.RotatingFileHandler(
    os.path.join(log_dir, 'benguelashield.log'),
    maxBytes=10 * 1024 * 1024,
    backupCount=5,
    encoding='utf-8',
)
handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s'))
logging.root.addHandler(handler)
logging.root.setLevel(logging.INFO)
logger = logging.getLogger("BenguelaShield")


def _crash_hook(exc_type, exc_value, exc_tb):
    tb = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
    logger.critical("CRASH NAO TRATADO: %s\n%s", exc_type.__name__, tb)


def _thread_crash_hook(args):
    if args.exc_value:
        tb = "".join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback))
        logger.critical("CRASH EM THREAD: %s\n%s", args.thread_name, tb)


sys.excepthook = _crash_hook
threading.excepthook = _thread_crash_hook


def main():
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    app = QApplication(sys.argv)
    app.setApplicationName('BenguelaShield')
    app.setApplicationVersion('1.0.0')
    from gui.main_window import MainWindow
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
