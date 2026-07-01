# BenguelaShield - Ponto de Entrada da Interface Grafica
import sys, os

if getattr(sys, 'frozen', False):
    APPLICATION_PATH = os.path.dirname(sys.executable)
    sys.path.insert(0, APPLICATION_PATH)
else:
    APPLICATION_PATH = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, APPLICATION_PATH)

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
import logging

if getattr(sys, 'frozen', False):
    log_dir = os.path.join(os.environ.get('PROGRAMDATA', r'C:\ProgramData'), 'BenguelaShield', 'logs')
else:
    log_dir = os.path.join(APPLICATION_PATH, 'logs')
os.makedirs(log_dir, exist_ok=True)
logging.basicConfig(
    filename=os.path.join(log_dir, 'benguelashield.log'),
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)

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
