"""Janela principal do BenguelaShield — navegação, layout e interacção."""

from __future__ import annotations

import sys
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QStackedWidget, QFrame, QApplication,
)

from modules.antivirus.config import AntiVirusConfig
from modules.antivirus.database import DatabaseManager
from gui.dashboard import DashboardPage
from gui.scanner_page import ScannerPage
from gui.quarantine_page import QuarantinePage
from gui.antiransom_page import AntiransomPage
from gui.behavioral_page import BehavioralPage
from gui.yara_page import YaraPage
from gui.settings_page import SettingsPage
from gui.reports_page import ReportsPage
from gui.tools_page import ToolsPage
from gui.notifications import ToastNotification
from gui.styles import DARK_STYLE


class MainWindow(QMainWindow):
    """Janela principal com sidebar e stacked widget."""

    def __init__(self) -> None:
        super().__init__()
        self.config = AntiVirusConfig()
        self.db = DatabaseManager(self.config.db_path)

        self.setWindowTitle("BenguelaShield — Antivírus Open Source")
        self.setMinimumSize(1200, 750)
        self.resize(1400, 900)
        self.setStyleSheet(DARK_STYLE)

        self._btns: list[QPushButton] = []
        self._page_names: list[str] = []

        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        sidebar = self._criar_sidebar()
        main_layout.addWidget(sidebar)

        self._stack = QStackedWidget()
        main_layout.addWidget(self._stack, 1)

        self._dashboard = DashboardPage(self.config, self.db)
        self._scanner = ScannerPage(self.config, self.db)
        self._quarantine = QuarantinePage(self.config, self.db)
        self._antiransom = AntiransomPage(self.config, self.db)
        self._behavioral = BehavioralPage(self.config, self.db)
        self._yara = YaraPage(self.config, self.db)
        self._settings = SettingsPage(self.config)
        self._reports = ReportsPage(self.db)
        self._tools = ToolsPage()

        self._pages = [
            self._dashboard,
            self._scanner,
            self._quarantine,
            self._antiransom,
            self._behavioral,
            self._yara,
            self._settings,
            self._reports,
            self._tools,
        ]

        for page in self._pages:
            self._stack.addWidget(page)

        self._toast = ToastNotification(self)

        self._dashboard._btn_rapido.clicked.connect(self._scan_rapido_dashboard)
        self._dashboard._btn_completo.clicked.connect(self._scan_completo_dashboard)
        self._scanner.scan_concluido.connect(self._on_scan_concluido)

        self._navegar(0)

    def _criar_sidebar(self) -> QFrame:
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(240)
        sidebar.setStyleSheet("""
            #sidebar {
                background-color: #111111;
                border-right: 1px solid #222222;
            }
        """)

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(16, 24, 16, 24)
        layout.setSpacing(4)

        logo_layout = QHBoxLayout()
        logo_label = QLabel("BS")
        logo_label.setFixedSize(36, 36)
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo_label.setStyleSheet("""
            background-color: #00c853;
            color: #0d0d0d;
            font-size: 18px;
            font-weight: bold;
            border-radius: 8px;
        """)
        logo_layout.addWidget(logo_label)

        nome_label = QLabel("BenguelaShield")
        nome_label.setStyleSheet("color: #ffffff; font-size: 16px; font-weight: bold;")
        logo_layout.addWidget(nome_label)
        logo_layout.addStretch()
        layout.addLayout(logo_layout)

        versao_label = QLabel("v1.0.0 — Motor: ClamAV 1.5.2")
        versao_label.setStyleSheet("color: #555555; font-size: 11px; padding-left: 4px;")
        layout.addWidget(versao_label)

        layout.addSpacing(16)

        self._status_label = QLabel("Estado: Protegido")
        self._status_label.setStyleSheet("""
            color: #00c853;
            font-size: 13px;
            font-weight: bold;
            padding: 8px 12px;
            background-color: #0a2e1a;
            border-radius: 6px;
        """)
        layout.addWidget(self._status_label)

        layout.addSpacing(12)

        itens = [
            ("  Painel", 0),
            ("  Scanner", 1),
            ("  Quarentena", 2),
            ("  Anti-Ransom", 3),
            ("  Comportamental", 4),
            ("  YARA", 5),
            ("  Ferramentas", 8),
            ("  Definicoes", 6),
            ("  Relatorios", 7),
        ]

        for nome, idx in itens:
            btn = QPushButton(nome)
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda checked, i=idx: self._navegar(i))
            layout.addWidget(btn)
            self._btns.append(btn)

        layout.addStretch()

        stats_label = QLabel("161 testes | 4 motores")
        stats_label.setStyleSheet("color: #444444; font-size: 11px; padding-left: 4px;")
        layout.addWidget(stats_label)

        return sidebar

    def _navegar(self, idx: int) -> None:
        self._stack.setCurrentIndex(idx)
        for i, btn in enumerate(self._btns):
            btn.setChecked(i == idx)

    def _scan_rapido_dashboard(self) -> None:
        self._navegar(1)
        self._scanner._scan_rapido()
        self._toast.show_toast("Scan rapido iniciado...", "info")

    def _scan_completo_dashboard(self) -> None:
        self._navegar(1)
        self._scanner._scan_completo()
        self._toast.show_toast("Scan completo iniciado...", "info")

    def _on_scan_concluido(self) -> None:
        stats = self.db.get_stats()
        ameacas = stats.get("total_threats", 0)
        if ameacas > 0:
            self._toast.show_toast(f"Scan concluido — {ameacas} ameaca(s) bloqueada(s)", "error")
            self._status_label.setText("Estado: Ameaca detectada")
            self._status_label.setStyleSheet("color: #ff1744; font-size: 13px; font-weight: bold; padding: 8px 12px; background-color: #2e0a0a; border-radius: 6px;")
        else:
            self._toast.show_toast("Scan concluido — Sistema limpo", "ok")
            self._status_label.setText("Estado: Protegido")
            self._status_label.setStyleSheet("color: #00c853; font-size: 13px; font-weight: bold; padding: 8px 12px; background-color: #0a2e1a; border-radius: 6px;")

    def mostrar_toast(self, mensagem: str, tipo: str = "info") -> None:
        self._toast.show_toast(mensagem, tipo)

    def closeEvent(self, event) -> None:
        self.db.close()
        super().closeEvent(event)


def main() -> None:
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
