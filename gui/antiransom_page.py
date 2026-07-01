"""Ecrã de Anti-Ransomware do BenguelaShield."""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame,
    QGroupBox, QFormLayout, QCheckBox, QSpinBox, QMessageBox,
)

from modules.antivirus.config import AntiVirusConfig
from modules.antivirus.database import DatabaseManager
from modules.antiransom.config import AntiRansomConfig
from modules.antiransom.folder_shield import FolderShield
from modules.antiransom.backup import BackupManager


class AntiransomPage(QWidget):
    """Ecrã de gestão do módulo anti-ransomware."""

    def __init__(self, config: AntiVirusConfig, db: DatabaseManager, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._av_config = config
        self._db = db
        self._ar_config = AntiRansomConfig(base_dir=config.base_dir)
        self._shield = FolderShield(self._ar_config)
        self._build_ui()
        self._actualizar_estado()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 24, 32, 24)
        layout.setSpacing(16)

        title = QLabel("Anti-Ransomware")
        title.setObjectName("title")
        layout.addWidget(title)

        subtitle = QLabel("Protecção contra sequestradores de ficheiros")
        subtitle.setObjectName("subtitle")
        layout.addWidget(subtitle)

        layout.addSpacing(8)

        # Estado
        estado_frame = QFrame()
        estado_frame.setStyleSheet("""
            QFrame {
                background-color: #1a1a1a;
                border: 1px solid #222222;
                border-radius: 12px;
                padding: 16px;
            }
        """)
        estado_layout = QHBoxLayout(estado_frame)

        self._label_estado = QLabel("A verificar...")
        self._label_estado.setStyleSheet("color: #00c853; font-size: 18px; font-weight: bold;")
        estado_layout.addWidget(self._label_estado)

        self._label_detalhe = QLabel("")
        self._label_detalhe.setStyleSheet("color: #888888; font-size: 13px;")
        estado_layout.addWidget(self._label_detalhe)
        estado_layout.addStretch()

        self._btn_activar = QPushButton("Activar")
        self._btn_activar.setObjectName("btn-primary")
        self._btn_activar.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_activar.clicked.connect(self._toggle_shield)
        estado_layout.addWidget(self._btn_activar)

        layout.addWidget(estado_frame)

        # Estatísticas
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(12)

        self._card_honeypots = self._criar_card("Honeypots", "0", "#ffc107")
        stats_layout.addWidget(self._card_honeypots)

        self._card_backups = self._criar_card("Backups", "0", "#4fc3f7")
        stats_layout.addWidget(self._card_backups)

        self._card_pastas = self._criar_card("Pastas Protegidas", "0", "#00c853")
        stats_layout.addWidget(self._card_pastas)

        self._card_tamanho = self._criar_card("Backup Total", "0 MB", "#9e9e9e")
        stats_layout.addWidget(self._card_tamanho)

        layout.addLayout(stats_layout)

        # Pastas protegidas
        grupo_pastas = QGroupBox("Pastas Protegidas")
        grupo_pastas.setStyleSheet("""
            QGroupBox {
                border: 1px solid #222222;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 20px;
                color: #aaaaaa;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 16px;
                padding: 0 8px;
            }
        """)
        pastas_layout = QVBoxLayout(grupo_pastas)

        self._tabela_pastas = QTableWidget()
        self._tabela_pastas.setColumnCount(2)
        self._tabela_pastas.setHorizontalHeaderLabels(["Pasta", "Estado"])
        self._tabela_pastas.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._tabela_pastas.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._tabela_pastas.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._tabela_pastas.verticalHeader().setVisible(False)
        self._tabela_pastas.setMaximumHeight(150)
        pastas_layout.addWidget(self._tabela_pastas)

        layout.addWidget(grupo_pastas)

        # Honeypots
        grupo_honeypots = QGroupBox("Honeypots (Ficheiros Isco)")
        grupo_honeypots.setStyleSheet(grupo_pastas.styleSheet())
        honeypots_layout = QVBoxLayout(grupo_honeypots)

        self._tabela_honeypots = QTableWidget()
        self._tabela_honeypots.setColumnCount(3)
        self._tabela_honeypots.setHorizontalHeaderLabels(["Ficheiro", "Pasta", "Estado"])
        self._tabela_honeypots.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._tabela_honeypots.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._tabela_honeypots.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._tabela_honeypots.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._tabela_honeypots.verticalHeader().setVisible(False)
        self._tabela_honeypots.setMaximumHeight(150)
        honeypots_layout.addWidget(self._tabela_honeypots)

        layout.addWidget(grupo_honeypots)

        # Backups recentes
        grupo_backups = QGroupBox("Backups Recentes")
        grupo_backups.setStyleSheet(grupo_pastas.styleSheet())
        backups_layout = QVBoxLayout(grupo_backups)

        self._tabela_backups = QTableWidget()
        self._tabela_backups.setColumnCount(4)
        self._tabela_backups.setHorizontalHeaderLabels(["Ficheiro Original", "Versão", "Tamanho", "Data"])
        self._tabela_backups.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._tabela_backups.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._tabela_backups.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._tabela_backups.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._tabela_backups.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._tabela_backups.verticalHeader().setVisible(False)
        self._tabela_backups.setMaximumHeight(150)
        backups_layout.addWidget(self._tabela_backups)

        layout.addWidget(grupo_backups)

        layout.addStretch()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._actualizar_estado)
        self._timer.start(10000)

    def _criar_card(self, titulo: str, valor: str, cor: str) -> QFrame:
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background-color: #1a1a1a;
                border: 1px solid #222222;
                border-radius: 12px;
                padding: 16px;
            }}
        """)
        layout = QVBoxLayout(card)
        layout.setSpacing(4)

        label_titulo = QLabel(titulo)
        label_titulo.setStyleSheet("color: #888888; font-size: 11px;")
        layout.addWidget(label_titulo)

        label_valor = QLabel(valor)
        label_valor.setStyleSheet(f"color: {cor}; font-size: 20px; font-weight: bold;")
        layout.addWidget(label_valor)

        card._label_valor = label_valor
        return card

    def _toggle_shield(self) -> None:
        if self._shield.esta_activo():
            self._shield.parar()
            self._btn_activar.setText("Activar")
            self._btn_activar.setObjectName("btn-primary")
        else:
            honeypots = self._shield.iniciar()
            self._btn_activar.setText("Desactivar")
            self._btn_activar.setObjectName("btn-danger")
            if honeypots > 0:
                self._toast(f"{honeypots} honeypot(s) criado(s)", "ok")
        self._btn_activar.style().polish(self._btn_activar)
        self._actualizar_estado()

    def _actualizar_estado(self) -> None:
        if self._shield.esta_activo():
            self._label_estado.setText("Protecção Activa")
            self._label_estado.setStyleSheet("color: #00c853; font-size: 18px; font-weight: bold;")
            self._label_detalhe.setText("Anti-ransomware a monitorizar pastas críticas")
            self._btn_activar.setText("Desactivar")
            self._btn_activar.setObjectName("btn-danger")
        else:
            self._label_estado.setText("Protecção Inactiva")
            self._label_estado.setStyleSheet("color: #ff1744; font-size: 18px; font-weight: bold;")
            self._label_detalhe.setText("Clique em Activar para proteger o sistema")
            self._btn_activar.setText("Activar")
            self._btn_activar.setObjectName("btn-primary")
        self._btn_activar.style().polish(self._btn_activar)

        status = self._shield.status()
        self._card_honeypots._label_valor.setText(str(status["honeypots_activos"]))
        self._card_backups._label_valor.setText(str(status["total_backups"]))
        self._card_pastas._label_valor.setText(str(status["pastas_protegidas"]))
        self._card_tamanho._label_valor.setText(f"{status['tamanho_backups_mb']:.1f} MB")

        self._actualizar_tabela_pastas()
        self._actualizar_tabela_honeypots()
        self._actualizar_tabela_backups()

    def _actualizar_tabela_pastas(self) -> None:
        self._tabela_pastas.setRowCount(0)
        for pasta in self._ar_config.protected_dirs:
            row = self._tabela_pastas.rowCount()
            self._tabela_pastas.insertRow(row)
            self._tabela_pastas.setItem(row, 0, QTableWidgetItem(pasta))
            estado = "Monitorizada" if self._shield.esta_activo() else "Inactiva"
            item_estado = QTableWidgetItem(estado)
            if self._shield.esta_activo():
                item_estado.setForeground(Qt.GlobalColor.green)
            else:
                item_estado.setForeground(Qt.GlobalColor.gray)
            self._tabela_pastas.setItem(row, 1, item_estado)

    def _actualizar_tabela_honeypots(self) -> None:
        self._tabela_honeypots.setRowCount(0)
        for caminho, pasta in self._shield.honeypot._honeypots_criados.items():
            if os.path.exists(caminho):
                row = self._tabela_honeypots.rowCount()
                self._tabela_honeypots.insertRow(row)
                self._tabela_honeypots.setItem(row, 0, QTableWidgetItem(Path(caminho).name))
                self._tabela_honeypots.setItem(row, 1, QTableWidgetItem(pasta))
                item = QTableWidgetItem("Activo")
                item.setForeground(Qt.GlobalColor.green)
                self._tabela_honeypots.setItem(row, 2, item)

    def _actualizar_tabela_backups(self) -> None:
        self._tabela_backups.setRowCount(0)
        todos_backups = []
        for filepath, backups in self._shield.backup._index.items():
            todos_backups.extend(backups)
        todos_backups.sort(key=lambda b: b.timestamp, reverse=True)

        for b in todos_backups[:15]:
            row = self._tabela_backups.rowCount()
            self._tabela_backups.insertRow(row)
            self._tabela_backups.setItem(row, 0, QTableWidgetItem(Path(b.filepath).name))

            versao = time.strftime("%d/%m/%Y %H:%M", time.localtime(b.timestamp))
            self._tabela_backups.setItem(row, 1, QTableWidgetItem(versao))

            if b.size > 1024 * 1024:
                txt = f"{b.size / (1024*1024):.1f} MB"
            elif b.size > 1024:
                txt = f"{b.size / 1024:.1f} KB"
            else:
                txt = f"{b.size} B"
            self._tabela_backups.setItem(row, 2, QTableWidgetItem(txt))

            data = time.strftime("%d/%m/%Y %H:%M", time.localtime(b.timestamp))
            self._tabela_backups.setItem(row, 3, QTableWidgetItem(data))

    def _toast(self, msg: str, tipo: str = "info") -> None:
        parent = self.parent()
        while parent:
            if hasattr(parent, "mostrar_toast"):
                parent.mostrar_toast(msg, tipo)
                return
            parent = parent.parent()
