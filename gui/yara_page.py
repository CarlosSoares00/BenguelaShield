"""Ecrã de gestão de regras YARA do BenguelaShield."""
from __future__ import annotations
import os
from pathlib import Path
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame,
    QMessageBox, QFileDialog, QTextEdit,
)
from modules.antivirus.config import AntiVirusConfig
from modules.antivirus.database import DatabaseManager
from modules.yara_engine.yara_scanner import YaraScanner
from modules.yara_engine.rule_manager import RuleManager

class YaraPage(QWidget):
    def __init__(self, config: AntiVirusConfig, db: DatabaseManager, parent=None):
        super().__init__(parent)
        self._config = config
        self._db = db
        self._scanner = YaraScanner()
        self._rm = RuleManager()
        self._build_ui()
        self._actualizar_lista()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 24, 32, 24)
        layout.setSpacing(16)

        title = QLabel("Motor YARA")
        title.setObjectName("title")
        layout.addWidget(title)
        subtitle = QLabel("Deteccao avancada de malware baseada em padroes")
        subtitle.setObjectName("subtitle")
        layout.addWidget(subtitle)
        layout.addSpacing(8)

        # Stats
        stats_frame = QFrame()
        stats_frame.setStyleSheet("QFrame{background:#1a1a1a;border:1px solid #222;border-radius:12px;padding:16px;}")
        sl = QHBoxLayout(stats_frame)
        self._lbl_pronto = QLabel("Pronto")
        self._lbl_pronto.setStyleSheet("color:#00c853;font-size:16px;font-weight:bold;")
        sl.addWidget(self._lbl_pronto)
        self._lbl_regras = QLabel("0 regras")
        self._lbl_regras.setStyleSheet("color:#4fc3f7;font-size:16px;font-weight:bold;")
        sl.addWidget(self._lbl_regras)
        sl.addStretch()
        self._btnActualizar = QPushButton("Actualizar")
        self._btnActualizar.setObjectName("btn-primary")
        self._btnActualizar.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btnActualizar.clicked.connect(self._actualizar_lista)
        sl.addWidget(self._btnActualizar)
        layout.addWidget(stats_frame)

        # Tabela de regras
        self._tabela = QTableWidget()
        self._tabela.setColumnCount(5)
        self._tabela.setHorizontalHeaderLabels(["Nome", "Origem", "Regras", "Tamanho", "Estado"])
        self._tabela.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._tabela.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._tabela.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._tabela.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._tabela.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self._tabela.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._tabela.verticalHeader().setVisible(False)
        layout.addWidget(self._tabela)

        # Botoes
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(12)

        btn_activar = QPushButton("Activar/Desactivar")
        btn_activar.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_activar.clicked.connect(self._toggle_regra)
        btn_layout.addWidget(btn_activar)

        btn_importar = QPushButton("Importar Regra")
        btn_importar.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_importar.clicked.connect(self._importar_regra)
        btn_layout.addWidget(btn_importar)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        # Area de detalhes
        self._detalhes = QTextEdit()
        self._detalhes.setReadOnly(True)
        self._detalhes.setMaximumHeight(120)
        self._detalhes.setStyleSheet("QTextEdit{background:#111;border:1px solid #222;border-radius:8px;padding:8px;color:#e0e0e0;}")
        layout.addWidget(self._detalhes)

    def _actualizar_lista(self):
        rules = self._rm.list_rules()
        self._scanner = YaraScanner()
        self._lbl_regras.setText(f"{self._scanner.rules_count} regras activas")
        self._lbl_pronto.setText("Pronto" if self._scanner.is_ready else "Sem regras")

        self._tabela.setRowCount(0)
        for r in rules:
            row = self._tabela.rowCount()
            self._tabela.insertRow(row)
            self._tabela.setItem(row, 0, QTableWidgetItem(r["name"]))
            self._tabela.setItem(row, 1, QTableWidgetItem(r["origin"]))
            self._tabela.setItem(row, 2, QTableWidgetItem(str(r["rule_count"])))
            tamanho = f"{r['size']/1024:.1f} KB" if r["size"] > 1024 else f"{r['size']} B"
            self._tabela.setItem(row, 3, QTableWidgetItem(tamanho))
            estado = "Activo" if r["active"] else "Inactivo"
            item = QTableWidgetItem(estado)
            item.setForeground(Qt.GlobalColor.green if r["active"] else Qt.GlobalColor.gray)
            self._tabela.setItem(row, 4, item)

        self._detalhes.setText(f"Total: {len(rules)} regras ({sum(1 for r in rules if r['active'])} activas)")

    def _toggle_regra(self):
        row = self._tabela.currentRow()
        if row < 0:
            return
        nome = self._tabela.item(row, 0).text()
        activa = self._tabela.item(row, 4).text() == "Activo"

        if activa:
            self._rm.disable_rule(nome)
        else:
            self._rm.enable_rule(nome)
        self._actualizar_lista()

    def _importar_regra(self):
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Importar regra YARA", "", "YARA (*.yar *.yara);;Todos (*)"
        )
        if filepath:
            ok = self._rm.import_rule(filepath)
            if ok:
                QMessageBox.information(self, "Sucesso", "Regra importada com sucesso!")
            else:
                QMessageBox.warning(self, "Erro", "Regra invalida — nao foi possivel importar.")
            self._actualizar_lista()