"""Ecrã de relatórios do BenguelaShield."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QDateEdit,
    QComboBox, QFileDialog, QFrame,
)

from PyQt6.QtCore import QDate

from modules.antivirus.database import DatabaseManager


class ReportsPage(QWidget):
    """Ecrã de relatórios e eventos."""

    def __init__(self, db: DatabaseManager, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.db = db
        self._build_ui()
        self._carregar_eventos()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 24, 32, 24)
        layout.setSpacing(16)

        title = QLabel("Relatórios")
        title.setObjectName("title")
        layout.addWidget(title)

        subtitle = QLabel("Histórico de eventos e ameaças")
        subtitle.setObjectName("subtitle")
        layout.addWidget(subtitle)

        layout.addSpacing(8)

        filtros_layout = QHBoxLayout()
        filtros_layout.setSpacing(12)

        self._combo_tipo = QComboBox()
        self._combo_tipo.addItems(["Todos", "Ameaças", "Scans", "Quarentena"])
        self._combo_tipo.currentTextChanged.connect(self._filtrar)
        filtros_layout.addWidget(QLabel("Tipo:"))
        filtros_layout.addWidget(self._combo_tipo)

        self._combo_gravidade = QComboBox()
        self._combo_gravidade.addItems(["Todas", "Crítico", "Alto", "Médio", "Baixo"])
        filtros_layout.addWidget(QLabel("Gravidade:"))
        filtros_layout.addWidget(self._combo_gravidade)

        filtros_layout.addStretch()

        btn_exportar = QPushButton("Exportar CSV")
        btn_exportar.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_exportar.clicked.connect(self._exportar_csv)
        filtros_layout.addWidget(btn_exportar)

        btn_actualizar = QPushButton("Actualizar")
        btn_actualizar.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_actualizar.clicked.connect(self._carregar_eventos)
        filtros_layout.addWidget(btn_actualizar)

        layout.addLayout(filtros_layout)

        self._tabela = QTableWidget()
        self._tabela.setColumnCount(5)
        self._tabela.setHorizontalHeaderLabels(["Data", "Tipo", "Ficheiro", "Detalhe", "Acção"])
        self._tabela.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._tabela.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._tabela.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._tabela.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._tabela.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self._tabela.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._tabela.setAlternatingRowColors(True)
        self._tabela.verticalHeader().setVisible(False)
        layout.addWidget(self._tabela)

        self._label_resumo = QLabel("")
        self._label_resumo.setObjectName("subtitle")
        layout.addWidget(self._label_resumo)

        self._eventos: list[dict] = []

    def _carregar_eventos(self) -> None:
        self._eventos = []

        for t in self.db.get_threats(limit=200):
            self._eventos.append({
                "data": t["timestamp"][:19].replace("T", " "),
                "tipo": "Ameaça",
                "ficheiro": Path(t["filepath"]).name,
                "detalhe": t["threat_name"] or "-",
                "acao": t["action"] or "-",
                "gravidade": "Crítico",
            })

        for s in self.db.get_scans(limit=100):
            self._eventos.append({
                "data": s["timestamp"][:19].replace("T", " "),
                "tipo": "Scan",
                "ficheiro": "-",
                "detalhe": f"{s['files_scanned']} ficheiros, {s['threats_found']} ameaças",
                "acao": s["scan_type"],
                "gravidade": "Médio" if s["threats_found"] > 0 else "Baixo",
            })

        self._eventos.sort(key=lambda e: e["data"], reverse=True)
        self._mostrar_eventos(self._eventos)

    def _mostrar_eventos(self, eventos: list[dict]) -> None:
        self._tabela.setRowCount(0)
        for e in eventos:
            row = self._tabela.rowCount()
            self._tabela.insertRow(row)
            self._tabela.setItem(row, 0, QTableWidgetItem(e["data"]))
            self._tabela.setItem(row, 1, QTableWidgetItem(e["tipo"]))
            self._tabela.setItem(row, 2, QTableWidgetItem(e["ficheiro"]))
            self._tabela.setItem(row, 3, QTableWidgetItem(e["detalhe"]))
            self._tabela.setItem(row, 4, QTableWidgetItem(e["acao"]))

        self._label_resumo.setText(f"Total: {len(eventos)} evento(s)")

    def _filtrar(self) -> None:
        tipo = self._combo_tipo.currentText()
        filtrados = self._eventos
        if tipo != "Todos":
            filtrados = [e for e in filtrados if e["tipo"] == tipo]
        self._mostrar_eventos(filtrados)

    def _exportar_csv(self) -> None:
        caminho, _ = QFileDialog.getSaveFileName(
            self, "Exportar Relatório", "benguelashield_relatorio.csv",
            "CSV (*.csv)",
        )
        if caminho:
            with open(caminho, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["data", "tipo", "ficheiro", "detalhe", "acao"])
                writer.writeheader()
                writer.writerows(self._eventos)
            QMessageBox.information(self, "Exportado", f"Relatório exportado para:\n{caminho}")


from PyQt6.QtWidgets import QMessageBox
