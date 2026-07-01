"""Ecrã de quarentena do BenguelaShield."""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QLineEdit,
    QFrame, QMessageBox,
)

from modules.antivirus.config import AntiVirusConfig
from modules.antivirus.database import DatabaseManager
from modules.antivirus.quarantine import QuarantineManager, QuarantineError


class QuarantinePage(QWidget):
    """Ecrã de gestão de quarentena."""

    def __init__(self, config: AntiVirusConfig, db: DatabaseManager, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.config = config
        self.db = db
        self._build_ui()
        self._actualizar_lista()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 24, 32, 24)
        layout.setSpacing(16)

        title = QLabel("Quarentena")
        title.setObjectName("title")
        layout.addWidget(title)

        subtitle = QLabel("Ficheiros bloqueados e isolados do sistema")
        subtitle.setObjectName("subtitle")
        layout.addWidget(subtitle)

        layout.addSpacing(8)

        search_layout = QHBoxLayout()
        self._pesquisa = QLineEdit()
        self._pesquisa.setPlaceholderText("Pesquisar por nome ou ameaça...")
        self._pesquisa.textChanged.connect(self._filtrar)
        search_layout.addWidget(self._pesquisa)
        layout.addLayout(search_layout)

        self._tabela = QTableWidget()
        self._tabela.setColumnCount(5)
        self._tabela.setHorizontalHeaderLabels(["Ficheiro", "Ameaça", "Caminho Original", "Data", "Tamanho"])
        self._tabela.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._tabela.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._tabela.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._tabela.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._tabela.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self._tabela.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._tabela.setAlternatingRowColors(True)
        self._tabela.verticalHeader().setVisible(False)
        layout.addWidget(self._tabela)

        botoes_layout = QHBoxLayout()
        botoes_layout.setSpacing(12)

        btn_restaurar = QPushButton("Restaurar")
        btn_restaurar.setObjectName("btn-primary")
        btn_restaurar.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_restaurar.clicked.connect(self._restaurar)
        botoes_layout.addWidget(btn_restaurar)

        btn_eliminar = QPushButton("Eliminar")
        btn_eliminar.setObjectName("btn-danger")
        btn_eliminar.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_eliminar.clicked.connect(self._eliminar)
        botoes_layout.addWidget(btn_eliminar)

        btn_actualizar = QPushButton("Actualizar")
        btn_actualizar.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_actualizar.clicked.connect(self._actualizar_lista)
        botoes_layout.addWidget(btn_actualizar)

        botoes_layout.addStretch()

        self._label_contagem = QLabel("0 ficheiro(s) em quarentena")
        self._label_contagem.setObjectName("subtitle")
        botoes_layout.addWidget(self._label_contagem)

        layout.addLayout(botoes_layout)

        self._entradas: list[dict] = []

    def _actualizar_lista(self) -> None:
        qm = QuarantineManager(self.config, self.db)
        self._entradas = [
            {
                "quarantine_id": e["quarantine_id"],
                "filename": e["filename"],
                "threat_name": e["threat_name"],
                "original_path": e["original_path"],
                "date": e["date_quarantined"][:16].replace("T", " "),
                "file_size": e["file_size"],
            }
            for e in qm.db.get_quarantine_entries()
        ]
        self._mostrar_entradas(self._entradas)

    def _mostrar_entradas(self, entradas: list[dict]) -> None:
        self._tabela.setRowCount(0)
        for e in entradas:
            row = self._tabela.rowCount()
            self._tabela.insertRow(row)
            self._tabela.setItem(row, 0, QTableWidgetItem(e["filename"]))
            self._tabela.setItem(row, 1, QTableWidgetItem(e["threat_name"]))
            self._tabela.setItem(row, 2, QTableWidgetItem(e["original_path"]))
            self._tabela.setItem(row, 3, QTableWidgetItem(e["date"]))

            tamanho = e["file_size"]
            if tamanho > 1024 * 1024:
                txt = f"{tamanho / (1024*1024):.1f} MB"
            elif tamanho > 1024:
                txt = f"{tamanho / 1024:.1f} KB"
            else:
                txt = f"{tamanho} B"
            self._tabela.setItem(row, 4, QTableWidgetItem(txt))

        self._label_contagem.setText(f"{len(entradas)} ficheiro(s) em quarentena")

    def _filtrar(self, texto: str) -> None:
        texto = texto.lower()
        filtradas = [
            e for e in self._entradas
            if texto in e["filename"].lower() or texto in e["threat_name"].lower()
        ]
        self._mostrar_entradas(filtradas)

    def _restaurar(self) -> None:
        row = self._tabela.currentRow()
        if row < 0:
            return
        qid = self._entradas[row]["quarantine_id"]
        try:
            qm = QuarantineManager(self.config, self.db)
            caminho = qm.restore_file(qid)
            QMessageBox.information(self, "Restaurado", f"Ficheiro restaurado para:\n{caminho}")
            self._actualizar_lista()
        except QuarantineError as e:
            QMessageBox.warning(self, "Erro", str(e))

    def _eliminar(self) -> None:
        row = self._tabela.currentRow()
        if row < 0:
            return
        qid = self._entradas[row]["quarantine_id"]
        nome = self._entradas[row]["filename"]
        resp = QMessageBox.question(
            self, "Confirmar",
            f"Eliminar permanentemente '{nome}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if resp == QMessageBox.StandardButton.Yes:
            try:
                qm = QuarantineManager(self.config, self.db)
                qm.delete_file(qid)
                self._actualizar_lista()
            except QuarantineError as e:
                QMessageBox.warning(self, "Erro", str(e))
