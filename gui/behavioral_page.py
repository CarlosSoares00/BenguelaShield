"""Ecrã de Análise Comportamental do BenguelaShield."""

from __future__ import annotations

import time

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame,
    QGroupBox,
)

from modules.antivirus.config import AntiVirusConfig
from modules.antivirus.database import DatabaseManager
from modules.behavioral.config import BehavioralConfig
from modules.behavioral.process_monitor import ProcessMonitor
from modules.behavioral.risk_score import RiskScorer
from modules.behavioral.heuristics import HeuristicAnalyzer


class BehavioralPage(QWidget):
    """Ecrã de análise comportamental."""

    def __init__(self, config: AntiVirusConfig, db: DatabaseManager, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._av_config = config
        self._db = db
        self._bh_config = BehavioralConfig()
        self._monitor = ProcessMonitor(self._bh_config)
        self._scorer = RiskScorer(self._bh_config)
        self._heuristics = HeuristicAnalyzer(self._bh_config, self._monitor)
        self._activo = False
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 24, 32, 24)
        layout.setSpacing(16)

        title = QLabel("Análise Comportamental")
        title.setObjectName("title")
        layout.addWidget(title)

        subtitle = QLabel("Monitorização de processos e detecção de anomalias")
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

        self._label_estado = QLabel("Inactivo")
        self._label_estado.setStyleSheet("color: #ff1744; font-size: 18px; font-weight: bold;")
        estado_layout.addWidget(self._label_estado)

        self._label_detalhe = QLabel("Clique em Activar para iniciar monitorização")
        self._label_detalhe.setStyleSheet("color: #888888; font-size: 13px;")
        estado_layout.addWidget(self._label_detalhe)
        estado_layout.addStretch()

        self._btn_activar = QPushButton("Activar")
        self._btn_activar.setObjectName("btn-primary")
        self._btn_activar.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_activar.clicked.connect(self._toggle)
        estado_layout.addWidget(self._btn_activar)

        layout.addWidget(estado_frame)

        # Stats
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(12)

        self._card_processos = self._criar_card("Processos", "0", "#4fc3f7")
        stats_layout.addWidget(self._card_processos)

        self._card_suspeitos = self._criar_card("Suspeitos", "0", "#ffc107")
        stats_layout.addWidget(self._card_suspeitos)

        self._card_alertas = self._criar_card("Alertas", "0", "#ff1744")
        stats_layout.addWidget(self._card_alertas)

        self._card_eventos = self._criar_card("Eventos", "0", "#9e9e9e")
        stats_layout.addWidget(self._card_eventos)

        layout.addLayout(stats_layout)

        # Processos suspeitos
        grupo_suspeitos = QGroupBox("Processos com Risco Elevado")
        grupo_suspeitos.setStyleSheet("""
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
        suspeitos_layout = QVBoxLayout(grupo_suspeitos)

        self._tabela_suspeitos = QTableWidget()
        self._tabela_suspeitos.setColumnCount(5)
        self._tabela_suspeitos.setHorizontalHeaderLabels(["Processo", "PID", "Score", "Nível", "Razões"])
        self._tabela_suspeitos.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._tabela_suspeitos.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._tabela_suspeitos.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._tabela_suspeitos.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._tabela_suspeitos.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self._tabela_suspeitos.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._tabela_suspeitos.verticalHeader().setVisible(False)
        self._tabela_suspeitos.setMaximumHeight(200)
        suspeitos_layout.addWidget(self._tabela_suspeitos)

        layout.addWidget(grupo_suspeitos)

        # Alertas heurísticos
        grupo_alertas = QGroupBox("Alertas Heurísticos Recentes")
        grupo_alertas.setStyleSheet(grupo_suspeitos.styleSheet())
        alertas_layout = QVBoxLayout(grupo_alertas)

        self._tabela_alertas = QTableWidget()
        self._tabela_alertas.setColumnCount(4)
        self._tabela_alertas.setHorizontalHeaderLabels(["Hora", "Tipo", "Severidade", "Descrição"])
        self._tabela_alertas.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._tabela_alertas.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._tabela_alertas.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._tabela_alertas.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._tabela_alertas.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._tabela_alertas.verticalHeader().setVisible(False)
        self._tabela_alertas.setMaximumHeight(200)
        alertas_layout.addWidget(self._tabela_alertas)

        layout.addWidget(grupo_alertas)

        layout.addStretch()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._actualizar)
        self._timer.start(3000)

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

    def _toggle(self) -> None:
        if self._activo:
            self._heuristics.parar()
            self._monitor.parar()
            self._activo = False
            self._btn_activar.setText("Activar")
            self._btn_activar.setObjectName("btn-primary")
        else:
            self._monitor.iniciar()
            self._heuristics.iniciar()
            self._activo = True
            self._btn_activar.setText("Desactivar")
            self._btn_activar.setObjectName("btn-danger")
        self._btn_activar.style().polish(self._btn_activar)

    def _actualizar(self) -> None:
        if not self._activo:
            self._label_estado.setText("Inactivo")
            self._label_estado.setStyleSheet("color: #ff1744; font-size: 18px; font-weight: bold;")
            self._label_detalhe.setText("Clique em Activar para iniciar monitorização")
            return

        self._label_estado.setText("A monitorizar")
        self._label_estado.setStyleSheet("color: #00c853; font-size: 18px; font-weight: bold;")

        stats = self._monitor.stats()
        self._card_processos._label_valor.setText(str(stats.get("processos_monitorizados", 0)))
        self._card_eventos._label_valor.setText(str(stats.get("eventos_totais", 0)))

        processos = self._monitor.todos_processos()
        for proc in processos:
            result = self._scorer.avaliar(proc)
            proc.risk_score = result.score
            proc.risk_reasons = result.reasons

        suspeitos = self._monitor.processos_suspeitos()
        self._card_suspeitos._label_valor.setText(str(len(suspeitos)))

        alertas = self._heuristics.alertas_recentes()
        self._card_alertas._label_valor.setText(str(len(alertas)))

        self._actualizar_tabela_suspeitos(suspeitos)
        self._actualizar_tabela_alertas(alertas)

    def _actualizar_tabela_suspeitos(self, suspeitos: list) -> None:
        self._tabela_suspeitos.setRowCount(0)
        for proc in suspeitos[:15]:
            row = self._tabela_suspeitos.rowCount()
            self._tabela_suspeitos.insertRow(row)
            self._tabela_suspeitos.setItem(row, 0, QTableWidgetItem(proc.name))
            self._tabela_suspeitos.setItem(row, 1, QTableWidgetItem(str(proc.pid)))
            self._tabela_suspeitos.setItem(row, 2, QTableWidgetItem(str(proc.risk_score)))

            nivel = "Crítico" if proc.risk_score >= 70 else "Alto" if proc.risk_score >= 40 else "Médio"
            item_nivel = QTableWidgetItem(nivel)
            if proc.risk_score >= 70:
                item_nivel.setForeground(Qt.GlobalColor.red)
            elif proc.risk_score >= 40:
                item_nivel.setForeground(Qt.GlobalColor.yellow)
            else:
                item_nivel.setForeground(Qt.GlobalColor.gray)
            self._tabela_suspeitos.setItem(row, 3, item_nivel)
            self._tabela_suspeitos.setItem(row, 4, QTableWidgetItem("; ".join(proc.risk_reasons[:3])))

    def _actualizar_tabela_alertas(self, alertas: list) -> None:
        self._tabela_alertas.setRowCount(0)
        for alerta in reversed(alertas[-15:]):
            row = self._tabela_alertas.rowCount()
            self._tabela_alertas.insertRow(row)
            hora = time.strftime("%H:%M:%S", time.localtime(alerta.timestamp))
            self._tabela_alertas.setItem(row, 0, QTableWidgetItem(hora))
            self._tabela_alertas.setItem(row, 1, QTableWidgetItem(alerta.alert_type))

            item_sev = QTableWidgetItem(alerta.severity)
            if alerta.severity == "critical":
                item_sev.setForeground(Qt.GlobalColor.red)
            elif alerta.severity == "high":
                item_sev.setForeground(Qt.GlobalColor.yellow)
            self._tabela_alertas.setItem(row, 2, item_sev)
            self._tabela_alertas.setItem(row, 3, QTableWidgetItem(alerta.description))

    def parar(self) -> None:
        if self._activo:
            self._heuristics.parar()
            self._monitor.parar()
            self._activo = False
