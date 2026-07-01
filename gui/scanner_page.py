"""Ecrã de scanner do BenguelaShield — design profissional."""

from __future__ import annotations

import os
import subprocess
import time
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QPainter, QPen
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QProgressBar, QTableWidget, QTableWidgetItem, QHeaderView,
    QFileDialog, QFrame,
)

from modules.antivirus.config import AntiVirusConfig
from modules.antivirus.database import DatabaseManager
from modules.antivirus.quarantine import QuarantineManager, QuarantineError
from modules.quickscan import QuickScanner


class ScanThread(QThread):
    progresso = pyqtSignal(str, int)
    ameaca_detectada = pyqtSignal(str, str, str)
    concluido = pyqtSignal(int, int, float)

    def __init__(self, config, caminhos, parent=None):
        super().__init__(parent)
        self.config = config
        self.caminhos = caminhos
        self._parar = False

    def parar(self):
        self._parar = True

    def run(self):
        total_ameacas = 0
        total_ficheiros = 0
        start = time.monotonic()
        for caminho in self.caminhos:
            if self._parar or not os.path.exists(caminho):
                continue
            self.progresso.emit(f"A analisar: {caminho}", total_ficheiros)
            cmd = [str(self.config.clamscan_binary), "-r", "--no-summary", caminho]
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
                if proc.stdout:
                    for line in proc.stdout:
                        if self._parar:
                            proc.terminate()
                            break
                        line = line.strip()
                        if not line:
                            continue
                        if ": OK" in line:
                            total_ficheiros += 1
                            nome = Path(line.split(": OK")[0]).name
                            self.progresso.emit(nome, total_ficheiros)
                        elif ": FOUND" in line:
                            total_ficheiros += 1
                            parts = line.split(": FOUND")
                            filepath = parts[0]
                            threat = parts[1].strip() if len(parts) > 1 else "UNKNOWN"
                            total_ameacas += 1
                            self.ameaca_detectada.emit(filepath, threat, "quarantined")
                proc.wait(timeout=600)
            except Exception:
                pass
        elapsed = time.monotonic() - start
        self.concluido.emit(total_ficheiros, total_ameacas, elapsed)


class QuickScanThread(QThread):
    """Thread para scan rapido abrangente com 6 fases."""
    progresso = pyqtSignal(str)
    ameaca_detectada = pyqtSignal(str, str, str)
    concluido = pyqtSignal(int, int, float)

    def __init__(self, config, parent=None):
        super().__init__(parent)
        self.config = config
        self._parar = False

    def parar(self):
        self._parar = True

    def run(self):
        scanner = QuickScanner(self.config)
        scanner.set_callbacks(
            on_progress=lambda msg: self.progresso.emit(msg),
            on_threat=lambda fp, t, q: self.ameaca_detectada.emit(fp, t, q),
        )
        results = scanner.executar()
        total_ameacas = sum(len(r.ameacas) for r in results)
        total_itens = sum(r.itens_verificados for r in results)
        elapsed = sum(r.duracao for r in results)
        self.concluido.emit(total_itens, total_ameacas, elapsed)


class CircularProgressBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._progress = 0
        self._status = "Pronto"
        self._substatus = ""
        self._color = QColor("#00c853")
        self._anim_progress = 0
        self.setMinimumSize(220, 220)
        self.setMaximumSize(280, 280)

    def set_progress(self, value):
        self._progress = max(0, min(100, value))
        self.update()

    def set_status(self, text, color="#00c853"):
        self._status = text
        self._color = QColor(color)
        self.update()

    def set_substatus(self, text):
        self._substatus = text
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        cx, cy = w // 2, h // 2
        radius = min(w, h) // 2 - 20

        # Fundo
        painter.setPen(QPen(QColor("#1a1a1a"), 12))
        painter.drawArc(cx - radius, cy - radius, radius * 2, radius * 2, 90 * 16, -360 * 16)

        # Progresso
        pen = QPen(self._color, 12, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        span = int(-360 * 16 * self._progress / 100)
        painter.drawArc(cx - radius, cy - radius, radius * 2, radius * 2, 90 * 16, span)

        # Percentagem
        painter.setPen(QColor("#ffffff"))
        font = QFont("Segoe UI", 32, QFont.Weight.Bold)
        painter.setFont(font)
        painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, f"{self._progress}%")

        # Status
        painter.setPen(self._color)
        font2 = QFont("Segoe UI", 12, QFont.Weight.Bold)
        painter.setFont(font2)
        painter.drawText(self.rect().adjusted(0, 55, 0, 0), Qt.AlignmentFlag.AlignCenter, self._status)

        # Sub-status
        if self._substatus:
            painter.setPen(QColor("#888888"))
            font3 = QFont("Segoe UI", 10)
            painter.setFont(font3)
            painter.drawText(self.rect().adjusted(0, 75, 0, 0), Qt.AlignmentFlag.AlignCenter, self._substatus)


class StatCard(QFrame):
    def __init__(self, titulo, valor, cor, icon="", parent=None):
        super().__init__(parent)
        self.setStyleSheet("QFrame{background:#1a1a1a;border:1px solid #222;border-radius:10px;padding:14px;min-height:70px;}")
        layout = QVBoxLayout(self)
        layout.setSpacing(2)

        lbl_icon = QLabel(icon)
        lbl_icon.setStyleSheet(f"color:{cor};font-size:16px;")
        layout.addWidget(lbl_icon)

        lbl_titulo = QLabel(titulo)
        lbl_titulo.setStyleSheet("color:#888;font-size:11px;")
        layout.addWidget(lbl_titulo)

        self._valor = QLabel(valor)
        self._valor.setStyleSheet(f"color:{cor};font-size:18px;font-weight:bold;")
        layout.addWidget(self._valor)

    def set_valor(self, v):
        self._valor.setText(str(v))


class ScannerPage(QWidget):
    scan_concluido = pyqtSignal()

    def __init__(self, config, db, parent=None):
        super().__init__(parent)
        self.config = config
        self.db = db
        self._scan_thread = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 16, 24, 16)
        layout.setSpacing(10)

        title = QLabel("Scanner de Antivirus")
        title.setObjectName("title")
        layout.addWidget(title)

        center_layout = QVBoxLayout()
        center_layout.setSpacing(16)

        # Circulo central
        circle_layout = QHBoxLayout()
        circle_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        circle_frame = QFrame()
        circle_frame.setStyleSheet("QFrame{background:#111;border:1px solid #222;border-radius:16px;padding:16px;}")
        circle_inner = QVBoxLayout(circle_frame)
        circle_inner.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._circle = CircularProgressBar()
        circle_inner.addWidget(self._circle, 0, Qt.AlignmentFlag.AlignCenter)
        circle_layout.addWidget(circle_frame)
        center_layout.addLayout(circle_layout)

        # Cards em linha horizontal
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(12)

        self._cards = {}
        for nome, cor, icon in [("Ficheiros", "#4fc3f7", "0"), ("Ameacas", "#ff1744", "0"), ("Tempo", "#ffc107", "0s"), ("Accao", "#00c853", "...")]:
            card = StatCard(nome, "0", cor, icon)
            cards_layout.addWidget(card)
            self._cards[nome] = card

        center_layout.addLayout(cards_layout)
        layout.addLayout(center_layout)

        # Botoes
        botoes_layout = QHBoxLayout()
        botoes_layout.setSpacing(12)
        for nome, callback in [("Scan Rapido", self._scan_rapido), ("Scan Completo", self._scan_completo), ("Escolher Pasta", self._escolher_pasta)]:
            btn = QPushButton(nome)
            btn.setObjectName("btn-scan")
            btn.setMinimumHeight(42)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(callback)
            botoes_layout.addWidget(btn)

        btn_parar = QPushButton("Parar")
        btn_parar.setObjectName("btn-danger")
        btn_parar.setMinimumHeight(42)
        btn_parar.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_parar.clicked.connect(self._parar_scan)
        btn_parar.setEnabled(False)
        botoes_layout.addWidget(btn_parar)
        layout.addLayout(botoes_layout)
        self._btn_parar = btn_parar

        # Progress bar
        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 0)
        self._progress_bar.setTextVisible(False)
        self._progress_bar.setFixedHeight(4)
        layout.addWidget(self._progress_bar)

        self._label_detalhe = QLabel("Pronto para escanear")
        self._label_detalhe.setStyleSheet("color:#888;font-size:12px;")
        layout.addWidget(self._label_detalhe)

        # Tabela
        self._tabela = QTableWidget()
        self._tabela.setColumnCount(5)
        self._tabela.setHorizontalHeaderLabels(["Estado", "Ficheiro / Ameaca", "Caminho", "Hora", "Accao"])
        self._tabela.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._tabela.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._tabela.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._tabela.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._tabela.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self._tabela.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._tabela.setAlternatingRowColors(True)
        self._tabela.verticalHeader().setVisible(False)
        self._tabela.setMinimumHeight(160)
        layout.addWidget(self._tabela)

        self._label_resultado = QLabel("")
        self._label_resultado.setObjectName("subtitle")
        layout.addWidget(self._label_resultado)

    def _scan_rapido(self):
        self._iniciar_quickscan()

    def _scan_completo(self):
        self._iniciar_scan(["C:\\"], "Completo")

    def _escolher_pasta(self):
        caminho = QFileDialog.getExistingDirectory(self, "Escolher pasta")
        if caminho:
            self._iniciar_scan([caminho], "Personalizado")

    def _iniciar_quickscan(self):
        """Scan rápido abrangente com 6 fases."""
        self._tabela.setRowCount(0)
        self._circle.set_progress(0)
        self._circle.set_status("A escanear...", "#ffc107")
        self._circle.set_substatus("5 fases em paralelo")
        self._progress_bar.setRange(0, 0)
        self._label_detalhe.setText("Scan rapido abrangente em curso...")
        self._btn_parar.setEnabled(True)
        self._cards["Ficheiros"].set_valor("0")
        self._cards["Ameacas"].set_valor("0")
        self._cards["Tempo"].set_valor("0s")
        self._cards["Accao"].set_valor("...")

        self._quick_thread = QuickScanThread(self.config, self)
        self._quick_thread.progresso.connect(self._on_progresso)
        self._quick_thread.ameaca_detectada.connect(self._on_ameaca)
        self._quick_thread.concluido.connect(self._on_concluido_quick)
        self._quick_thread.start()

    def _on_concluido_quick(self, ficheiros, ameacas, elapsed):
        self._btn_parar.setEnabled(False)
        self._progress_bar.setRange(0, 1)
        self._progress_bar.setValue(1)

        if ameacas > 0:
            self._circle.set_progress(100)
            self._circle.set_status("AMEACA", "#ff1744")
            self._circle.set_substatus(f"{ameacas} ameaca(s) detetada(s)")
            self._label_detalhe.setText(f"Scan rapido concluido — {ameacas} ameaca(s) em {elapsed:.1f}s")
        else:
            self._circle.set_progress(100)
            self._circle.set_status("LIMPO", "#00c853")
            self._circle.set_substatus("Sistema seguro")
            self._label_detalhe.setText(f"Scan rapido concluido — {ficheiros} itens verificados em {elapsed:.1f}s")

        self._cards["Ficheiros"].set_valor(str(ficheiros))
        self._cards["Ameacas"].set_valor(str(ameacas))
        self._cards["Tempo"].set_valor(f"{elapsed:.1f}s")
        self._cards["Accao"].set_valor("Concluido")

        self._label_resultado.setText(f"Itens: {ficheiros} | Ameacas: {ameacas} | Duracao: {elapsed:.1f}s")
        self.db.log_scan("quick_scan", ficheiros, ameacas, elapsed)
        self.scan_concluido.emit()

    def _iniciar_scan(self, caminhos, tipo):
        self._tabela.setRowCount(0)
        self._circle.set_progress(0)
        self._circle.set_status("A escanear...", "#ffc107")
        self._circle.set_substatus(f"{len(caminhos)} pasta(s)")
        self._progress_bar.setRange(0, 0)
        self._label_detalhe.setText(f"Scan {tipo} em curso...")
        self._btn_parar.setEnabled(True)
        self._cards["Ficheiros"].set_valor("0")
        self._cards["Ameacas"].set_valor("0")
        self._cards["Tempo"].set_valor("0s")
        self._cards["Accao"].set_valor("...")

        self._scan_thread = ScanThread(self.config, caminhos, self)
        self._scan_thread.progresso.connect(self._on_progresso)
        self._scan_thread.ameaca_detectada.connect(self._on_ameaca)
        self._scan_thread.concluido.connect(self._on_concluido)
        self._scan_thread.start()

    def _parar_scan(self):
        if self._scan_thread:
            self._scan_thread.parar()
        if hasattr(self, '_quick_thread') and self._quick_thread:
            self._quick_thread.parar()

    def _on_progresso(self, texto, count=None):
        self._circle.set_status("A escanear...", "#ffc107")
        if count is not None:
            self._circle.set_substatus(f"{count} ficheiros verificados")
            self._label_detalhe.setText(f"Ficheiro {count}: {texto}")
            self._cards["Ficheiros"].set_valor(str(count))
        else:
            self._label_detalhe.setText(texto)
        self._cards["Tempo"].set_valor(f"{count} verificados")

        row = self._tabela.rowCount()
        self._tabela.insertRow(row)
        self._tabela.setItem(row, 0, QTableWidgetItem("OK"))
        self._tabela.item(row, 0).setForeground(QColor("#00c853"))
        self._tabela.setItem(row, 1, QTableWidgetItem(texto))
        self._tabela.setItem(row, 2, QTableWidgetItem(""))
        self._tabela.setItem(row, 3, QTableWidgetItem(datetime.now().strftime("%H:%M:%S")))
        self._tabela.setItem(row, 4, QTableWidgetItem("Limpo"))
        self._tabela.scrollToBottom()

    def _on_ameaca(self, filepath, threat, accao):
        row = self._tabela.rowCount()
        self._tabela.insertRow(row)
        self._tabela.setItem(row, 0, QTableWidgetItem("AMEACA"))
        self._tabela.item(row, 0).setForeground(QColor("#ff1744"))
        self._tabela.setItem(row, 1, QTableWidgetItem(threat))
        self._tabela.setItem(row, 2, QTableWidgetItem(filepath))
        self._tabela.setItem(row, 3, QTableWidgetItem(datetime.now().strftime("%H:%M:%S")))

        try:
            qm = QuarantineManager(self.config, self.db)
            qm.quarantine_file(filepath, threat)
            self._tabela.setItem(row, 4, QTableWidgetItem("Quarentenado"))
            self.db.log_threat(filepath, threat, "quarantined", "FOUND")
        except Exception as e:
            self._tabela.setItem(row, 4, QTableWidgetItem(f"Erro: {e}"))
            self.db.log_threat(filepath, threat, "error", "FOUND")

        self._tabela.scrollToBottom()
        ameacas = sum(1 for r in range(self._tabela.rowCount()) if self._tabela.item(r, 0) and self._tabela.item(r, 0).text() == "AMEACA")
        self._cards["Ameacas"].set_valor(str(ameacas))
        self._circle.set_status("AMEACA", "#ff1744")
        self._circle.set_substatus(f"{ameacas} ameaca(s) detetada(s)")

    def _on_concluido(self, ficheiros, ameacas, elapsed):
        self._btn_parar.setEnabled(False)
        self._progress_bar.setRange(0, 1)
        self._progress_bar.setValue(1)

        if ameacas > 0:
            self._circle.set_progress(100)
            self._circle.set_status("AMEACA", "#ff1744")
            self._circle.set_substatus(f"{ameacas} ameaca(s) bloqueada(s)")
            self._label_detalhe.setText(f"Scan concluido — {ameacas} ameaca(s) bloqueada(s) em {elapsed:.1f}s")
        else:
            self._circle.set_progress(100)
            self._circle.set_status("LIMPO", "#00c853")
            self._circle.set_substatus(f"{ficheiros} ficheiros verificados")
            self._label_detalhe.setText(f"Scan concluido — {ficheiros} ficheiros verificados em {elapsed:.1f}s")

        self._cards["Ficheiros"].set_valor(str(ficheiros))
        self._cards["Ameacas"].set_valor(str(ameacas))
        self._cards["Tempo"].set_valor(f"{elapsed:.1f}s")
        self._cards["Accao"].set_valor("Concluido")

        self._label_resultado.setText(f"Ficheiros: {ficheiros} | Ameacas: {ameacas} | Duracao: {elapsed:.1f}s")
        self.db.log_scan("gui_scan", ficheiros, ameacas, elapsed)
        self.scan_concluido.emit()
