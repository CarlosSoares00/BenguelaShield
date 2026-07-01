"""Ecrã de Ferramentas do BenguelaShield."""
from __future__ import annotations

import os
import sys
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame,
    QFileDialog, QMessageBox, QTextEdit, QGroupBox, QFormLayout,
    QComboBox, QLineEdit,
)

from modules.tools.usb_vaccinator import USBVaccinator
from modules.tools.file_restorer import FileRestorer
from modules.tools.registry_repair import RegistryRepairer
from modules.tools.win_force import WinForce
from modules.tools.manual_scanner import ManualScanner
from modules.tools.admin_protection import AdminProtection
from modules.tools.exception_list import ExceptionList
from modules.tools.process_manager import BenguelaProcessManager


class ToolsPage(QWidget):
    """Ecrã de Ferramentas — limpeza, reparação, protecção USB."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._vaccinator = USBVaccinator()
        self._restorer = FileRestorer()
        self._registry = RegistryRepairer()
        self._win_force = WinForce()
        self._scanner = ManualScanner()
        self._admin = AdminProtection()
        self._exceptions = ExceptionList()
        self._proc_manager = BenguelaProcessManager()
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        title = QLabel("Ferramentas")
        title.setObjectName("title")
        layout.addWidget(title)

        subtitle = QLabel("Protecção USB, reparação de sistema e análise manual")
        subtitle.setObjectName("subtitle")
        layout.addWidget(subtitle)

        tabs_layout = QHBoxLayout()
        tabs_layout.setSpacing(8)

        self._tab_buttons = []
        tab_names = ["USB", "Reparar", "Win-Force", "Análise", "Processos", "Definições"]
        for i, name in enumerate(tab_names):
            btn = QPushButton(name)
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda checked, idx=i: self._mostrar_tab(idx))
            tabs_layout.addWidget(btn)
            self._tab_buttons.append(btn)

        tabs_layout.addStretch()
        layout.addLayout(tabs_layout)

        self._stack = QFrame()
        self._stack_layout = QVBoxLayout(self._stack)
        self._stack_layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._stack, 1)

        self._tabs = [
            self._criar_tab_usb(),
            self._criar_tab_reparar(),
            self._criar_tab_winforce(),
            self._criar_tab_analise(),
            self._criar_tab_processos(),
            self._criar_tab_definicoes(),
        ]

        for tab in self._tabs:
            self._stack_layout.addWidget(tab)
            tab.hide()

        self._mostrar_tab(0)

    def _mostrar_tab(self, idx: int) -> None:
        for i, btn in enumerate(self._tab_buttons):
            btn.setChecked(i == idx)
        for i, tab in enumerate(self._tabs):
            tab.setVisible(i == idx)

    def _criar_tab_usb(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 8, 0, 0)

        grupo = QGroupBox("Protecção USB Avançada")
        glayout = QFormLayout(grupo)

        self._usb_combo = QComboBox()
        self._usb_combo.addItem("Nenhum USB detectado")
        glayout.addRow("Drive:", self._usb_combo)

        btns = QHBoxLayout()
        btn_vacinar = QPushButton("Vacinar USB")
        btn_vacinar.setObjectName("btn-primary")
        btn_vacinar.clicked.connect(self._vacinar_usb)
        btns.addWidget(btn_vacinar)

        btn_limpar = QPushButton("Limpar USB")
        btn_limpar.clicked.connect(self._limpar_usb)
        btns.addWidget(btn_limpar)

        btn_restaurar = QPushButton("Restaurar Ficheiros")
        btn_restaurar.clicked.connect(self._restaurar_usb)
        btns.addWidget(btn_restaurar)

        btn_actualizar = QPushButton("Actualizar")
        btn_actualizar.clicked.connect(self._actualizar_drives)
        btns.addWidget(btn_actualizar)

        glayout.addRow(btns)
        layout.addWidget(grupo)

        self._usb_resultado = QTextEdit()
        self._usb_resultado.setReadOnly(True)
        self._usb_resultado.setMaximumHeight(200)
        layout.addWidget(self._usb_resultado)

        layout.addStretch()
        self._actualizar_drives()
        return w

    def _criar_tab_reparar(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 8, 0, 0)

        grupo = QGroupBox("Reparação de Registry")
        glayout = QVBoxLayout(grupo)

        btn_scan = QPushButton("Escanear Registry")
        btn_scan.clicked.connect(self._scan_registry)
        glayout.addWidget(btn_scan)

        self._registry_resultado = QTextEdit()
        self._registry_resultado.setReadOnly(True)
        self._registry_resultado.setMaximumHeight(150)
        glayout.addWidget(self._registry_resultado)

        btn_reparar = QPushButton("Reparar Tudo")
        btn_reparar.setObjectName("btn-primary")
        btn_reparar.clicked.connect(self._reparar_registry)
        glayout.addWidget(btn_reparar)

        layout.addWidget(grupo)
        layout.addStretch()
        return w

    def _criar_tab_winforce(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 8, 0, 0)

        grupo = QGroupBox("Win-Force — Desbloquear Ferramentas")
        glayout = QVBoxLayout(grupo)

        self._winforce_tabela = QTableWidget()
        self._winforce_tabela.setColumnCount(3)
        self._winforce_tabela.setHorizontalHeaderLabels(["Ferramenta", "Estado", "Acção"])
        self._winforce_tabela.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._winforce_tabela.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._winforce_tabela.verticalHeader().setVisible(False)
        glayout.addWidget(self._winforce_tabela)

        btns = QHBoxLayout()
        btn_desbloquear = QPushButton("Desbloquear Tudo")
        btn_desbloquear.setObjectName("btn-primary")
        btn_desbloquear.clicked.connect(self._desbloquear_tudo)
        btns.addWidget(btn_desbloquear)

        btn_actualizar = QPushButton("Actualizar")
        btn_actualizar.clicked.connect(self._actualizar_winforce)
        btns.addWidget(btn_actualizar)

        glayout.addLayout(btns)
        layout.addWidget(grupo)
        layout.addStretch()

        self._actualizar_winforce()
        return w

    def _criar_tab_analise(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 8, 0, 0)

        grupo = QGroupBox("Análise Manual de Ficheiro")
        glayout = QVBoxLayout(grupo)

        btn_procurar = QPushButton("Procurar Ficheiro...")
        btn_procurar.clicked.connect(self._procurar_ficheiro)
        glayout.addWidget(btn_procurar)

        self._analise_resultado = QTextEdit()
        self._analise_resultado.setReadOnly(True)
        self._analise_resultado.setMaximumHeight(300)
        self._analise_resultado.setStyleSheet("QTextEdit { font-family: Consolas, monospace; font-size: 12px; }")
        glayout.addWidget(self._analise_resultado)

        layout.addWidget(grupo)
        layout.addStretch()
        return w

    def _criar_tab_processos(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 8, 0, 0)

        grupo = QGroupBox("Gestão de Processos")
        glayout = QVBoxLayout(grupo)

        btn_actualizar = QPushButton("Actualizar")
        btn_actualizar.clicked.connect(self._actualizar_processos)
        glayout.addWidget(btn_actualizar)

        self._proc_tabela = QTableWidget()
        self._proc_tabela.setColumnCount(5)
        self._proc_tabela.setHorizontalHeaderLabels(["Processo", "PID", "CPU", "RAM", "Veredicto"])
        self._proc_tabela.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._proc_tabela.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._proc_tabela.verticalHeader().setVisible(False)
        glayout.addWidget(self._proc_tabela)

        layout.addWidget(grupo)
        layout.addStretch()
        self._actualizar_processos()
        return w

    def _criar_tab_definicoes(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 8, 0, 0)

        grupo = QGroupBox("Password de Administrador")
        glayout = QFormLayout(grupo)

        self._admin_entry = QLineEdit()
        self._admin_entry.setEchoMode(QLineEdit.EchoMode.Password)
        self._admin_entry.setPlaceholderText("Definir password...")
        glayout.addRow("Password:", self._admin_entry)

        btns = QHBoxLayout()
        btn_definir = QPushButton("Definir")
        btn_definir.clicked.connect(self._definir_password)
        btns.addWidget(btn_definir)

        btn_remover = QPushButton("Remover")
        btn_remover.clicked.connect(self._remover_password)
        btns.addWidget(btn_remover)

        glayout.addRow(btns)
        layout.addWidget(grupo)

        grupo_exc = QGroupBox("Lista de Exclusões")
        elayout = QVBoxLayout(grupo_exc)

        self._exc_tabela = QTableWidget()
        self._exc_tabela.setColumnCount(2)
        self._exc_tabela.setHorizontalHeaderLabels(["Tipo", "Valor"])
        self._exc_tabela.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._exc_tabela.verticalHeader().setVisible(False)
        elayout.addWidget(self._exc_tabela)

        btns2 = QHBoxLayout()
        btn_adicionar = QPushButton("Adicionar...")
        btn_adicionar.clicked.connect(self._adicionar_exclusao)
        btns2.addWidget(btn_adicionar)

        btn_remover_exc = QPushButton("Remover")
        btn_remover_exc.clicked.connect(self._remover_exclusao)
        btns2.addWidget(btn_remover_exc)

        elayout.addLayout(btns2)
        layout.addWidget(grupo_exc)

        layout.addStretch()
        self._actualizar_exclusoes()
        return w

    def _actualizar_drives(self) -> None:
        self._usb_combo.clear()
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            try:
                drive_type = ctypes.windll.kernel32.GetDriveTypeW(f"{letter}:\\")
                if drive_type == 2:
                    self._usb_combo.addItem(f"{letter}:\\ USB")
            except Exception:
                pass
        if self._usb_combo.count() == 0:
            self._usb_combo.addItem("Nenhum USB detectado")

    def _vacinar_usb(self) -> None:
        drive = self._usb_combo.currentText()[:2]
        if not drive or drive == "Nen":
            return
        result = self._vaccinator.vaccinate(drive)
        self._usb_resultado.setText(str(result))

    def _limpar_usb(self) -> None:
        drive = self._usb_combo.currentText()[:2]
        if not drive or drive == "Nen":
            return
        result = self._vaccinator.clean_usb(drive)
        self._usb_resultado.setText(str(result))

    def _restaurar_usb(self) -> None:
        drive = self._usb_combo.currentText()[:2]
        if not drive or drive == "Nen":
            return
        result = self._restorer.restore_hidden(f"{drive}:\\")
        self._usb_resultado.setText(str(result))

    def _scan_registry(self) -> None:
        result = self._registry.scan()
        lines = [f"Problemas encontrados: {result['issues_found']}"]
        for issue in result["issues"]:
            lines.append(f"  ⚠ {issue['description']}")
        self._registry_resultado.setText("\n".join(lines))

    def _reparar_registry(self) -> None:
        result = self._registry.scan_and_repair_all(auto_repair=True)
        lines = [f"Reparados: {len(result.get('repaired', []))}"]
        for r in result.get("repaired", []):
            lines.append(f"  ✅ {r}")
        self._registry_resultado.setText("\n".join(lines))

    def _actualizar_winforce(self) -> None:
        blocked = self._win_force.check_all_blocked()
        self._winforce_tabela.setRowCount(0)
        for key, info in blocked.items():
            row = self._winforce_tabela.rowCount()
            self._winforce_tabela.insertRow(row)
            self._winforce_tabela.setItem(row, 0, QTableWidgetItem(info["description"]))
            estado = "❌ Bloqueado" if info["blocked"] else "✅ Livre"
            self._winforce_tabela.setItem(row, 1, QTableWidgetItem(estado))
            btn = QPushButton("Abrir")
            btn.clicked.connect(lambda checked, k=key: self._abrir_ferramenta(k))
            self._winforce_tabela.setCellWidget(row, 2, btn)

    def _abrir_ferramenta(self, key: str) -> None:
        result = self._win_force.open_tool(key)
        status = "Aberta" if result["opened"] else "Erro"
        QMessageBox.information(self, result["tool"], status)

    def _desbloquear_tudo(self) -> None:
        results = self._win_force.open_all_blocked()
        QMessageBox.information(self, "Win-Force", f"{len(results)} ferramenta(s) desbloqueada(s)")

    def _procurar_ficheiro(self) -> None:
        filepath, _ = QFileDialog.getOpenFileName(self, "Escolher ficheiro para análise")
        if filepath:
            result = self._scanner.analyze_file(filepath)
            self._analise_resultado.setText(result["detailed_report"])

    def _actualizar_processos(self) -> None:
        processes = self._proc_manager.list_processes()
        self._proc_tabela.setRowCount(0)
        for p in processes[:50]:
            row = self._proc_tabela.rowCount()
            self._proc_tabela.insertRow(row)
            self._proc_tabela.setItem(row, 0, QTableWidgetItem(p["name"]))
            self._proc_tabela.setItem(row, 1, QTableWidgetItem(str(p["pid"])))
            self._proc_tabela.setItem(row, 2, QTableWidgetItem(f"{p['cpu_percent']}%"))
            self._proc_tabela.setItem(row, 3, QTableWidgetItem(f"{p['memory_mb']:.0f}MB"))
            item = QTableWidgetItem(p["security_verdict"])
            if p["security_verdict"] == "SUSPEITO":
                item.setForeground(Qt.GlobalColor.yellow)
            elif p["security_verdict"] == "SEGURO":
                item.setForeground(Qt.GlobalColor.green)
            self._proc_tabela.setItem(row, 4, item)

    def _definir_password(self) -> None:
        pwd = self._admin_entry.text()
        if len(pwd) < 4:
            QMessageBox.warning(self, "Erro", "Password deve ter pelo menos 4 caracteres")
            return
        self._admin.set_password(pwd)
        QMessageBox.information(self, "OK", "Password definida com sucesso")

    def _remover_password(self) -> None:
        pwd = self._admin_entry.text()
        if self._admin.remove_password(pwd):
            QMessageBox.information(self, "OK", "Password removida")
        else:
            QMessageBox.warning(self, "Erro", "Password incorrecta")

    def _actualizar_exclusoes(self) -> None:
        data = self._exceptions.list_all()
        self._exc_tabela.setRowCount(0)
        for item_type, items in data.items():
            for item in items:
                row = self._exc_tabela.rowCount()
                self._exc_tabela.insertRow(row)
                self._exc_tabela.setItem(row, 0, QTableWidgetItem(item_type))
                self._exc_tabela.setItem(row, 1, QTableWidgetItem(item))

    def _adicionar_exclusao(self) -> None:
        filepath, _ = QFileDialog.getExistingDirectory(self, "Escolher pasta para excluir")
        if filepath:
            self._exceptions.add_folder(filepath)
            self._actualizar_exclusoes()

    def _remover_exclusao(self) -> None:
        row = self._exc_tabela.currentRow()
        if row >= 0:
            tipo = self._exc_tabela.item(row, 0).text()
            valor = self._exc_tabela.item(row, 1).text()
            self._exceptions.remove(valor, tipo)
            self._actualizar_exclusoes()
