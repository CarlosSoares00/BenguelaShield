"""Ecrã de definições do BenguelaShield."""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QCheckBox, QSpinBox, QLineEdit, QGroupBox, QFormLayout,
    QComboBox, QFrame, QMessageBox,
)

from modules.antivirus.config import AntiVirusConfig


class SettingsPage(QWidget):
    """Ecrã de definições do BenguelaShield."""

    def __init__(self, config: AntiVirusConfig, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.config = config
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 24, 32, 24)
        layout.setSpacing(16)

        title = QLabel("Definições")
        title.setObjectName("title")
        layout.addWidget(title)

        subtitle = QLabel("Configuração do BenguelaShield")
        subtitle.setObjectName("subtitle")
        layout.addWidget(subtitle)

        layout.addSpacing(8)

        grupo_scanner = QGroupBox("Scanner")
        form_scanner = QFormLayout(grupo_scanner)

        self._spin_timeout = QSpinBox()
        self._spin_timeout.setRange(30, 3600)
        self._spin_timeout.setValue(self.config.scan_timeout)
        self._spin_timeout.setSuffix(" segundos")
        form_scanner.addRow("Timeout por ficheiro:", self._spin_timeout)

        self._check_force_disk = QCheckBox("Forçar escrita em disco para scan")
        self._check_force_disk.setChecked(True)
        form_scanner.addRow(self._check_force_disk)

        layout.addWidget(grupo_scanner)

        grupo_quarentena = QGroupBox("Quarentena")
        form_quarentena = QFormLayout(grupo_quarentena)

        self._check_encriptar = QCheckBox("Encriptar ficheiros em quarentena (AES-256)")
        self._check_encriptar.setChecked(True)
        form_quarentena.addRow(self._check_encriptar)

        self._spin_retention = QSpinBox()
        self._spin_retention.setRange(1, 365)
        self._spin_retention.setValue(90)
        self._spin_retention.setSuffix(" dias")
        form_quarentena.addRow("Eliminar após:", self._spin_retention)

        layout.addWidget(grupo_quarentena)

        grupo_actualizacao = QGroupBox("Actualização de Assinaturas")
        form_actualizacao = QFormLayout(grupo_actualizacao)

        self._combo_freq = QComboBox()
        self._combo_freq.addItems(["Manual", "A cada 6 horas", "Diariamente", "Semanalmente"])
        self._combo_freq.setCurrentIndex(2)
        form_actualizacao.addRow("Frequência:", self._combo_freq)

        self._check_auto_update = QCheckBox("Actualizar automaticamente ao iniciar")
        self._check_auto_update.setChecked(True)
        form_actualizacao.addRow(self._check_auto_update)

        layout.addWidget(grupo_actualizacao)

        grupo_rede = QGroupBox("Rede")
        form_rede = QFormLayout(grupo_rede)

        self._edit_proxy = QLineEdit()
        self._edit_proxy.setPlaceholderText("Ex: http://proxy:8080")
        form_rede.addRow("Proxy:", self._edit_proxy)

        self._spin_porta = QSpinBox()
        self._spin_porta.setRange(1, 65535)
        self._spin_porta.setValue(self.config.clamd_port)
        form_rede.addRow("Porta clamd:", self._spin_porta)

        layout.addWidget(grupo_rede)

        grupo_aparencia = QGroupBox("Aparência")
        form_aparencia = QFormLayout(grupo_aparencia)

        self._combo_tema = QComboBox()
        self._combo_tema.addItems(["Escuro", "Claro"])
        form_aparencia.addRow("Tema:", self._combo_tema)

        self._combo_idioma = QComboBox()
        self._combo_idioma.addItems(["Português", "English"])
        form_aparencia.addRow("Idioma:", self._combo_idioma)

        layout.addWidget(grupo_aparencia)

        botoes_layout = QHBoxLayout()
        botoes_layout.addStretch()

        btn_guardar = QPushButton("Guardar Definições")
        btn_guardar.setObjectName("btn-primary")
        btn_guardar.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_guardar.clicked.connect(self._guardar)
        botoes_layout.addWidget(btn_guardar)

        btn_repor = QPushButton("Repor Definições")
        btn_repor.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_repor.clicked.connect(self._repor)
        botoes_layout.addWidget(btn_repor)

        layout.addLayout(botoes_layout)

        layout.addStretch()

    def _guardar(self) -> None:
        self.config.scan_timeout = self._spin_timeout.value()
        self.config.clamd_port = self._spin_porta.value()
        if self.config.save_to_file():
            QMessageBox.information(self, "Guardado", "Definicoes guardadas com sucesso.")
        else:
            QMessageBox.warning(self, "Erro", "Falha ao guardar definicoes em disco.")

    def _repor(self) -> None:
        self._spin_timeout.setValue(300)
        self._check_force_disk.setChecked(True)
        self._check_encriptar.setChecked(True)
        self._spin_retention.setValue(90)
        self._combo_freq.setCurrentIndex(2)
        self._check_auto_update.setChecked(True)
        self._edit_proxy.clear()
        self._spin_porta.setValue(3310)
        self._combo_tema.setCurrentIndex(0)
        self._combo_idioma.setCurrentIndex(0)
        QMessageBox.information(self, "Reposto", "Definições repostas para os valores por omissão.")
