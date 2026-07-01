"""Sistema de notificações toast para o BenguelaShield."""

from __future__ import annotations

from PyQt6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QPoint
from PyQt6.QtWidgets import QWidget, QHBoxLayout, QLabel, QGraphicsOpacityEffect


class ToastNotification(QWidget):
    """Notificação toast no canto inferior direito."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedWidth(360)
        self.setMinimumHeight(50)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._container = QWidget(self)
        self._container.setObjectName("toast")
        self._container.setStyleSheet("""
            #toast {
                background-color: #1a1a1a;
                border: 1px solid #333333;
                border-radius: 8px;
                padding: 12px 20px;
            }
        """)

        container_layout = QHBoxLayout(self._container)
        container_layout.setContentsMargins(16, 10, 16, 10)

        self._icon_label = QLabel()
        self._icon_label.setFixedWidth(20)
        self._icon_label.setStyleSheet("color: #00c853; font-size: 16px; font-weight: bold;")
        container_layout.addWidget(self._icon_label)

        self._text_label = QLabel()
        self._text_label.setStyleSheet("color: #e0e0e0; font-size: 13px;")
        self._text_label.setWordWrap(True)
        container_layout.addWidget(self._text_label, 1)

        layout.addWidget(self._container)

        self._opacity = QGraphicsOpacityEffect(self)
        self._opacity.setOpacity(0.0)
        self.setGraphicsEffect(self._opacity)

        self._fade_in = QPropertyAnimation(self._opacity, b"opacity")
        self._fade_in.setDuration(200)
        self._fade_in.setStartValue(0.0)
        self._fade_in.setEndValue(1.0)
        self._fade_in.setEasingCurve(QEasingCurve.Type.OutCubic)

        self._fade_out = QPropertyAnimation(self._opacity, b"opacity")
        self._fade_out.setDuration(300)
        self._fade_out.setStartValue(1.0)
        self._fade_out.setEndValue(0.0)
        self._fade_out.setEasingCurve(QEasingCurve.Type.InCubic)
        self._fade_out.finished.connect(self.hide)

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._start_fade_out)

        self.hide()

    def show_toast(self, message: str, tipo: str = "info", duration: int = 3000) -> None:
        """Mostra uma notificação toast.

        Args:
            message: Mensagem a mostrar.
            tipo: ``info``, ``ok``, ``warn`` ou ``error``.
            duration: Duração em milissegundos.
        """
        icones = {"info": "i", "ok": "+", "warn": "!", "error": "x"}
        cores = {"info": "#4fc3f7", "ok": "#00c853", "warn": "#ffc107", "error": "#ff1744"}

        self._icon_label.setText(icones.get(tipo, "i"))
        self._icon_label.setStyleSheet(f"color: {cores.get(tipo, '#4fc3f7')}; font-size: 16px; font-weight: bold;")
        self._text_label.setText(message)

        border_cor = cores.get(tipo, "#4fc3f7")
        self._container.setStyleSheet(f"""
            #toast {{
                background-color: #1a1a1a;
                border: 1px solid #333333;
                border-left: 4px solid {border_cor};
                border-radius: 8px;
                padding: 12px 20px;
            }}
        """)

        self.adjustSize()

        if self.parent():
            parent_rect = self.parent().geometry()
            x = parent_rect.right() - self.width() - 20
            y = parent_rect.bottom() - self.height() - 20
            self.move(x, y)

        self.show()
        self._fade_in.start()
        self._timer.start(duration)

    def _start_fade_out(self) -> None:
        self._fade_out.start()
