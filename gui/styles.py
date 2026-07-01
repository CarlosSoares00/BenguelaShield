"""Estilos CSS do PyQt6 para o BenguelaShield."""

DARK_STYLE = """
QMainWindow, QWidget {
    background-color: #0d0d0d;
    color: #e0e0e0;
    font-family: "Segoe UI", sans-serif;
    font-size: 13px;
}

#sidebar {
    background-color: #111111;
    border-right: 1px solid #222222;
}

#sidebar QPushButton {
    background-color: transparent;
    color: #888888;
    border: none;
    border-radius: 8px;
    padding: 12px 16px;
    text-align: left;
    font-size: 13px;
}

#sidebar QPushButton:hover {
    background-color: #1a1a1a;
    color: #e0e0e0;
}

#sidebar QPushButton:checked {
    background-color: #1a1a1a;
    color: #00c853;
    border-left: 3px solid #00c853;
}

.stat-card {
    background-color: #1a1a1a;
    border: 1px solid #222222;
    border-radius: 12px;
    padding: 20px;
}

.stat-card:hover {
    border-color: #333333;
}

QPushButton {
    background-color: #1a1a1a;
    color: #e0e0e0;
    border: 1px solid #333333;
    border-radius: 8px;
    padding: 10px 20px;
    font-size: 13px;
}

QPushButton:hover {
    background-color: #252525;
    border-color: #444444;
}

QPushButton:pressed {
    background-color: #0d0d0d;
}

QPushButton:disabled {
    background-color: #151515;
    color: #555555;
    border-color: #222222;
}

#btn-primary {
    background-color: #00c853;
    color: #0d0d0d;
    border: none;
    font-weight: bold;
}

#btn-primary:hover {
    background-color: #00e676;
}

#btn-primary:pressed {
    background-color: #00a844;
}

#btn-danger {
    background-color: #ff1744;
    color: #ffffff;
    border: none;
}

#btn-danger:hover {
    background-color: #ff5252;
}

#btn-scan {
    background-color: #1a1a1a;
    border: 2px solid #00c853;
    color: #00c853;
    font-size: 14px;
    font-weight: bold;
    padding: 14px 28px;
    border-radius: 10px;
}

#btn-scan:hover {
    background-color: #00c853;
    color: #0d0d0d;
}

QTableWidget {
    background-color: #111111;
    border: 1px solid #222222;
    border-radius: 8px;
    gridline-color: #1a1a1a;
    selection-background-color: #1a3a1a;
    selection-color: #e0e0e0;
}

QTableWidget::item {
    padding: 6px;
    border-bottom: 1px solid #1a1a1a;
}

QTableWidget::item:selected {
    background-color: #1a3a1a;
}

QHeaderView::section {
    background-color: #111111;
    color: #888888;
    border: none;
    border-bottom: 2px solid #222222;
    padding: 8px;
    font-weight: bold;
    font-size: 11px;
}

QProgressBar {
    background-color: #1a1a1a;
    border: none;
    border-radius: 4px;
    height: 6px;
    text-align: center;
    color: transparent;
}

QProgressBar::chunk {
    background-color: #00c853;
    border-radius: 4px;
}

QLineEdit, QSpinBox, QComboBox {
    background-color: #1a1a1a;
    color: #e0e0e0;
    border: 1px solid #333333;
    border-radius: 6px;
    padding: 8px 12px;
    font-size: 13px;
}

QLineEdit:focus, QSpinBox:focus, QComboBox:focus {
    border-color: #00c853;
}

QComboBox::drop-down {
    border: none;
    width: 30px;
}

QComboBox QAbstractItemView {
    background-color: #1a1a1a;
    color: #e0e0e0;
    border: 1px solid #333333;
    selection-background-color: #1a3a1a;
}

QScrollBar:vertical {
    background-color: #0d0d0d;
    width: 8px;
    border: none;
}

QScrollBar::handle:vertical {
    background-color: #333333;
    border-radius: 4px;
    min-height: 30px;
}

QScrollBar::handle:vertical:hover {
    background-color: #555555;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

#title {
    font-size: 22px;
    font-weight: bold;
    color: #ffffff;
}

#subtitle {
    font-size: 14px;
    color: #888888;
}

QGroupBox {
    border: 1px solid #222222;
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 20px;
    font-weight: bold;
    color: #aaaaaa;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 16px;
    padding: 0 8px;
}

QCheckBox {
    spacing: 8px;
    color: #e0e0e0;
}

QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border: 2px solid #333333;
    border-radius: 4px;
    background-color: #1a1a1a;
}

QCheckBox::indicator:checked {
    background-color: #00c853;
    border-color: #00c853;
}
"""
