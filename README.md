# BenguelaShield

Antivirus open source para Windows 10/11, criado para a administracao municipal de Benguela, Angola.

## Motores de Deteccao

| Motor | Tecnologia | O que faz |
|-------|-----------|-----------|
| **ClamAV 1.5.2** | 3.6M assinaturas | Scan de ficheiros baseado em assinaturas |
| **YARA 4.5.4** | 23 regras (10 Angola + 13 genericas) | Deteccao por padroes e strings maliciosas |
| **IA LightGBM** | 22 features PE, 99.5% accuracy | Classificacao de executaveis por estrutura |

## Modulos

| Modulo | Descricao |
|--------|-----------|
| **AntiVirus** | Scan rapido/completo, quarentena AES-256, assinaturas |
| **Monitor Tempo Real** | Watchdog em pastas criticas, USB Guard, Download Guard |
| **Anti-Ransomware** | Honeypots, backup automatico, deteccao de encriptacao |
| **Comportamental** | Monitor de processos, ML Isolation Forest, heuristicas |
| **YARA** | 23 regras (10 Angola-specific + 13 genericas) |
| **IA** | Classificador LightGBM com 22 features de executaveis PE |
| **Scan Agendado** | Scan rapido diario + completo semanal |
| **Ferramentas Smadav** | USB vaccinator, registry repair, win-force, analise manual |
| **Quick Scan** | 10 fases em paralelo (processos, autostart, WMI, boot, etc.) |

## GUI PyQt6

9 paginas com tema escuro:
1. Painel - Dashboard com estado do sistema
2. Scanner - Scan com circular progress e log em tempo real
3. Quarentena - Gestao de ficheiros bloqueados
4. Anti-Ransom - Honeypots, backups, proteccao de pastas
5. Comportamental - Processos, alertas
6. YARA - Gestao de regras
7. Ferramentas - USB, reparacao, analise manual
8. Definicoes - Configuracoes gerais
9. Relatorios - Historico e exportacao

## Quick Scan (10 Fases)

| Fase | Verifica |
|------|----------|
| 1. Processos | 165 processos, hash SHA256, DLLs, assinatura |
| 2. Autostart | 10 chaves de registo, 72 itens |
| 3. Startup | 287 tarefas + WMI subscriptions |
| 4. Ficheiros Risco | TEMP, Downloads (ultimos 7 dias) |
| 5. Browser/Hosts | hosts file, extensoes |
| 6. Rede | 45 ligacoes TCP activas |
| 7. Servicos | 288 servicos Windows |
| 8. DLLs | DLLs em pastas suspeitas |
| 9. YARA | 23 regras em executaveis |
| 10. Integridade | Ficheiros criticos + boot sector |

**Total: 875 itens, 32 ameacas, 21 segundos**

## Instalacao

```bash
pip install PyQt6 psutil yara-python lightgbm scikit-learn pycryptodome
git clone https://github.com/CarlosSoares00/BenguelaShield.git
cd BenguelaShield
python -m pytest tests/ -q
python -m gui
python run_service.py
```

## Requisitos

- Windows 10/11 (64-bit)
- Python 3.12+
- ClamAV 1.5.2 (binarios em engine/clamav/x64/)

## Licenca

GPLv2 — Software livre para uso municipal em Benguela, Angola.
