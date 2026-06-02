# zapret2-tui

Консольный TUI интерфейс для управления [zapret2](https://github.com/bol-van/zapret2) с AI-подбором стратегий обхода DPI.

## Возможности
- Управление запуском/остановкой nfqws2
- Готовые шаблоны стратегий (TLS, HTTP, QUIC, Discord...)
- AI-подбор стратегии по домену (instagram.com, tiktok.com и т.д.)
- Поиск готовых решений в интернете через Claude API
- Смешивание нескольких стратегий в мульти-профиль
- Сохранение профилей

## Установка

```bash
git clone https://github.com/ТВО_ИМЯ/zapret2-tui.git
cd zapret2-tui
```

## Запуск

```bash
# Без AI
sudo python3 zapret2-tui-v2.py

# С AI (нужен Anthropic API ключ)
export ANTHROPIC_API_KEY="sk-ant-..."
sudo python3 zapret2-tui-v2.py
```

## Требования
- Python 3.6+
- zapret2 установлен (https://github.com/bol-van/zapret2)
- root/sudo для запуска nfqws2