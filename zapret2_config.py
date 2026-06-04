"""
zapret2_config.py — безопасная загрузка конфигурации и секретов

Порядок загрузки ключей (от приоритетного к запасному):
  1. Файл .env в папке проекта
  2. Переменные окружения системы (export KEY=...)
  3. Конфиг ~/.zapret2-tui.json (сохранённый через TUI)
  4. Пусто — AI будет недоступен
"""

import os
import json
import re
from typing import Optional, Dict

# Путь к .env — ищем рядом с этим файлом
_HERE = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(_HERE, ".env")
# Конфиг рядом со скриптом — не зависит от sudo/пользователя
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zapret2-tui.json")

# ── Поддерживаемые провайдеры ─────────────────────────────────────────────────

AI_PROVIDERS = {
    "claude": {
        "name":    "Claude (Anthropic)",
        "url":     "https://api.anthropic.com/v1/messages",
        "key_env": "ANTHROPIC_API_KEY",
        "key_cfg": "anthropic_key",
        "models":  ["claude-sonnet-4-6", "claude-opus-4-6", "claude-haiku-4-5-20251001"],
        "model_env": "CLAUDE_MODEL",
        "model_cfg": "claude_model",
        "default_model": "claude-sonnet-4-6",
        "get_key_url": "https://console.anthropic.com/",
    },
    "openai": {
        "name":    "ChatGPT (OpenAI)",
        "url":     "https://api.openai.com/v1/chat/completions",
        "key_env": "OPENAI_API_KEY",
        "key_cfg": "openai_key",
        "models":  ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo"],
        "model_env": "OPENAI_MODEL",
        "model_cfg": "openai_model",
        "default_model": "gpt-4o",
        "get_key_url": "https://platform.openai.com/api-keys",
    },
}


def load_env_file(path: str = ENV_FILE) -> Dict[str, str]:
    """Читает .env файл и возвращает словарь переменных."""
    result = {}
    if not os.path.isfile(path):
        return result
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                # Пропускаем комментарии и пустые строки
                if not line or line.startswith("#"):
                    continue
                # Парсим KEY=VALUE (поддерживаем кавычки)
                m = re.match(r'^([A-Z_][A-Z0-9_]*)=(.*)$', line)
                if m:
                    key, value = m.group(1), m.group(2)
                    # Убираем кавычки если есть
                    value = value.strip()
                    if (value.startswith('"') and value.endswith('"')) or \
                       (value.startswith("'") and value.endswith("'")):
                        value = value[1:-1]
                    result[key] = value
    except Exception:
        pass
    return result


def load_user_config() -> dict:
    """Загружает пользовательский конфиг из ~/.zapret2-tui.json."""
    if os.path.isfile(CONFIG_FILE):
        try:
            return json.load(open(CONFIG_FILE, encoding="utf-8"))
        except Exception:
            pass
    return {}


def save_user_config(cfg: dict):
    """Сохраняет конфиг. Ключи хранятся в конфиге, не в коде."""
    try:
        json.dump(cfg, open(CONFIG_FILE, "w", encoding="utf-8"),
                  indent=2, ensure_ascii=False)
    except Exception as e:
        pass


def get_api_key(provider: str, cfg: dict = None) -> Optional[str]:
    """
    Возвращает API ключ для провайдера.
    Порядок: .env → системный env → конфиг.
    """
    if provider not in AI_PROVIDERS:
        return None

    info = AI_PROVIDERS[provider]
    env_var = info["key_env"]
    cfg_key = info["key_cfg"]

    # 1. Из .env файла
    env_data = load_env_file()
    val = env_data.get(env_var, "").strip()
    if val and not val.startswith("sk-YOUR") and val != "":
        return val

    # 2. Из системных переменных окружения
    val = os.environ.get(env_var, "").strip()
    if val:
        return val

    # 3. Из конфига TUI
    if cfg is None:
        cfg = load_user_config()
    val = cfg.get(cfg_key, "").strip()
    if val:
        return val

    return None


def get_model(provider: str, cfg: dict = None) -> str:
    """Возвращает модель для провайдера."""
    if provider not in AI_PROVIDERS:
        return ""

    info = AI_PROVIDERS[provider]
    env_var = info["model_env"]
    cfg_key = info["model_cfg"]

    # 1. Из .env
    env_data = load_env_file()
    val = env_data.get(env_var, "").strip()
    if val:
        return val

    # 2. Из системных env
    val = os.environ.get(env_var, "").strip()
    if val:
        return val

    # 3. Из конфига
    if cfg is None:
        cfg = load_user_config()
    val = cfg.get(cfg_key, "").strip()
    if val:
        return val

    return info["default_model"]


def get_active_provider(cfg: dict = None) -> str:
    """Возвращает активный AI провайдер из настроек."""
    # 1. Из .env
    env_data = load_env_file()
    val = env_data.get("AI_PROVIDER", "").strip().lower()
    if val in AI_PROVIDERS:
        return val

    # 2. Из конфига
    if cfg is None:
        cfg = load_user_config()
    val = cfg.get("ai_provider", "").strip().lower()
    if val in AI_PROVIDERS:
        return val

    # 3. Автоопределение — используем тот, у которого есть ключ
    for provider in AI_PROVIDERS:
        if get_api_key(provider, cfg):
            return provider

    return "claude"  # дефолт


def save_api_key_to_env(provider: str, key: str):
    """
    Сохраняет API ключ в .env файл (не в конфиг, не в код).
    Создаёт файл если не существует.
    """
    env_var = AI_PROVIDERS[provider]["key_env"]

    # Читаем существующий .env
    lines = []
    if os.path.isfile(ENV_FILE):
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()

    # Обновляем или добавляем строку
    updated = False
    for i, line in enumerate(lines):
        if line.strip().startswith(f"{env_var}="):
            lines[i] = f"{env_var}={key}\n"
            updated = True
            break

    if not updated:
        lines.append(f"{env_var}={key}\n")

    with open(ENV_FILE, "w", encoding="utf-8") as f:
        f.writelines(lines)

    # Защищаем файл — только владелец может читать
    try:
        os.chmod(ENV_FILE, 0o600)
    except Exception:
        pass


def save_provider_to_env(provider: str):
    """Сохраняет выбор провайдера в .env."""
    lines = []
    if os.path.isfile(ENV_FILE):
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()

    updated = False
    for i, line in enumerate(lines):
        if line.strip().startswith("AI_PROVIDER="):
            lines[i] = f"AI_PROVIDER={provider}\n"
            updated = True
            break

    if not updated:
        lines.insert(0, f"AI_PROVIDER={provider}\n")

    with open(ENV_FILE, "w", encoding="utf-8") as f:
        f.writelines(lines)
    try:
        os.chmod(ENV_FILE, 0o600)
    except Exception:
        pass


def mask_key(key: str) -> str:
    """Маскирует ключ для отображения: sk-ant-...xK3F"""
    if not key or len(key) < 8:
        return "***"
    return key[:6] + "..." + key[-4:]


def check_env_safety() -> list:
    """
    Проверяет безопасность — возвращает список предупреждений.
    """
    warnings = []

    # Проверяем права на .env
    if os.path.isfile(ENV_FILE):
        try:
            mode = oct(os.stat(ENV_FILE).st_mode)[-3:]
            if mode not in ("600", "400"):
                warnings.append(
                    f".env доступен другим пользователям (права {mode}). "
                    f"Исправь: chmod 600 .env"
                )
        except Exception:
            pass
    else:
        warnings.append(".env файл не найден. Скопируй .env.example в .env и заполни ключи.")

    # Проверяем .gitignore
    gitignore = os.path.join(_HERE, ".gitignore")
    if os.path.isfile(gitignore):
        content = open(gitignore).read()
        if ".env" not in content:
            warnings.append(".gitignore не содержит .env — ключи могут попасть на GitHub!")
    else:
        warnings.append(".gitignore не найден — создай его чтобы не загрузить ключи на GitHub!")

    return warnings
