"""Configuration de l'application, lue depuis l'environnement.

Aucun secret n'est ecrit dans le code : tout vient du fichier .env (jamais
commite) ou des variables d'environnement de la plateforme d'hebergement.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

# Racine du projet : .../packet-analyzer
BASE_DIR = Path(__file__).resolve().parent.parent

# Charge .env avant toute lecture de variable
load_dotenv(BASE_DIR / ".env")


def _bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "oui", "on")


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, "") or default)
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, "") or default)
    except ValueError:
        return default


@dataclass
class Settings:
    """Configuration complete, construite une seule fois au demarrage."""

    env: str = "dev"
    mode: str = "local"                     # local | cloud
    secret_key: str = ""
    capture_iface: str = ""
    max_packets_buffer: int = 5000

    sqlite_path: Path = field(default_factory=lambda: BASE_DIR / "data" / "analyzer.db")

    supabase_url: str = ""
    supabase_service_key: str = ""
    supabase_enabled: bool = False

    enrich_enabled: bool = True
    enrich_cache_ttl_hours: float = 24.0
    abuseipdb_api_key: str = ""

    ai_enabled: bool = False
    ai_provider: str = "openai"
    ai_api_key: str = ""
    ai_model: str = "gpt-4o-mini"
    ai_base_url: str = ""           # pour tout service compatible OpenAI

    # ------------------------------------------------------------------
    @property
    def is_local(self) -> bool:
        """La capture n'est possible qu'en mode local (pilote Npcap requis)."""
        return self.mode == "local"

    @property
    def is_production(self) -> bool:
        return self.env == "prod" or _bool("RENDER", False) or bool(os.getenv("RAILWAY_ENVIRONMENT"))

    def validate(self) -> list[str]:
        """Retourne la liste des problemes de configuration (vide = tout va bien)."""
        problems: list[str] = []

        if self.is_production and len(self.secret_key) < 32:
            problems.append(
                "SECRET_KEY manquante ou trop courte en production (32 caracteres minimum)."
            )
        if self.mode not in ("local", "cloud"):
            problems.append(f"APP_MODE invalide : {self.mode!r} (attendu 'local' ou 'cloud').")
        if self.supabase_enabled and not (self.supabase_url and self.supabase_service_key):
            problems.append(
                "SUPABASE_ENABLED=true mais SUPABASE_URL ou SUPABASE_SERVICE_KEY est vide."
            )
        if self.ai_enabled and not self.ai_api_key:
            problems.append("AI_ENABLED=true mais AI_API_KEY est vide.")
        return problems

    def ensure_dirs(self) -> None:
        self.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        (BASE_DIR / "data" / "captures").mkdir(parents=True, exist_ok=True)


def load_settings() -> Settings:
    """Construit l'objet de configuration a partir de l'environnement."""
    key = os.getenv("SECRET_KEY", "").strip()

    settings = Settings(
        env=os.getenv("APP_ENV", "dev").strip() or "dev",
        mode=os.getenv("APP_MODE", "local").strip().lower() or "local",
        secret_key=key,
        capture_iface=os.getenv("CAPTURE_IFACE", "").strip(),
        max_packets_buffer=_int("MAX_PACKETS_BUFFER", 5000),
        sqlite_path=Path(os.getenv("SQLITE_PATH") or (BASE_DIR / "data" / "analyzer.db")),
        supabase_url=os.getenv("SUPABASE_URL", "").strip(),
        supabase_service_key=os.getenv("SUPABASE_SERVICE_KEY", "").strip(),
        supabase_enabled=_bool("SUPABASE_ENABLED", False),
        enrich_enabled=_bool("ENRICH_ENABLED", True),
        enrich_cache_ttl_hours=_float("ENRICH_CACHE_TTL_HOURS", 24.0),
        abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY", "").strip(),
        ai_enabled=_bool("AI_ENABLED", False),
        ai_provider=os.getenv("AI_PROVIDER", "openai").strip() or "openai",
        ai_api_key=os.getenv("AI_API_KEY", "").strip(),
        ai_model=os.getenv("AI_MODEL", "gpt-4o-mini").strip() or "gpt-4o-mini",
        ai_base_url=os.getenv("AI_BASE_URL", "").strip(),
    )

    # En developpement, on genere une cle ephemere plutot que d'echouer :
    # l'application reste utilisable, mais les sessions ne survivent pas
    # a un redemarrage. En production, validate() refuse de demarrer.
    if not settings.secret_key:
        settings.secret_key = secrets.token_hex(32)

    if not settings.sqlite_path.is_absolute():
        settings.sqlite_path = BASE_DIR / settings.sqlite_path

    return settings


settings = load_settings()
