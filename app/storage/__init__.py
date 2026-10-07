"""Persistance : SQLite en local, Supabase en ligne, derriere une meme interface."""

from app.storage.base import Repository
from app.storage.sqlite_repo import SqliteRepository

__all__ = ["Repository", "SqliteRepository", "build_repository"]


def build_repository(settings) -> Repository:
    """Construit le depot de donnees adapte a la configuration.

    SQLite est toujours disponible et sert de source locale. Si Supabase est
    active, les donnees y sont egalement poussees ; en cas d'indisponibilite
    du reseau, l'application continue de fonctionner sur SQLite.
    """
    from app.storage.supabase_repo import SupabaseRepository

    local = SqliteRepository(settings.sqlite_path)
    local.init_schema()

    if settings.supabase_enabled and settings.supabase_url and settings.supabase_service_key:
        remote = SupabaseRepository(settings.supabase_url, settings.supabase_service_key)
        if remote.ping():
            from app.storage.composite_repo import CompositeRepository
            return CompositeRepository(local, remote)
        local.record_warning(
            "Supabase est active mais injoignable : les donnees sont conservees "
            "uniquement en local pour l'instant."
        )
    return local
