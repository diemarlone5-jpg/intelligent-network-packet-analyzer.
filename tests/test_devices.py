"""Tests de la decouverte des appareils du reseau local.

Ces tests portent sur deux choses distinctes :

  1. la traduction d'un nom de service DNS-SD en libelle comprehensible ;
  2. la distinction entre un appareil qui ANNONCE un service et un appareil qui
     le RECHERCHE — les confondre ferait dire a l'outil l'inverse de la verite.

Ils ne testent volontairement aucune fonction de lecture de trafic prive :
cette fonction n'existe pas.
"""

from __future__ import annotations

from app.analysis.devices import (
    DeviceTable,
    explain_service,
    service_type_of,
)
from app.models import PacketRecord


def make_record(**kwargs) -> PacketRecord:
    """Construit un enregistrement de paquet avec des valeurs par defaut saines."""
    base = dict(number=1, ts=1000.0, src="192.168.1.4", dst="192.168.1.10",
                protocol="UDP", size=100)
    base.update(kwargs)
    return PacketRecord(**base)


def local_only(ip: str) -> bool:
    return ip in {"192.168.1.10", "fe80::a572:4e01:8b4b:cf1b"}


# --------------------------------------------------------------------------
# Traduction des noms de services
# --------------------------------------------------------------------------


def test_traduit_un_service_connu_avec_son_instance():
    etiquette, instance = explain_service("smart-tv-A1B2._googlecast._tcp.local")
    assert etiquette == "Google Cast (Chromecast, Android TV)"
    assert instance == "smart-tv-A1B2"


def test_traduit_spotify_connect():
    """Le type de service vient de la documentation officielle de Spotify."""
    etiquette, instance = explain_service("Bose-ST10._spotify-connect._tcp.local")
    assert etiquette == "Spotify Connect"
    assert instance == "Bose-ST10"


def test_traduit_airplay():
    etiquette, _ = explain_service("salon._airplay._tcp.local")
    assert etiquette == "AirPlay (diffusion video Apple)"


def test_nom_d_hote_simple_n_a_pas_de_service():
    etiquette, instance = explain_service("DESKTOP-ABC.local")
    assert etiquette is None
    assert instance == "DESKTOP-ABC"


def test_interrogation_de_la_liste_des_services():
    etiquette, instance = explain_service("_services._dns-sd._udp.local")
    assert etiquette is not None
    assert instance is None


def test_service_inconnu_n_invente_pas_de_libelle():
    """Un type non documente doit rester sans libelle, jamais etre devine."""
    etiquette, instance = explain_service("machin._type-inconnu._tcp.local")
    assert etiquette is None
    assert instance == "machin"


def test_entrees_vides_ne_levent_pas():
    assert explain_service(None) == (None, None)
    assert explain_service("") == (None, None)
    assert explain_service("...") == (None, None)


def test_extraction_du_type_de_service():
    assert service_type_of("a._googlecast._tcp.local") == "_googlecast"
    assert service_type_of("DESKTOP.local") is None
    assert service_type_of(None) is None


# --------------------------------------------------------------------------
# Table des appareils
# --------------------------------------------------------------------------


def test_arp_fournit_le_couple_adresse_ip_et_adresse_materielle():
    table = DeviceTable(local_only)
    table.observe(make_record(
        protocol="ARP", src="192.168.1.4", dst="192.168.1.10",
        src_mac="3c:07:54:aa:bb:cc",
        info="ARP reponse : qui possede 192.168.1.10 ? dit 192.168.1.4",
    ))
    appareils = table.snapshot()
    assert len(appareils) == 1
    assert appareils[0]["ip"] == "192.168.1.4"
    assert appareils[0]["mac"] == "3c:07:54:aa:bb:cc"


def test_une_adresse_qui_n_est_que_destinataire_n_est_pas_un_appareil():
    """Une requete ARP cite une adresse : la citer ne prouve pas qu'elle existe."""
    table = DeviceTable(local_only)
    table.observe(make_record(src="142.250.75.238", dst="192.168.1.10"))
    assert table.snapshot() == []


def test_une_adresse_publique_n_est_pas_un_appareil_du_reseau():
    table = DeviceTable(local_only)
    table.observe(make_record(src="142.250.75.238", dst="192.168.1.10"))
    table.observe(make_record(src="192.168.1.4", dst="142.250.75.238"))
    adresses = {a["ip"] for a in table.snapshot()}
    assert "142.250.75.238" not in adresses
    assert "192.168.1.4" in adresses


def test_les_diffusions_ne_sont_pas_des_appareils():
    table = DeviceTable(local_only)
    for adresse in ("255.255.255.255", "224.0.0.251", "239.255.255.250"):
        table.observe(make_record(src=adresse, dst="192.168.1.10"))
    assert table.snapshot() == []


def test_l_adresse_de_diffusion_du_sous_reseau_n_est_pas_un_appareil():
    """192.168.1.255 designe tout le monde sur le reseau, pas une machine."""
    table = DeviceTable(local_only)
    table.observe(make_record(src="192.168.1.255", dst="192.168.1.10"))
    assert "192.168.1.255" not in [a["ip"] for a in table.snapshot()]


def test_une_machine_avec_plusieurs_adresses_ne_fait_qu_un_appareil():
    """IPv4 et IPv6 d'une meme machine = un seul appareil, pas deux lignes."""
    table = DeviceTable(local_only)
    for adresse in ("192.168.1.4", "fe80::51c:d34f:cde8:77de"):
        table.observe(make_record(
            protocol="ARP", src=adresse, dst="192.168.1.10",
            src_mac="38:26:56:01:2c:7f",
        ))
    appareils = table.snapshot()
    assert len(appareils) == 1
    assert appareils[0]["mac"] == "38:26:56:01:2c:7f"
    assert "192.168.1.4" in appareils[0]["addresses"]
    assert "fe80::51c:d34f:cde8:77de" in appareils[0]["addresses"]


def test_une_adresse_materielle_de_diffusion_n_est_pas_retenue():
    """ff:ff:ff:ff:ff:ff designe tout le monde, pas un appareil precis."""
    table = DeviceTable(local_only)
    table.observe(make_record(
        protocol="ARP", src="192.168.1.4", dst="192.168.1.10",
        src_mac="ff:ff:ff:ff:ff:ff",
    ))
    appareils = table.snapshot()
    assert appareils[0]["mac"] is None


def test_recherche_de_service_n_est_pas_une_annonce():
    """Le point central : chercher Spotify n'est pas proposer Spotify."""
    table = DeviceTable(local_only)
    table.observe(make_record(
        src="192.168.1.4", dst="224.0.0.251", protocol="DNS",
        dns_query="_spotify-connect._tcp.local", dns_is_query=True,
    ))
    services = table.services_snapshot()
    assert len(services) == 1
    assert services[0]["label"] == "Spotify Connect"
    assert services[0]["searched"] is True
    assert services[0]["announced"] is False


def test_annonce_de_service_est_distinguee_de_la_recherche():
    table = DeviceTable(local_only)
    table.observe(make_record(
        src="192.168.1.30", dst="224.0.0.251", protocol="DNS",
        dns_query="salon-tv._googlecast._tcp.local", dns_is_query=False,
    ))
    services = table.services_snapshot()
    assert services[0]["announced"] is True
    assert services[0]["searched"] is False


def test_le_service_est_rattache_a_l_appareil_qui_l_a_emis():
    table = DeviceTable(local_only)
    table.observe(make_record(src="192.168.1.4", dst="192.168.1.10"))
    table.observe(make_record(
        src="192.168.1.4", dst="224.0.0.251", protocol="DNS",
        dns_query="Enceinte._spotify-connect._tcp.local", dns_is_query=True,
    ))
    appareil = next(a for a in table.snapshot() if a["ip"] == "192.168.1.4")
    types = {s["type"]: s for s in appareil["services"]}
    assert "_spotify-connect" in types
    assert types["_spotify-connect"]["searched"] is True
    assert types["_spotify-connect"]["announced"] is False
    assert "Enceinte" in types["_spotify-connect"]["instances"]


def test_un_nom_de_domaine_internet_n_est_pas_un_service_local():
    table = DeviceTable(local_only)
    table.observe(make_record(
        src="192.168.1.10", dst="8.8.8.8", protocol="DNS",
        dns_query="www.google.com", dns_is_query=True,
    ))
    assert table.services_snapshot() == []


def test_les_octets_bruts_ne_font_pas_echouer_l_observation():
    table = DeviceTable(local_only)
    table.observe(make_record(malformed=True))
    table.observe(make_record(src="", dst=""))
    table.observe(make_record(src=None, dst=None))
    assert isinstance(table.snapshot(), list)


def test_la_machine_locale_est_marquee_comme_telle():
    table = DeviceTable(local_only)
    table.observe(make_record(src="192.168.1.10", dst="192.168.1.4"))
    table.observe(make_record(src="192.168.1.4", dst="192.168.1.10"))
    local = next(a for a in table.snapshot() if a["ip"] == "192.168.1.10")
    distant = next(a for a in table.snapshot() if a["ip"] == "192.168.1.4")
    assert local["is_local"] is True
    assert distant["is_local"] is False


def test_le_compteur_de_paquets_par_appareil():
    table = DeviceTable(local_only)
    for _ in range(3):
        table.observe(make_record(src="192.168.1.4", dst="192.168.1.10"))
    appareil = next(a for a in table.snapshot() if a["ip"] == "192.168.1.4")
    assert appareil["packets"] == 3
    assert table.count() == 1


def test_les_services_non_documentes_sont_regroupes_en_une_seule_ligne():
    """Quatre lignes « non documente » n'apprendraient rien : elles sont regroupees."""
    table = DeviceTable(local_only)
    for type_service in ("_tranCast", "_trel", "_trancse"):
        table.observe(make_record(
            src="192.168.1.8", dst="224.0.0.251", protocol="DNS",
            dns_query=f"appareil.{type_service}._tcp.local", dns_is_query=True,
        ))
    services = table.services_snapshot()
    assert len(services) == 1
    assert services[0]["label"] is None
    assert services[0]["is_unlabelled"] is True
    assert services[0]["count"] == 3
    # Le type est normalise en minuscules : c'est une cle de comparaison.
    assert "_trancast" in services[0]["types"]


def test_les_services_documentes_restent_visibles_individuellement():
    table = DeviceTable(local_only)
    table.observe(make_record(
        src="192.168.1.4", dst="224.0.0.251", protocol="DNS",
        dns_query="_spotify-connect._tcp.local", dns_is_query=True,
    ))
    table.observe(make_record(
        src="192.168.1.8", dst="224.0.0.251", protocol="DNS",
        dns_query="appareil._tranCast._tcp.local", dns_is_query=True,
    ))
    services = table.services_snapshot()
    labels = [s["label"] for s in services]
    assert "Spotify Connect" in labels
    # Le regroupement vient en dernier et n'ecrase pas les services identifies.
    assert services[-1]["is_unlabelled"] is True


def test_vider_la_table_remet_tout_a_zero():
    table = DeviceTable(local_only)
    table.observe(make_record(src="192.168.1.4", dst="192.168.1.10", protocol="ARP"))
    table.clear()
    assert table.snapshot() == []
    assert table.services_snapshot() == []
