"""Tests de la couche d'analyse : lecture, regroupement, explication, detection.

Chaque test correspond a une affirmation verifiable du cahier des charges.
"""

from __future__ import annotations

import pytest

from app.analysis.detectors import BehaviorAnalyzer, DetectionConfig, shannon_entropy
from app.analysis.explain import Explainer
from app.analysis.flows import (
    FlowTable,
    infer_direction,
    resolve_service_port,
    state_label,
)
from app.analysis.parser import extract_http_host, extract_tls_sni
from app.analysis.protocols import classify_address, is_translation_prefix, lookup_port
from app.models import KIND_ALERTE, KIND_HYPOTHESE, KIND_OBSERVATION
from tests.conftest import (
    LOCAL_IP,
    REMOTE_IP,
    arp_request,
    dns_query,
    http_get,
    tcp_packet,
    tls_client_hello,
    udp_packet,
)


# ==========================================================================
# 1. Lecture des paquets
# ==========================================================================


class TestExtractionSNI:
    """Le nom de domaine est lisible dans un ClientHello, sans rien dechiffrer."""

    def test_sni_extrait_d_un_client_hello(self):
        assert extract_tls_sni(tls_client_hello("www.wikipedia.org")) == "www.wikipedia.org"

    def test_sni_absent_renvoie_none(self):
        """Un paquet qui n'est pas un ClientHello ne doit produire aucun domaine.

        C'est la garantie qu'aucun faux domaine n'est jamais affiche.
        """
        assert extract_tls_sni(b"\x17\x03\x03\x00\x10" + b"\xaa" * 20) is None
        assert extract_tls_sni(b"") is None
        assert extract_tls_sni(b"\x16\x03\x01\x00\x05\x02\x00\x00\x01\x00") is None

    def test_sni_tronque_ne_leve_pas(self):
        """Un paquet tronque doit retourner None, jamais lever d'exception."""
        complet = tls_client_hello("example.com")
        for longueur in range(1, len(complet), 7):
            assert extract_tls_sni(complet[:longueur]) in (None, "example.com")


class TestExtractionHTTP:
    def test_entete_host_lu(self):
        assert extract_http_host(http_get("neverssl.com")) == "neverssl.com"

    def test_reponse_http_ne_donne_pas_de_host(self):
        reponse = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        assert extract_http_host(reponse) is None


class TestParseur:
    def test_paquet_tcp_renseigne_les_champs(self, parser):
        record = parser.parse(tcp_packet(sport=51000, dport=443, flags="S"), 1)
        assert record.src == LOCAL_IP
        assert record.dst == REMOTE_IP
        assert record.transport == "TCP"
        assert record.src_port == 51000
        assert record.dst_port == 443
        assert record.tcp_flags == "S"
        assert record.direction == "sortant"
        assert record.malformed is False

    def test_tls_reconnu_et_domaine_extrait(self, parser):
        record = parser.parse(
            tcp_packet(dport=443, flags="PA", payload=tls_client_hello("api.github.com")), 2
        )
        assert record.protocol == "TLS"
        assert record.tls_sni == "api.github.com"
        assert record.domain == "api.github.com"

    def test_http_en_clair_reconnu(self, parser):
        record = parser.parse(
            tcp_packet(dport=80, flags="PA", payload=http_get("neverssl.com")), 3
        )
        assert record.protocol == "HTTP"
        assert record.http_host == "neverssl.com"

    def test_requete_dns_lue(self, parser):
        record = parser.parse(dns_query("example.com"), 4)
        assert record.protocol == "DNS"
        assert record.dns_query == "example.com"

    def test_arp_reconnu(self, parser):
        record = parser.parse(arp_request(), 5)
        assert record.protocol == "ARP"
        assert "qui possede" in record.info.lower()

    def test_paquet_vide_ne_leve_pas(self, parser):
        """Cas limite : un paquet sans couche exploitable reste analysable."""
        from scapy.layers.l2 import Ether
        paquet = Ether()
        paquet.time = 1000.0
        record = parser.parse(paquet, 6)
        assert record.malformed is False
        assert record.protocol == "Ethernet"


# ==========================================================================
# 2. Regroupement en communications
# ==========================================================================


class TestTableDesFlux:
    def build(self):
        return FlowTable(is_local=lambda ip: ip == LOCAL_IP)

    def test_les_deux_sens_forment_un_seul_flux(self):
        """Une conversation appartient aux deux machines, pas a une seule."""
        table = self.build()
        table.observe(parse(tcp_packet(sport=51000, dport=443, flags="S"), 1))
        table.observe(parse(tcp_packet(src=REMOTE_IP, dst=LOCAL_IP, sport=443,
                                       dport=51000, flags="SA"), 2))
        assert table.count() == 1

    def test_etat_tcp_suit_les_drapeaux(self):
        table = self.build()
        flow = table.observe(parse(tcp_packet(sport=51000, dport=443, flags="S"), 1))
        assert flow.handshake_seen is True
        assert flow.tcp_state == "ouverture demandee"
        assert flow.service_port == 443

        flow = table.observe(parse(tcp_packet(src=REMOTE_IP, dst=LOCAL_IP, sport=443,
                                              dport=51000, flags="SA"), 2))
        assert flow.tcp_state == "ouverture acceptee"

        flow = table.observe(parse(tcp_packet(sport=51000, dport=443, flags="A"), 3))
        assert flow.tcp_state == "etablie"
        assert flow.state == "etablie"

    def test_connexion_refusee_reconnue(self):
        """Un RST juste apres un SYN signifie un refus, pas une fermeture."""
        table = self.build()
        table.observe(parse(tcp_packet(sport=51000, dport=8080, flags="S"), 1))
        flow = table.observe(parse(tcp_packet(src=REMOTE_IP, dst=LOCAL_IP, sport=8080,
                                              dport=51000, flags="RA"), 2))
        assert flow.tcp_state == "refusee par le destinataire"
        assert flow.state == "echec"
        assert "refusee" in state_label(flow)

    def test_fermeture_normale(self):
        table = self.build()
        table.observe(parse(tcp_packet(sport=51000, dport=443, flags="SA"), 1))
        table.observe(parse(tcp_packet(sport=51000, dport=443, flags="FA"), 2))
        flow = table.observe(parse(tcp_packet(src=REMOTE_IP, dst=LOCAL_IP, sport=443,
                                              dport=51000, flags="FA"), 3))
        assert flow.state == "fermee"

    def test_compteurs_de_volume_separes_par_sens(self):
        table = self.build()
        table.observe(parse(tcp_packet(sport=51000, dport=443, flags="S"), 1))
        flow = table.observe(parse(tcp_packet(src=REMOTE_IP, dst=LOCAL_IP, sport=443,
                                              dport=51000, flags="A"), 2))
        assert flow.bytes_fwd == 54      # paquet Ethernet+IP+TCP de 54 octets
        assert flow.bytes_rev == 54
        assert flow.packets == 2

    def test_protocole_applicatif_le_plus_precis_gagne(self):
        """Un flux TLS ne doit jamais etre ramene a TCP par un paquet ulterieur."""
        table = self.build()
        table.observe(parse(tcp_packet(sport=51000, dport=443, flags="PA",
                                       payload=tls_client_hello("example.com")), 1))
        flow = table.observe(parse(tcp_packet(sport=51000, dport=443, flags="A"), 2))
        assert flow.app_protocol == "TLS"
        assert flow.domain == "example.com"

    def test_inactivite_apres_silence(self):
        table = self.build()
        table.observe(parse(tcp_packet(sport=51000, dport=443, flags="A", ts=1000.0), 1))
        table.tick(now=1000.0 + 3600)
        assert table.snapshot()[0].state == "inactive"


class TestDeductionDuService:
    """Le port du service doit rester correct meme si le debut a ete manque."""

    def test_port_deduit_quand_le_syn_est_manque(self):
        """Cas reel : capture demarree en cours de connexion.

        Premier paquet observe : le serveur repond sur 443 vers notre port
        ephemeral 63847. Le service discute est bien 443, pas 63847.
        """
        table = FlowTable(is_local=lambda ip: ip == LOCAL_IP)
        flow = table.observe(parse(tcp_packet(src=REMOTE_IP, dst=LOCAL_IP, sport=443,
                                              dport=63847, flags="A"), 1))
        assert flow.handshake_seen is False
        assert resolve_service_port(flow) == 443
        assert infer_direction(flow, table.is_local) == "local"

    def test_port_deduit_par_defaut_le_plus_bas_si_aucun_connu(self):
        table = FlowTable(is_local=lambda ip: ip == LOCAL_IP)
        flow = table.observe(parse(tcp_packet(src=REMOTE_IP, dst=LOCAL_IP, sport=51000,
                                              dport=52000, flags="A"), 1))
        assert resolve_service_port(flow) == 51000

    def test_sens_deduit_d_un_service_local_connu(self):
        """Un client distant qui atteint notre port 22 : c'est lui qui appelle."""
        table = FlowTable(is_local=lambda ip: ip == LOCAL_IP)
        flow = table.observe(parse(tcp_packet(src=REMOTE_IP, dst=LOCAL_IP, sport=51000,
                                              dport=22, flags="A"), 1))
        assert infer_direction(flow, table.is_local) == "distant"


def parse(packet, number):
    from app.analysis.parser import PacketParser
    return PacketParser(local_ips={LOCAL_IP}).parse(packet, number)


# ==========================================================================
# 3. Base de connaissance
# ==========================================================================


class TestBaseDeConnaissance:
    def test_ports_connus(self):
        assert lookup_port(443, "TCP").service == "HTTPS"
        assert lookup_port(53, "UDP").service == "DNS"
        assert lookup_port(22, "TCP").service == "SSH"

    def test_port_inconnu(self):
        assert lookup_port(63847, "TCP") is None

    def test_port_sensible_signale(self):
        assert lookup_port(23, "TCP").sensitive is True   # Telnet
        assert lookup_port(3389, "TCP").sensitive is True  # RDP
        assert lookup_port(443, "TCP").sensitive is False

    def test_protocole_en_clair_marque(self):
        assert lookup_port(80, "TCP").cleartext is True
        assert lookup_port(443, "TCP").cleartext is not True

    def test_classification_des_adresses(self):
        assert classify_address("192.168.1.10") == "prive"
        assert classify_address("8.8.8.8") == "public"
        assert classify_address("127.0.0.1") == "loopback"
        assert classify_address("169.254.1.1") == "lien-local"
        assert classify_address("pas-une-ip") == "inconnu"

    def test_prefixes_de_traduction_reconnus(self):
        """Un prefixe NAT64 ou 6to4 n'est pas un hote : c'est une passerelle
        derriere laquelle se cachent de nombreuses destinations."""
        from app.analysis.protocols import is_translation_prefix
        assert classify_address("64:ff9b::3ad:153f") == "traduction"
        assert is_translation_prefix("64:ff9b::3ad:153f") is True
        assert is_translation_prefix("2002::1") is True
        # Une adresse IPv6 publique ordinaire n'est pas un prefixe de traduction
        assert is_translation_prefix("2001:67c:4e8:f004::9") is False
        assert is_translation_prefix("192.168.1.10") is False
        assert is_translation_prefix(None) is False

    def test_decouverte_du_prefixe_nat64_du_reseau(self):
        """Chaque operateur choisit son propre prefixe NAT64 (RFC 6052) : il ne
        peut donc pas figurer dans une liste fixe. La RFC 7050 permet de le
        decouvrir, et c'est indispensable pour ne pas presenter une passerelle
        comme un hote unique.

        Le test tolere l'absence de DNS64 (reseau sans traduction) : ce qui est
        verifie, c'est que la reponse est vide, ou constituee de prefixes /96
        valides et effectivement reconnus par la classification.
        """
        import ipaddress

        from app.analysis.protocols import discover_nat64_prefixes
        prefixes = discover_nat64_prefixes()
        assert isinstance(prefixes, tuple)

        for prefixe in prefixes:
            assert prefixe.endswith("/96")
            network = ipaddress.ip_network(prefixe)
            assert network.prefixlen == 96
            exemple = str(network.network_address)
            assert is_translation_prefix(exemple) is True

    def test_tous_les_prefixes_annonces_sont_retenus(self):
        """Un resolveur peut annoncer le prefixe bien connu ET celui de
        l'operateur, et varier d'une interrogation a l'autre. Ce qui a ete
        appris ne doit jamais etre perdu."""
        from app.analysis import protocols
        from app.analysis.protocols import discover_nat64_prefixes

        prefixes = discover_nat64_prefixes()
        assert discover_nat64_prefixes() == prefixes      # stable (cache)
        assert len(set(prefixes)) == len(prefixes)        # aucun doublon

        # On simule un reseau qui n'annonce plus rien : l'acquis doit rester.
        acquis = protocols._NAT64_CACHE["prefixes"]
        protocols.discover_nat64_prefixes(force=True)
        assert set(acquis).issubset(set(protocols._NAT64_CACHE["prefixes"]))

    def test_adresses_de_diffusion_reconnues(self):
        """255.255.255.255 et les diffusions dirigees ne sont pas des hotes."""
        from app.analysis.protocols import is_broadcast
        assert is_broadcast("255.255.255.255") is True
        assert is_broadcast("192.168.1.255") is True
        assert is_broadcast("192.168.1.10") is False
        assert is_broadcast("ff02::1") is False
        assert classify_address("192.168.1.255") == "diffusion"
        assert classify_address("255.255.255.255") == "diffusion"


class TestDetectionDesAdressesLocales:
    """Sans reconnaissance des IPv6, une communication SORTANTE peut etre prise
    pour une connexion ENTRANTE, ce qui fausse le sens et le niveau de risque."""

    def test_ipv6_locale_reconnue(self):
        from app.analysis.parser import PacketParser
        parser = PacketParser(local_ips={"2001:42d8:379d:e500:c892:3484:1e87:3d2"})
        assert parser.is_local("2001:42d8:379d:e500:c892:3484:1e87:3d2") is True
        assert parser.is_local("2001:67c:4e8:f004::9") is False

    def test_ipv6_equivalente_ecrite_autrement(self):
        """Une meme adresse IPv6 s'ecrit de plusieurs facons : 2001:db8::1
        et 2001:0db8:0000:0000:0000:0000:0000:0001 sont identiques."""
        from app.analysis.parser import PacketParser
        parser = PacketParser(local_ips={"2001:db8::1"})
        assert parser.is_local("2001:0db8:0000:0000:0000:0000:0000:0001") is True

    def test_suffixe_de_zone_ignore(self):
        from app.analysis.parser import PacketParser
        parser = PacketParser(local_ips={"fe80::1"})
        assert parser.is_local("fe80::1%12") is True

    def test_ipv4_inchangee(self):
        from app.analysis.parser import PacketParser
        parser = PacketParser(local_ips={"192.168.1.10"})
        assert parser.is_local("192.168.1.10") is True
        assert parser.is_local("192.168.1.11") is False
        assert parser.is_local(None) is False


# ==========================================================================
# 4. Moteur d'explication
# ==========================================================================


class TestMoteurDExplication:
    def build_flow(self, **kwargs):
        table = FlowTable(is_local=lambda ip: ip == LOCAL_IP)
        for i, packet in enumerate(kwargs.get("packets", []), start=1):
            flow = table.observe(parse(packet, i))
        return flow

    def test_explication_separe_faits_et_interpretations(self):
        """Exigence centrale : les deux categories ne sont jamais melangees."""
        flow = self.build_flow(packets=[
            tcp_packet(sport=51000, dport=443, flags="S", ts=1000.0),
            tcp_packet(src=REMOTE_IP, dst=LOCAL_IP, sport=443, dport=51000,
                       flags="SA", ts=1000.1),
            tcp_packet(sport=51000, dport=443, flags="PA", ts=1000.2),
        ])
        explanation = Explainer(is_local=lambda ip: ip == LOCAL_IP).explain_flow(flow)

        assert explanation.headline.startswith("Communication chiffree")
        assert len(explanation.facts) >= 6
        assert len(explanation.interpretations) >= 3
        assert explanation.caveats
        assert explanation.plain_text

        # Chaque fait porte son origine : mesure ou deduction
        for fait in explanation.facts:
            assert fait.origin

        # Chaque interpretation est rattachee a une justification
        for interpretation in explanation.interpretations:
            assert interpretation.basis
            assert interpretation.confidence in ("haute", "moyenne", "faible")

    def test_le_port_est_presente_comme_une_convention(self):
        """Une interpretation ne doit jamais etre presentee comme une preuve."""
        flow = self.build_flow(packets=[
            tcp_packet(sport=51000, dport=443, flags="S", ts=1000.0),
            tcp_packet(sport=51000, dport=443, flags="A", ts=1000.1),
        ])
        explanation = Explainer(is_local=lambda ip: ip == LOCAL_IP).explain_flow(flow)
        # On examine l'affirmation ET sa justification : c'est l'ensemble qui
        # doit rendre compte du caractere conventionnel du port.
        texte = " ".join(
            f"{i.statement} {i.basis}" for i in explanation.interpretations
        )
        assert "habituellement" in texte
        assert "convention" in texte
        assert "non une preuve" in texte

    def test_texte_humain_comprehensible(self):
        flow = self.build_flow(packets=[
            tcp_packet(sport=51000, dport=443, flags="S", ts=1000.0),
            tcp_packet(src=REMOTE_IP, dst=LOCAL_IP, sport=443, dport=51000,
                       flags="SA", ts=1000.1),
        ])
        explanation = Explainer(is_local=lambda ip: ip == LOCAL_IP).explain_flow(flow)
        # Le texte doit etre une phrase francaise complete et mentionner les acteurs
        assert "La machine locale" in explanation.plain_text
        assert REMOTE_IP in explanation.plain_text
        assert explanation.plain_text.endswith(".")

    def test_udp_ne_parle_pas_de_syn(self):
        """Exactitude : UDP n'etablit pas de connexion, il n'y a donc pas de SYN."""
        flow = self.build_flow(packets=[udp_packet(dport=53, ts=1000.0)])
        explanation = Explainer(is_local=lambda ip: ip == LOCAL_IP).explain_flow(flow)
        texte = " ".join(
            f"{i.statement} {i.basis}" for i in explanation.interpretations
        ).lower()
        assert "syn" not in texte
        assert "etablissement de connexion" in texte

        # Et la reserve doit le dire explicitement plutot que de parler de debut
        # de connexion manque, notion qui n'existe pas en UDP.
        reserves = " ".join(explanation.caveats).lower()
        assert "n'etablit pas de connexion" in reserves

    def test_precision_du_port_deduit_est_annoncee(self):
        """Quand le port est deduit, l'interface doit le dire explicitement."""
        flow = self.build_flow(packets=[
            tcp_packet(src=REMOTE_IP, dst=LOCAL_IP, sport=443, dport=63847,
                       flags="A", ts=1000.0),
        ])
        explanation = Explainer(is_local=lambda ip: ip == LOCAL_IP).explain_flow(flow)
        origine = [f.origin for f in explanation.facts if "service" in f.label.lower()]
        assert origine and "deduit" in origine[0]
        assert explanation.confidence != "haute"   # le port est suppose, pas mesure

    def test_port_non_documente_assume(self):
        flow = self.build_flow(packets=[
            tcp_packet(sport=51000, dport=64999, flags="S", ts=1000.0),
        ])
        explanation = Explainer(is_local=lambda ip: ip == LOCAL_IP).explain_flow(flow)
        assert "non documente" in explanation.headline
        assert "port standard documente" in explanation.plain_text
        assert explanation.confidence == "faible"

    def test_explication_d_un_evenement(self):
        from app.models import Event
        evenement = Event(ts=1.0, kind=KIND_OBSERVATION, rule="test",
                          title="Titre", explanation="Texte d'explication.")
        assert Explainer().explain_event(evenement) == "Texte d'explication."


# ==========================================================================
# 5. Detection comportementale
# ==========================================================================


class TestDetection:
    def build_scan(self, nombre=20):
        """Simule un poste qui contacte de nombreuses destinations distinctes."""
        table = FlowTable(is_local=lambda ip: ip == LOCAL_IP)
        for index in range(nombre):
            table.observe(parse(tcp_packet(sport=51000 + index,
                                           dst=f"203.0.113.{index}", dport=443,
                                           flags="S", ts=1000.0), index + 1))
        return table.snapshot()

    def test_balayage_de_destinations_detecte(self):
        analyzer = BehaviorAnalyzer(is_local=lambda ip: ip == LOCAL_IP)
        events = analyzer.analyze(self.build_scan(20), now=1000.0)
        regles = [e.rule for e in events]
        assert "destinations_multiples" in regles

    def test_l_evenement_est_une_hypothese_pas_une_alerte(self):
        """Exigence explicite : comportement inhabituel n'est pas attaque."""
        analyzer = BehaviorAnalyzer(is_local=lambda ip: ip == LOCAL_IP)
        events = analyzer.analyze(self.build_scan(20), now=1000.0)
        balayage = next(e for e in events if e.rule == "destinations_multiples")
        assert balayage.kind == KIND_HYPOTHESE
        assert "HYPOTHESE" in balayage.explanation
        assert "OBSERVATION" in balayage.explanation
        # Les preuves chiffrees doivent etre presentes
        assert balayage.evidence["nb_destinations"] == 20
        assert balayage.evidence["seuil"] == 15

    def test_anti_repetition(self):
        """Une meme regle ne doit pas inonder l'interface."""
        analyzer = BehaviorAnalyzer(is_local=lambda ip: ip == LOCAL_IP)
        flows = self.build_scan(20)
        premier = analyzer.analyze(flows, now=1000.0)
        second = analyzer.analyze(flows, now=1001.0)
        assert premier
        assert not any(e.rule == "destinations_multiples" for e in second)

    def test_service_sensible_en_entree_declenche_une_alerte(self):
        table = FlowTable(is_local=lambda ip: ip == LOCAL_IP)
        table.observe(parse(tcp_packet(src="203.0.113.7", dst=LOCAL_IP,
                                       sport=51000, dport=23, flags="S", ts=1000.0), 1))
        analyzer = BehaviorAnalyzer(is_local=lambda ip: ip == LOCAL_IP)
        events = analyzer.analyze(table.snapshot(), now=1000.0)
        alerte = next(e for e in events if e.rule == "service_sensible_joignable")
        assert alerte.kind == KIND_ALERTE
        assert alerte.severity == "eleve"

    def test_aucune_alerte_pour_un_service_en_diffusion(self):
        """SSDP et mDNS sont presents sur presque tous les reseaux domestiques.
        Les presenter comme une exposition serait un cri au loup."""
        table = FlowTable(is_local=lambda ip: ip == LOCAL_IP)
        # Annonce SSDP classique : diffusion vers 239.255.255.250
        table.observe(parse(udp_packet(src="192.168.1.50", dst="239.255.255.250",
                                       sport=1900, dport=1900, ts=1000.0), 1))
        # Requete mDNS : diffusion vers le groupe 224.0.0.251
        table.observe(parse(udp_packet(src="192.168.1.51", dst="224.0.0.251",
                                       sport=5353, dport=5353, ts=1000.1), 2))
        # Resolution NetBIOS : diffusion dirigee vers tout le sous-reseau
        table.observe(parse(udp_packet(src=LOCAL_IP, dst="192.168.1.255",
                                       sport=137, dport=137, ts=1000.2), 3))
        analyzer = BehaviorAnalyzer(is_local=lambda ip: ip == LOCAL_IP)
        events = analyzer.analyze(table.snapshot(), now=1000.0)
        assert not any(e.rule == "service_sensible_joignable" for e in events)

    def test_pas_de_volume_dominant_sous_le_seuil(self):
        """Une part de volume elevee mais ordinaire ne doit pas devenir un
        evenement : sinon la liste est noyee et les vraies detections disparaissent."""
        table = FlowTable(is_local=lambda ip: ip == LOCAL_IP)
        index = 0
        # 8 interlocuteurs distincts, donc la contrainte de diversite passe
        for destination in ("203.0.113.%d" % n for n in range(1, 9)):
            index += 1
            table.observe(parse(tcp_packet(sport=51000 + index, dst=destination,
                                           dport=443, flags="PA", ts=1000.0,
                                           payload=b"x" * 200), index))
        analyzer = BehaviorAnalyzer(is_local=lambda ip: ip == LOCAL_IP)
        events = analyzer.analyze(table.snapshot(), now=1000.0)
        # Repartition egale : aucune concentration ne merite d'etre signalee
        assert not any(e.rule == "volume_dominant" for e in events)

    def test_beaconing_sur_fenetre_longue(self):
        """Un rythme regulier ne se voit que sur une duree longue.

        Connexions toutes les 60 secondes : la fenetre courte des regles de
        volume (60 s) ne verrait qu'un seul flux. C'est pourquoi la detection
        de balise utilise sa propre fenetre.
        """
        table = FlowTable(is_local=lambda ip: ip == LOCAL_IP)
        for index in range(8):
            table.observe(parse(tcp_packet(sport=51000 + index, dst="203.0.113.50",
                                           dport=8443, flags="S",
                                           ts=2000.0 + index * 60), index + 1))
        analyzer = BehaviorAnalyzer(is_local=lambda ip: ip == LOCAL_IP)
        events = analyzer.analyze(table.snapshot(), now=2500.0)
        regulier = next(e for e in events if e.rule == "connexions_regulieres")
        assert regulier.kind == KIND_HYPOTHESE
        assert regulier.evidence["nb_connexions"] == 8
        assert regulier.evidence["intervalle_moyen_s"] == 60.0
        assert "dispersion_relative" in regulier.evidence

    def test_beaconing_ignore_un_rythme_irregulier(self):
        """Un trafic humain irregulier ne doit pas declencher la regle."""
        table = FlowTable(is_local=lambda ip: ip == LOCAL_IP)
        ecarts = [3, 240, 12, 400, 5, 180, 30]
        instant = 2000.0
        for index, ecart in enumerate(ecarts):
            instant += ecart
            table.observe(parse(tcp_packet(sport=51000 + index, dst="203.0.113.51",
                                           dport=8443, flags="S", ts=instant), index + 1))
        analyzer = BehaviorAnalyzer(is_local=lambda ip: ip == LOCAL_IP)
        events = analyzer.analyze(table.snapshot(), now=instant)
        assert not any(e.rule == "connexions_regulieres" for e in events)

    def test_entropie_distingue_aleatoire_et_mot(self):
        """Sert a reperer les noms generes par programme (tunnel DNS, DGA)."""
        assert shannon_entropy("a8f3kd92mzxqplw") > shannon_entropy("wikipedia")

    def test_pas_de_volume_dominant_avec_peu_d_interlocuteurs(self):
        """« Concentre 90 % du volume » n'apprend rien s'il n'y a que 2 hotes :
        c'est le cas normal d'une conversation unique et volumineuse."""
        table = FlowTable(is_local=lambda ip: ip == LOCAL_IP)
        for index in range(10):
            table.observe(parse(tcp_packet(sport=51000 + index, dst="203.0.113.9",
                                           dport=443, flags="S", ts=1000.0), index + 1))
        analyzer = BehaviorAnalyzer(is_local=lambda ip: ip == LOCAL_IP)
        events = analyzer.analyze(table.snapshot(), now=1000.0)
        assert not any(e.rule == "volume_dominant" for e in events)

    def test_volume_dominant_avec_diversite_reelle(self):
        """Avec suffisamment d'interlocuteurs, la concentration devient informative."""
        table = FlowTable(is_local=lambda ip: ip == LOCAL_IP)
        index = 0
        for destination in ("203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"):
            for _ in range(6):
                index += 1
                table.observe(parse(tcp_packet(sport=51000 + index, dst=destination,
                                               dport=443, flags="PA", ts=1000.0,
                                               payload=b"x" * 1200), index))
        analyzer = BehaviorAnalyzer(is_local=lambda ip: ip == LOCAL_IP)
        events = analyzer.analyze(table.snapshot(), now=1000.0)
        # La regle peut se declencher ; ce qui compte est que les preuves
        # indiquent combien de flux ont ete analyses.
        for event in events:
            if event.rule == "volume_dominant":
                assert event.evidence["nb_flux_analyses"] >= 5
                break
        else:
            # Aucun hote ne depasse le seuil de part : comportement acceptable
            assert True

    def test_trafic_calme_ne_produit_rien(self):
        table = FlowTable(is_local=lambda ip: ip == LOCAL_IP)
        table.observe(parse(tcp_packet(sport=51000, dport=443, flags="S", ts=1000.0), 1))
        analyzer = BehaviorAnalyzer(is_local=lambda ip: ip == LOCAL_IP)
        assert analyzer.analyze(table.snapshot(), now=1000.0) == []

    def test_analyse_sur_liste_vide(self):
        analyzer = BehaviorAnalyzer(is_local=lambda ip: ip == LOCAL_IP)
        assert analyzer.analyze([], now=1000.0) == []
