# Intelligent Network Packet Analyzer

**Capturer → Analyser → Comprendre → Expliquer.**

Un analyseur de paquets réseau qui ne se contente pas d'afficher des données
techniques : il les traduit en explications compréhensibles, en séparant
toujours ce qui a été **observé** de ce qui a été **déduit**.

Projet réalisé dans le cadre du **SPRINT PYTHON 3 — HACKTUALIZ ACADEMY CÔTE D'IVOIRE**.

---

## 1. Présentation

### Le problème que cet outil résout

Les analyseurs de trafic classiques affichent des informations brutes. Pour une
personne qui débute en cybersécurité, voir ceci ne permet pas de comprendre ce
qui se passe :

```
TCP 192.168.1.15:52341 → 142.x.x.x:443  Flags: SYN
```

Ce système fait le travail inverse. À partir des mêmes paquets, il produit :

> **Communication chiffrée (TLS/HTTPS) probable vers api.telegram.org**
> La machine locale (192.168.1.22) a pris l'initiative d'établir une
> communication avec 149.154.166.110, sur le port 443. Ce port est généralement
> utilisé par le service HTTPS… Le contenu échangé est chiffré : on peut mesurer
> le volume, mais pas lire les données. Le nom de domaine « api.telegram.org » a
> toutefois été observé en clair lors de la négociation.

### La règle de conception centrale

**Aucune hypothèse n'est jamais présentée comme une certitude.** Chaque analyse
est découpée en trois zones distinctes :

| Zone | Contenu | Exemple |
|---|---|---|
| **Faits observés** | ce qui est mesuré dans les paquets | « port de destination = 443 » |
| **Interprétations** | ce que cela signifie habituellement, avec justification et niveau de confiance | « le port 443 est généralement associé à HTTPS » |
| **Réserves** | ce que l'observation ne permet **pas** de conclure | « le début de la connexion n'a pas été observé » |

Les détections suivent la même discipline : **OBSERVATION** (fait mesuré),
**HYPOTHÈSE** (lecture probable), **ALERTE** (exposition documentée et
vérifiable). Un comportement inhabituel n'est jamais présenté comme une attaque.

---

## 2. Fonctionnalités

- **Capture du trafic réel** — démarrage, arrêt, choix de l'interface, filtre
  d'expression (BPF).
- **Analyse des paquets** — source, destination, protocole, ports, taille,
  horodatage, drapeaux TCP, TTL, couches empilées.
- **Regroupement en communications** — les paquets d'une même conversation sont
  réunis ; durée, volume par sens, état, nombre de paquets.
- **Suivi des étapes d'une connexion** — ouverture, acceptation, établissement,
  échange de données, fermeture, refus, réinitialisation, inactivité.
- **Extraction du nom de domaine sans déchiffrement** — SNI du *ClientHello* TLS,
  en-tête `Host` des requêtes HTTP en clair, nom interrogé dans une requête DNS.
- **Moteur d'explication** — texte en langage humain, faits, interprétations
  justifiées, réserves.
- **Indicateur de risque par communication** — score de 0 à 100, chaque point
  attribué étant rattaché au fait observé qui le justifie.
- **Détection comportementale** — 11 règles (voir §7).
- **Enrichissement par API externe** — pays, opérateur, réseau d'une adresse IP.
- **Résumé de session en langage humain** — composé localement par défaut ; une
  couche IA peut le reformuler, sous contrôle (§13).
- **Interface web** — tableau de bord, paquets, communications, détail d'analyse,
  événements, base de connaissance des protocoles, historique, page de
  compréhension.
- **État des services** — l'utilisateur voit immédiatement quelle dépendance ne
  répond pas, et que l'analyse continue malgré tout.
- **Historique** — SQLite en local, **Supabase** en ligne.

---

## 3. Architecture

### Le trajet d'une donnée

```
   ┌──────────────┐
   │   CAPTURER   │  Scapy + Npcap / libpcap — fil d'exécution dédié
   └──────┬───────┘
          │ paquet brut
   ┌──────▼───────┐
   │   ANALYSER   │  parser.py — paquet → enregistrement plat (aucune interprétation)
   └──────┬───────┘
          │ PacketRecord
   ┌──────▼───────┐
   │   REGROUPER  │  flows.py — paquets → communications + machine à états TCP
   └──────┬───────┘
          │ Flow
   ┌──────▼───────┐
   │  COMPRENDRE  │  protocols.py — base de connaissance ports / protocoles
   └──────┬───────┘
          │
   ┌──────▼───────┐
   │  EXPLIQUER   │  explain.py — faits / interprétations / réserves / texte
   └──────┬───────┘
          │
   ┌──────▼───────┐
   │   DÉTECTER   │  detectors.py — 10 règles comportementales
   └──────┬───────┘
          │
   ┌──────▼───────┐
   │   ENRICHIR   │  ip_intel.py — API externe + cache
   └──────┬───────┘
          │
   ┌──────▼───────┐
   │   STOCKER    │  sqlite_repo.py  /  supabase_repo.py
   └──────┬───────┘
          │
   ┌──────▼───────┐
   │   EXPOSER    │  FastAPI — pages HTML, API JSON, WebSocket temps réel
   └──────────────┘
```

### Comment les parties communiquent

Chaque couche ne connaît que la précédente. Le **moteur** (`app/engine.py`) est
le seul point de rencontre : il possède le parseur, la table des flux, le
détecteur et l'explicateur, et il expose des instantanés. L'interface web ne
contient **aucune logique d'analyse** — elle affiche ce que le moteur lui donne.
C'est ce qui permet de tester l'analyse sans lancer de serveur.

### Structure du projet

```
packet-analyzer/
├── run.py                      point d'entrée
├── app/
│   ├── models.py               PacketRecord, Flow, Event, IPIntel
│   ├── config.py               configuration depuis l'environnement
│   ├── engine.py               orchestration + statistiques
│   ├── capture/
│   │   ├── interfaces.py       détection des interfaces Npcap + noms lisibles
│   │   └── agent.py            capture démirable / arrêtable
│   ├── analysis/
│   │   ├── parser.py           paquet → enregistrement plat + SNI / Host / DNS
│   │   ├── protocols.py        base de connaissance (58 ports, 10 protocoles)
│   │   ├── flows.py            regroupement + machine à états TCP
│   │   ├── explain.py          moteur d'explication
│   │   ├── risk.py             indicateur de risque justifié
│   │   └── detectors.py        détection comportementale
│   ├── intelligence/           résumé et reformulation sous contrôle
│   │   ├── context.py          contexte fermé (seule matière autorisée)
│   │   └── summarizer.py       fournisseurs + vérificateur anti-invention
│   ├── enrichment/ip_intel.py  API externe + cache
│   ├── storage/                base.py, sqlite_repo.py, supabase_repo.py,
│   │                           composite_repo.py
│   └── web/                    app.py, routes.py, api.py, templates/, static/
├── schema/supabase.sql         schéma PostgreSQL commenté
├── tests/                      126 tests automatisés
├── Dockerfile · render.yaml    déploiement
└── .env.example                modèle de configuration
```

---

## 4. Technologies, et pourquoi

| Choix | Justification |
|---|---|
| **Python 3.11+** | écosystème réseau et analyse de données le plus complet |
| **Scapy** | seule bibliothèque Python mature capable de disséquer et de capturer du trafic réel avec une finesse de couche 2 à 7 |
| **Npcap** (Windows) | pilote de capture ; Scapy s'y appuie. Il doit être installé en cochant « autoriser les utilisateurs non administrateurs à capturer » |
| **FastAPI** | API REST et **WebSocket** dans le même cadre, documentation OpenAPI générée automatiquement, validation des entrées par typage |
| **Jinja2 + CSS/JS sans dépendance** | aucune chaîne de compilation : le projet se lance partout, et l'interface reste compatible avec une politique de sécurité stricte |
| **SQLite** | historique local, sans serveur, toujours disponible même hors ligne |
| **Supabase** | exigé par le cahier des charges : base joignable en HTTP, indispensable pour qu'une instance **déployée** puisse lire un historique produit **en local** |
| **httpx** | appels à l'API externe avec délais d'attente maîtrisés |

**Choix écarté : les microservices.** Le volume et la complexité du projet ne les
justifient pas. Une architecture en couches, testable et lisible, a été
préférée ; c'est aussi ce qui permet de répondre aux questions de défense
technique sur chaque module.

---

## 5. API externe

**Service retenu : `ipwho.is`** — avec `ip-api.com` en secours.

| Question | Réponse |
|---|---|
| Pourquoi cette API ? | HTTPS natif (nos adresses d'observation ne circulent pas en clair), **aucune clé d'API** (donc aucun secret à protéger), réponse JSON exploitable, quota annoncé suffisant pour un usage pédagogique |
| Quelles données sont envoyées ? | **Uniquement l'adresse IP distante** déjà observée dans le trafic. Jamais le contenu d'un paquet, jamais une donnée locale |
| Que renvoie-t-elle ? | pays, ville, opérateur, organisation, numéro de système autonome |
| Comment le résultat est-il utilisé ? | ajouté à la section **faits**, marqué comme provenant d'une source externe, avec le nom de la source |
| Ce que cela ne fait **pas** | ces données ne servent jamais à déduire une intention. Le pays d'une adresse ne prouve rien sur son propriétaire |
| Adresses privées | **aucun appel externe** : leur nature est déterminée localement (RFC 1918 / 6890) |
| Panne de l'API | l'application continue de fonctionner, l'erreur est consignée et affichée ; le cache local évite de redemander une adresse déjà connue |

---

## 6. Base de données

Cinq tables, dont la raison d'être est documentée dans `schema/supabase.sql`.

| Table | Une ligne = | Pourquoi elle existe |
|---|---|---|
| `capture_sessions` | une campagne d'observation | sans elle, impossible de comparer deux analyses ou de savoir à quelle capture appartient une communication |
| `flows` | une **communication** (pas un paquet) | c'est l'unité qui a du sens pour un analyste ; le volume stocké est divisé par plusieurs milliers |
| `events` | un fait remarquable, avec ses preuves chiffrées | permet de rejouer une détection et de justifier chaque alerte |
| `packets` | un paquet brut, **échantillon plafonné** | sert à la vérification et à la démonstration, pas à l'analyse de masse |
| `ip_intel` | une adresse IP enrichie | respecte les quotas de l'API et rend l'application utilisable hors ligne |

**Relations :** `flows`, `events` et `packets` référencent `capture_sessions`
avec suppression en cascade. `ip_intel` est indépendante : c'est un cache.

**Écriture :** SQLite est toujours alimenté ; si Supabase est activé, les mêmes
données y sont poussées en mode *upsert*. En cas de panne réseau, l'application
continue en local et retente la connexion périodiquement — une coupure
d'Internet n'interrompt jamais une capture.

---

## 7. Risque / statut

Le cahier des charges demande, dans la vue détaillée, quatre éléments :
informations techniques, analyse, explication humaine, **risque / statut**.

Le score (0 à 100) n'est **pas** une probabilité d'attaque : c'est un indicateur
d'attention. Il répond à « cette communication mérite-t-elle que je m'y
arrête ? », pas à « est-ce une attaque ? ». Chaque point attribué est affiché
avec le fait qui le justifie.

| Élément observé | Points | Pourquoi |
|---|---|---|
| Service documenté comme sensible, en entrée | 25 | exposition vérifiable de la surface d'attaque |
| Service sensible contacté en sortie | 12 | usage à confronter à l'usage attendu du poste |
| Protocole en clair (Telnet, FTP, HTTP…) | 15 | identifiants potentiellement lisibles |
| Connexion entrante depuis une adresse publique | 10 | provenance hors du réseau local |
| Connexion refusée (RST observé) | 10 | révèle une recherche de service inexistant |
| Volume important vers un hôte non identifié | 10 | transfert sans destination nommée |
| Port de service non documenté | 5 | l'application ne peut pas l'interpréter |
| Trafic chiffré sans nom de domaine annoncé | 5 | destination indéterminée |
| Retransmissions nombreuses | 5 | réseau dégradé ou interférence |

Tranches : **faible** (0–14), **modéré** (15–34), **élevé** (35–59),
**critique** (60+).

> Un score élevé sur une communication parfaitement légitime est normal : un
> serveur SSH administré volontairement depuis Internet est à la fois légitime
> et digne d'attention. C'est pourquoi les raisons sont toujours affichées.

---

## 8. Règles de détection

Seuils définis dans `app/analysis/detectors.py`, tous modifiables.

| Règle | Type | Ce qu'elle mesure |
|---|---|---|
| `destinations_multiples` | Hypothèse | une machine contacte ≥ 15 destinations distinctes en 60 s |
| `balayage_entrant` | Hypothèse | ≥ 20 ports locaux distincts sollicités par la même source |
| `service_sensible_joignable` | **Alerte** | un service documenté comme sensible (Telnet, RDP, SMB, Redis…) accepte une connexion entrante |
| `contact_port_sensible` | Observation | une machine locale contacte un port sensible |
| `connexions_refusees_repetees` | Hypothèse | ≥ 8 connexions rejetées (RST) vers la même cible |
| `ouvertures_sans_reponse` | Hypothèse | ≥ 15 communications ouvertes sans réponse, dont certaines retentées |
| `volume_dns` | Hypothèse | ≥ 40 requêtes DNS, dont des noms à forte entropie (tunnel DNS / DGA possible) |
| `volume_dominant` | Observation | un hôte concentre ≥ 35 % du volume (à partir de 5 flux et 50 Ko) |
| `connexions_regulieres` | Hypothèse | ≥ 5 connexions à intervalle régulier (dispersion < 30 %) — rythme de balise |
| `ecart_comportement` | Observation | le nombre de destinations dépasse 3× la moyenne observée sur la session |
| `protocole_en_clair` | Observation | échanges en HTTP, FTP, Telnet, POP3… non chiffrés |

Chaque événement contient une clé `evidence` avec les **valeurs réellement
mesurées** (nombre observé, seuil appliqué, exemples). C'est ce qui permet de
répondre à la question « quelle information est observée, et laquelle est
déduite ? ». Un délai anti-répétition évite qu'une même règle inonde l'écran.

---

## 9. Installation

### Prérequis

- **Python 3.11 ou supérieur**
- **Npcap** (Windows) ou **libpcap** (Linux/macOS) pour la capture réelle
  - Sur Windows : installez Npcap depuis <https://npcap.com> et **cochez
    « Allow non-admin users to capture »** — sans cette case, la capture exige
    les droits administrateur.

### Mise en place

```bash
git clone https://github.com/<votre-compte>/packet-analyzer.git
cd packet-analyzer

# Environnement virtuel + dépendances (uv recommandé)
uv venv
uv pip install -r requirements.txt
# ou, sans uv :
# python -m venv .venv && .venv/Scripts/activate   (Windows)
# python -m venv .venv && source .venv/bin/activate (Linux/macOS)
# pip install -r requirements.txt
```

### Configuration

```bash
cp .env.example .env
```

Puis, dans `.env`, renseignez au minimum :

| Variable | Rôle |
|---|---|
| `SECRET_KEY` | signature des sessions — générer avec `python -c "import secrets;print(secrets.token_hex(32))"` |
| `APP_MODE` | `local` (capture active) ou `cloud` (consultation seule) |
| `SUPABASE_URL` / `SUPABASE_SERVICE_KEY` | laisser vide pour démarrer sans Supabase |
| `SUPABASE_ENABLED` | `true` une fois les clés renseignées |

> ⚠️ **Le fichier `.env` ne doit jamais être commité.** Il est déjà listé dans
> `.gitignore`. La clé `SUPABASE_SERVICE_KEY` contourne les règles de sécurité
> de la base : elle reste côté serveur, jamais dans une page web.

### Mise en place de Supabase

1. Créez un projet sur <https://supabase.com>.
2. Ouvrez **SQL Editor**, collez le contenu de `schema/supabase.sql`, exécutez.
3. **Project Settings → API** : copiez `Project URL` et la clé `service_role`.
4. Renseignez-les dans `.env` puis passez `SUPABASE_ENABLED=true`.

---

## 10. Utilisation

```bash
python run.py                       # http://127.0.0.1:8000
python run.py --reload              # développement, rechargement automatique
python run.py --mode cloud          # consultation d'historique seulement
python run.py --host 0.0.0.0        # exposer sur le réseau local
```

Puis, dans le navigateur :

1. **Tableau de bord** — vérifiez que l'interface réseau proposée est la bonne
   (l'application choisit celle qui porte la route par défaut vers Internet).
2. Cliquez sur **Démarrer**. Les paquets défilent en temps réel.
3. Ouvrez **Communications**, cliquez sur **Analyser** sur une ligne.
4. La page d'analyse présente l'explication, les faits, les interprétations,
   les réserves, puis l'enrichissement externe.
5. **Événements** liste les comportements détectés, filtrables par type.

Un filtre de capture est disponible (syntaxe BPF) : `tcp port 443`,
`not port 22`, `host 192.168.1.1`…

---

## 11. Scénarios de test

### Tests automatisés

```bash
python -m pytest -q          # 98 tests, aucune capture réseau requise
python -m pytest -v          # détail par test
```

Les paquets des tests sont **construits à la main** : la suite est donc
reproductible sur une machine sans Npcap.

**Deux tests de non-régression** reproduisent des bugs réellement rencontrés :

- `test_page_rendue` — l'ordre des intergiciels ASGI faisait échouer **toutes**
  les pages en erreur 500 ;
- `test_stats_serialisables` — un objet d'interface Scapy non converti en chaîne
  cassait la sérialisation JSON de `/api/stats`.

### Scénarios manuels de vérification

| # | Ce qu'on provoque | Ce que l'application doit montrer |
|---|---|---|
| 1 | Visite d'un site HTTPS | communication « chiffrée (TLS/HTTPS) probable », **nom de domaine extrait du SNI**, contenu annoncé comme illisible |
| 2 | Visite d'un site en HTTP (`neverssl.com`) | protocole HTTP reconnu, en-tête `Host` extrait, avertissement « contenu en clair » |
| 3 | `ping 8.8.8.8` | messages ICMP, absence de port, explication « message de contrôle » |
| 4 | Résolution DNS | requête nommée, rôle du DNS expliqué, port 53 en UDP |
| 5 | Connexion à un port fermé | état « refusée par le destinataire », RST compté, explication du refus |
| 6 | Fermeture normale d'une connexion | état « fermée », deux FIN comptés |
| 7 | Connexion à un service sensible local | **ALERTE** « service sensible joignable » avec la provenance |
| 8 | Nombreuses destinations en peu de temps | **HYPOTHÈSE** « balayage possible », avec le seuil et le nombre mesuré |
| 9 | Coupure d'Internet pendant l'enrichissement | analyse intacte, erreur consignée, cache local utilisé |
| 10 | Interface invalide ou filtre BPF invalide | message compréhensible, capture non démarrée, pas de trace technique |
| 11 | Base Supabase injoignable | bascule en local, avertissement affiché, capture non interrompue |
| 12 | Arrêt de la capture puis consultation de l'historique | session enregistrée, communications et événements relus depuis la base |
| 13 | Consultation de la page **Protocoles** | les 58 services documentés sont listés avec leur rôle, leur justification et un niveau de confiance ; les filtres « à surveiller » et « en clair » fonctionnent |
| 14 | Communication vers un service sensible (SSH, RDP…) | score de risque élevé, chaque point accompagné du fait observé qui le justifie |
| 15 | Clic sur **Actualiser** dans « Résumé de la session » | résumé en langage humain cohérent avec les chiffres affichés, mention de la source et du nombre d'entités autorisées |
| 16 | `AI_ENABLED=true` sans clé d'API | le résumé par règles reste affiché, aucun appel réseau n'est tenté |
| 17 | Panneau « État des services » | chaque dépendance montre son état réel ; Supabase désactivé est signalé sans être présenté comme une panne |
| 18 | Trafic IPv6 sortant | la communication est bien qualifiée de **sortante** et non d'entrante (les adresses IPv6 de la machine sont reconnues) |

---

## 12. Déploiement

### Point essentiel : deux modes

La **capture réseau exige un accès au pilote de la machine**. Un hébergeur en
ligne n'a ni Npcap ni carte réseau à observer. Le projet assume donc deux modes,
et c'est ce qui le rend à la fois honnête et déployable :

- **mode local** — capture active, sur la machine de l'utilisateur ;
- **mode cloud** — consultation de l'historique enregistré dans Supabase.

### Docker

```bash
docker build -t packet-analyzer .
docker run -p 8000:8000 --env-file .env packet-analyzer
```

### Render

Le fichier `render.yaml` décrit le service. Dans le tableau de bord Render,
renseignez `SUPABASE_URL` et `SUPABASE_SERVICE_KEY` comme variables secrètes.
La vérification de santé utilise `/api/status`.

---

## 13. Intelligence artificielle

Le cahier des charges autorise l'IA mais interdit qu'elle devienne le cerveau du
système. L'implémentation prend cette contrainte au sérieux, en trois temps.

### 1. Le programme produit d'abord des données structurées et vérifiables

Le moteur calcule tout : communications, états, services, risque, événements.
Un **contexte fermé** (`app/intelligence/context.py`) est ensuite construit, qui
ne contient que ces valeurs. Aucun paquet brut ne lui est transmis.

### 2. Une couche d'intelligence reformule ce contexte

Deux fournisseurs interchangeables :

| Fournisseur | Configuration | Comportement |
|---|---|---|
| **règles** (défaut) | aucune | résumé composé localement, déterministe, aucun appel réseau, aucun secret |
| **openai** | `AI_ENABLED=true` + `AI_API_KEY` | appel à toute API compatible OpenAI (OpenAI, Groq, Ollama, LM Studio) |

Le mode par défaut ne requiert **aucune clé** : la fonctionnalité marche
immédiatement, et l'IA est un enrichissement facultatif.

### 3. La réponse est vérifiée après coup

C'est le point le plus important. La consigne donnée au modèle (« ne cite aucune
adresse ni domaine absent du contexte ») ne suffit pas : un modèle peut
halluciner. Le texte produit est donc **analysé** (`Summarizer._validate`) :

- toutes les adresses IP et tous les noms de domaine cités sont extraits ;
- chacun doit exister dans le contexte fourni ;
- si une seule entité est absente, **la génération est rejetée** et le résumé
  par règles est affiché à la place, avec un message expliquant pourquoi.

Autrement dit, la garantie « aucune invention » n'est pas une intention
déclarée : c'est un contrôle exécuté à chaque appel, et couvert par des tests
(`tests/test_intelligence.py`).

L'interface affiche systématiquement, sous le résumé, la source utilisée et le
nombre d'entités autorisées — l'utilisateur peut donc constater que rien n'a
été ajouté.

---

## 14. Sécurité

- **Aucun secret dans le code** — tout vient de variables d'environnement.
  `.env` est ignoré par Git, `.env.example` est fourni à la place.
- **Clé `service_role` uniquement côté serveur** — jamais dans une page web.
- **Protection CSRF** — toute action modifiant l'état (démarrer, arrêter,
  vider) exige un jeton de session, comparé en temps constant. Sans lui : `400`.
- **En-têtes de sécurité** sur chaque réponse : `Content-Security-Policy`
  stricte (`script-src 'self'`, aucun script en ligne), `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`,
  HSTS en HTTPS.
- **Aucune injection possible depuis les données capturées** — l'interface
  construit chaque élément du DOM avec `textContent`, jamais avec `innerHTML`.
  Un nom de domaine hostile reste donc du texte.
- **Validation des entrées** — les paramètres d'API sont bornés (`limit` entre 1
  et 2000) ; une valeur invalide renvoie `422`, jamais une valeur par défaut
  silencieuse.
- **Erreurs sans fuite** — aucune trace technique, chemin ou secret n'apparaît
  dans une page. Le détail va dans le journal du serveur.
- **Démarrage refusé en production** si `SECRET_KEY` est absente ou trop courte,
  ou si une fonctionnalité activée n'a pas ses clés.

---

## 15. Limites

Ce que l'analyseur **ne sait pas faire** — ces limites sont aussi affichées dans
la page « Comprendre » de l'application :

- **Il ne déchiffre rien.** Le contenu d'une session TLS reste illisible. Seuls
  le volume, le rythme et parfois le nom du serveur (SNI) sont observables.
- **Il ne voit que le trafic de sa propre machine.** Depuis un poste classique,
  une communication entre deux autres machines n'est pas visible (il faudrait un
  port miroir ou un point d'accès).
- **Il ne conserve pas le contenu des paquets.** L'analyse porte sur les en-têtes
  et sur ce que le client annonce en clair.
- **Un port est une convention, pas une preuve.** Un service peut écouter sur
  n'importe quel port ; l'application le rappelle dans chaque analyse.
- **Une anomalie statistique n'est pas une attaque.** Chaque règle affiche ses
  chiffres pour que l'utilisateur juge lui-même.
- **La détection de retransmissions est approximative** : elle compare les
  numéros de séquence, ce qui n'est pas une analyse fine de la fenêtre TCP.
- **Les seuils sont fixes.** Ils ne sont pas appris automatiquement — la règle
  d'écart au comportement habituel utilise une moyenne glissante, mais reste
  rudimentaire.
- **Pas de reconstruction de flux applicatif** : les fichiers transférés ne sont
  ni reconstitués ni exportés ; aucun export PCAP n'est proposé.
- **Le score de risque suit un barème fixe.** Il n'est pas appris. Il indique ce
  qui mérite un coup d'œil, jamais ce qui est malveillant.
- **Le résumé automatique reste descriptif.** Il décrit ce qui a été observé ; il
  ne diagnostique pas une attaque et ne propose pas de remédiation.

---

## 16. Défense technique — questions probables

<details>
<summary><strong>Qu'est-ce qu'un paquet ?</strong></summary>

Une tranche de données à laquelle on a ajouté les informations nécessaires pour
l'acheminer : qui envoie, à qui, quel protocole, et comment la réassembler. Une
communication est une suite de paquets, pas un paquet isolé — c'est pourquoi le
projet regroupe les paquets en « communications » avant de les expliquer.

</details>

<details>
<summary><strong>Pourquoi Scapy ?</strong></summary>

C'est la seule bibliothèque Python mature qui dissèque le trafic de la couche 2
à la couche 7 et permet d'accéder aux octets bruts — indispensable pour lire un
SNI TLS, un nom DNS ou un en-tête HTTP sans rien déchiffrer.

</details>

<details>
<summary><strong>Comment votre application identifie-t-elle une communication ?</strong></summary>

Par le quintuplet (protocole, IP, port, IP, port) rendu **bidirectionnel** : les
deux sens de l'échange appartiennent au même flux, car une conversation
appartient aux deux machines. Le premier paquet observé fixe l'initiateur, ce
qui permet ensuite de compter séparément les octets dans chaque sens.

</details>

<details>
<summary><strong>Comment évitez-vous que votre système invente une conclusion ?</strong></summary>

Trois mécanismes. D'abord, le texte est assemblé **uniquement** à partir des
faits et des interprétations calculés — jamais à partir d'autre chose. Ensuite,
chaque interprétation porte sa **justification** et un **niveau de confiance**,
dégradé lorsque l'information est incomplète. Enfin, chaque analyse affiche une
section **réserves** qui énonce explicitement ce qui n'a pas été observé.

Pour la couche IA, la même exigence est appliquée par un contrôle exécutable :
le modèle ne reçoit qu'un contexte fermé, et sa réponse est analysée. Toute
adresse IP ou nom de domaine cité qui n'existe pas dans les observations fait
rejeter la génération au profit du résumé déterministe. La consigne « n'invente
rien » devient donc une garantie vérifiable, pas une promesse.

</details>

<details>
<summary><strong>Comment votre application identifie-t-elle le sens d'une communication ?</strong></summary>

D'abord par le **SYN réellement observé** : son port de destination est, par
définition, le port du service, et son émetteur est l'initiateur. Si la capture
a commencé en cours de connexion, aucun SYN n'existe : on retombe alors sur la
position des ports (un service écoute sur un port bas, un client utilise un port
élevé), et l'application **l'annonce explicitement** dans la justification, avec
une confiance réduite et une réserve affichée.

Pour UDP, qui n'établit pas de connexion, la notion même de SYN n'existe pas :
l'application le dit au lieu de parler d'une ouverture qu'elle n'aurait pas vue.

</details>

<details>
<summary><strong>Quelle information est réellement observée, et quelle information est déduite ?</strong></summary>

Chaque fait affiché porte son origine. Les valeurs marquées « observation
directe du paquet » viennent des octets lus (adresses, ports, drapeaux, taille).
Celles marquées « compteur du flux » résultent d'un comptage effectué par
l'application sur plusieurs paquets. Celles marquées « API externe » viennent de
la source d'enrichissement. Enfin, le port du service peut être marqué
« déduit » lorsque la capture a commencé trop tard — et dans ce cas, la
confiance globale ne peut pas être maximale.

</details>

<details>
<summary><strong>Que se passe-t-il lors d'une requête API ?</strong></summary>

L'application envoie une adresse IP à `ipwho.is` en HTTPS, avec un délai
d'attente de 6 secondes. La réponse JSON est convertie en objet `IPIntel`, mise
en cache en base, puis ajoutée aux faits de l'analyse. Si la réponse est
invalide, si le quota est atteint ou si le réseau tombe, l'erreur est consignée
et l'analyse continue sans ces informations — jamais d'échec bloquant.

</details>

<details>
<summary><strong>Pourquoi Supabase plutôt qu'une base locale ?</strong></summary>

Parce que la capture ne peut avoir lieu que sur la machine locale, alors que
l'application doit être consultable en ligne. Il faut donc une base joignable
par HTTP. Supabase fournit cette API immédiatement, et le même jeu de tables
sert aux deux modes.

</details>

<details>
<summary><strong>Comment gérez-vous les erreurs ?</strong></summary>

À chaque frontière. Un paquet illisible est compté et ignoré, sans arrêter la
capture. Une interface indisponible produit un message compréhensible plutôt
qu'une trace technique. Une base injoignable fait basculer l'application en
local. Une API externe muette retire simplement l'enrichissement. L'utilisateur
ne voit jamais de pile d'appels.

</details>

---

## 17. Auteur et contexte

Projet réalisé dans le cadre du **SPRINT PYTHON 3** de
**HACKTUALIZ ACADEMY CÔTE D'IVOIRE**.

> **Autorisation.** Cet outil n'observe que le trafic de la machine sur laquelle
> il est lancé. Toute capture doit être effectuée dans un environnement où vous
> y êtes autorisé : votre propre poste, ou un réseau dont vous avez la
> responsabilité.

Licence : MIT.
