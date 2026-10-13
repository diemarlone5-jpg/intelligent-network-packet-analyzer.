# Guide d'utilisation — Intelligent Network Packet Analyzer

Ce guide explique **comment lancer l'outil** et **comment lire ce qu'il affiche**.
Aucune connaissance préalable en réseau n'est nécessaire.

---

## 1. Démarrer l'outil

Double-clique sur :

```
C:\Users\TRUST\dev\packet-analyzer\Demarrer-Packet-Analyzer.bat
```

Si l'icône n'est pas visible sur le bureau, ouvre une fenêtre **Exécuter**
(touche `Windows` + `R`), colle ce chemin et valide :

```
C:\Users\TRUST\dev\packet-analyzer\Demarrer-Packet-Analyzer.bat
```

Ce qui se passe :

1. une **fenêtre noire** s'ouvre — c'est le moteur. **Ne la ferme pas** pendant
   que tu utilises l'outil ;
2. ton navigateur s'ouvre tout seul sur la page d'accueil.

**Pour arrêter :** ferme la fenêtre noire.

> Si tu relances le lanceur alors que l'outil tourne déjà, il ouvre simplement
> la page au lieu de démarrer un second moteur.

L'adresse est toujours **http://127.0.0.1:8000**. Elle ne fonctionne que sur cet
ordinateur : c'est volontaire, l'outil contient ton trafic capturé.

---

## 2. Capturer du trafic

En haut à droite de chaque page :

| Élément | Rôle |
|---|---|
| **Interface réseau** | la carte à écouter. « Wi-Fi » convient dans la plupart des cas |
| **Filtre de capture** | laisse vide pour tout voir. Exemples : `tcp port 443`, `udp` |
| **Démarrer** | lance la capture |
| **Arrêter** | l'arrête et clôture la session |
| **Vider** | efface l'affichage sans arrêter la capture |

La pastille à côté du bouton indique l'état réel : **Capture arrêtée** (gris) ou
**Capture en cours** (vert).

**Pour commencer simplement :** choisis l'interface Wi-Fi, laisse le filtre vide,
clique **Démarrer**, puis ouvre un site dans un autre onglet. Les paquets
apparaissent en une à deux secondes.

---

## 3. Lire chaque page

### La barre de menus

En haut, cinq menus regroupent les actions **par intention** — « qu'est-ce que je
veux faire ? » — alors que le menu de gauche les regroupe **par page**.

| Menu | Ce qu'on y trouve |
|---|---|
| **Fichier** | ouvrir un `.pcap`, exporter en PCAP ou CSV, documentation de l'API |
| **Capture** | démarrer, arrêter, vider |
| **Analyse** | les pages de lecture du trafic |
| **Statistiques** | activité, volumes, qui parle à qui |
| **Aide** | comprendre l'application, paramètres |

Les deux se complètent : on ne cherche pas « la page Protocoles » de la même
façon qu'on cherche « voir ce qui occupe la bande passante ».

---

### 3.1 Tableau de bord — « que se passe-t-il en ce moment ? »

C'est la vue d'ensemble. Tu y trouves :

- le **nombre de paquets**, de communications et d'événements ;
- la **courbe d'activité** : le débit seconde par seconde, sur les 5 dernières
  minutes. Les pics se voient ;
- la **répartition par taille de paquet** : des petites trames de signalisation,
  ou de gros transferts ? Deux problèmes différents ;
- **qui occupe le réseau** : la part de chaque protocole **en volume**, pas en
  nombre de paquets. Un transfert de fichier peut être minoritaire en paquets et
  majoritaire en octets ;
- la **répartition par protocole**, les **ports les plus utilisés** ;
- les **domaines les plus contactés** et les **derniers paquets** capturés.

Commence toujours par ici : si quelque chose t'inquiète, tu sauras sur quelle
page aller creuser.

---

### 3.2 Paquets — « la matière première »

C'est la liste brute, celle qui ressemble à Wireshark. **Aucune interprétation
ici : uniquement des faits observés.**

#### L'écran est découpé en trois volets

| Volet | Ce qu'il montre |
|---|---|
| **haut** | la liste des paquets |
| **milieu** | les **couches** du paquet sélectionné, empilées |
| **bas** | le **contenu brut** en hexadécimal et en caractères |

**Clique une ligne : les trois volets se remplissent sans changer de page.**
C'est exactement le fonctionnement de Wireshark. Les deux volets du bas restent
repliés tant que tu n'as rien choisi — sinon ils prennent la place de la liste.

| Colonne | Ce que ça veut dire |
|---|---|
| **N°** | numéro d'ordre du paquet depuis le début de la capture |
| **Instant** | heure à la milliseconde près |
| **Source** | qui a envoyé — `adresse:port` |
| **Destination** | vers qui — `adresse:port` |
| **Protocole** | le protocole identifié le plus précisément possible |
| **Taille** | taille du paquet en octets |
| **Pays** | pays déclaré de l'adresse **distante** (voir §5) |
| **Organisation** | à qui appartient cette adresse (opérateur, hébergeur…) |
| **Résumé** | description technique du paquet |

#### Le filtre d'affichage

La barre en haut accepte des expressions, comme Wireshark :

| Expression | Ce qu'elle garde |
|---|---|
| `tcp` | tout le TCP (y compris TLS) |
| `dns and size > 200` | le DNS de plus de 200 octets |
| `ip.addr == 8.8.8.8` | tout ce qui concerne cette adresse |
| `tcp.port == 443` | le port 443, en TCP seulement |
| `not arp` | tout **sauf** ARP |
| `contains "telegram"` | ce qui contient ce mot |

Les opérateurs `and`, `or`, `not` et les parenthèses sont acceptés.

**Point important** : si tu te trompes, l'outil te le dit et **garde ta liste à
l'écran**. Une faute de frappe ne doit jamais passer pour « aucun paquet trouvé ».

#### Ouvrir un fichier `.pcap`

Le bouton **Ouvrir un .pcap** analyse une capture enregistrée **comme une
capture en direct** : mêmes colonnes, mêmes filtres, mêmes explications. Pratique
pour analyser un fichier venu d'ailleurs, ou pour rejouer une démonstration.

#### Exporter

- **PCAP** : fichier ouvrable dans Wireshark, pour comparer.
- **CSV** : tableau ouvrable dans Excel.

#### Les adresses soulignées en pointillé

Un téléphone qui n'a pas d'adresse IPv4 à lui passe par une **traduction d'adresse**
(NAT64) : le paquet ne contient pas « 3.173.21.63 », il contient
`64:ff9b::3ad:153f`. Sur un réseau mobile, c'est la **majorité** du trafic.

L'outil affiche donc directement l'adresse **réelle** :

```
64:ff9b::3ad:153f:443   →   affiché :  3.173.21.63:443
```

Le **soulignement pointillé** signale cette transformation : le texte affiché
n'est pas celui qui a circulé sur le fil. Passe la souris dessus pour voir
l'adresse d'origine, telle qu'elle était dans le paquet.

Sans ce décodage, l'outil ne pourrait afficher **aucune organisation** sur ce
trafic : la forme IPv6 n'appartient à personne, donc rien à interroger. Avec lui,
une ligne qui affichait « — » affiche « Amazon », « GitHub » ou « Microsoft ».

**Ce que l'outil refuse de décoder** : les autres formes de traduction (6to4,
Teredo) placent l'adresse ailleurs, parfois en la brouillant. L'outil s'abstient
plutôt que d'afficher une adresse fausse — une adresse fausse serait pire que
pas d'adresse du tout.

---

### 3.3 Communications — « le sens de ce qui se passe »

C'est la page la plus utile pour **comprendre**. Un paquet isolé ne veut rien
dire ; une communication, si.

L'outil regroupe les paquets d'un même échange et t'en donne le sens :

> **Communication chiffrée (TLS/HTTPS) probable vers api.telegram.org**
> La machine locale a pris l'initiative d'établir une communication avec
> 149.154.166.110 sur le port 443. Ce port est généralement utilisé par HTTPS…
> Le contenu échangé est chiffré : on peut mesurer *qui* parle à *qui*, mais pas
> lire *ce qui est dit*.

Chaque colonne :

| Colonne | Signification |
|---|---|
| **Hôte local** | ta machine |
| **Hôte distant** | l'interlocuteur |
| **Service** | le service reconnu (HTTPS, DNS…) puis le protocole |
| **État** | où en est l'échange (en cours, établie, terminée, échec) |
| **Trafic** | nombre de paquets · volume échangé |
| **Lecture** | le nom de domaine, ou le sens (sortant / entrant) |
| **Risque** | note de 0 à 100, jamais une accusation (voir §4) |

Clique sur **Analyser** au bout d'une ligne pour l'explication complète.

#### La carte des relations (en haut de la page)

Le centre est **ta machine**. Chaque trait part vers un interlocuteur, et son
**épaisseur suit le volume échangé** : un trait large, c'est une conversation
volumineuse.

Les interlocuteurs non dessinés sont **comptés et totalisés** en bas de la carte.
Sans ce total, la carte laisserait croire qu'elle montre tout le trafic.

> **Le centre est le seul point de vue que la capture permet de connaître.** On
> ne voit pas le trafic des autres appareils du réseau : le chiffrement Wi-Fi et
> les commutateurs s'y opposent. La carte le dit au lieu de laisser croire le
> contraire.

#### Suivre une conversation

Sur la page d'analyse d'une communication, le bouton **Reconstituer l'échange**
montre le contenu réellement échangé, sens par sens — c'est le *Follow TCP
Stream* de Wireshark.

Trois cas, et l'outil dit toujours dans lequel il se trouve :

| Ce que tu vois | Ce que ça veut dire |
|---|---|
| du **texte lisible** | la conversation est en clair (HTTP, protocole texte) |
| **« contenu chiffré »** | c'est du TLS : on voit *qui* parle, pas *ce qui est dit* |
| **« octets manquants »** | la capture n'a pas vu tous les paquets — signalé, jamais comblé en silence |

---

### 3.4 Événements — « ce qui mérite ton attention »

L'outil y signale les comportements sortant de l'ordinaire. Chaque événement est
classé en trois niveaux :

- **OBSERVATION** — un fait notable, sans jugement ;
- **HYPOTHÈSE** — une piste à vérifier ;
- **ALERTE** — un élément qui mérite vraiment un coup d'œil.

**Un comportement inhabituel n'est pas une attaque.** Un serveur mis à jour, ton
antivirus qui télécharge une mise à jour ou un site qui change d'adresse
produisent tous des événements. C'est le sens de cette page : attirer ton
attention, pas te faire peur.

---

### 3.5 Réseau local — « qui d'autre est là ? »

Cette page liste les **autres appareils** présents sur ton réseau, avec :

- leurs **adresses** (IPv4 et IPv6 regroupées sur une ligne) ;
- leur **adresse matérielle** (elle ne change jamais, contrairement à l'adresse IP) ;
- ce qu'ils **annoncent** : télévision, Chromecast, Spotify, imprimante…

C'est possible parce que ces appareils **diffusent volontairement** ces
informations à tout le réseau pour se faire connaître.

**Annoncer ≠ rechercher.** Un appareil qui *annonce* Spotify en propose ; un
appareil qui le *recherche* a simplement Spotify ouvert. L'outil distingue les
deux, parce que confondre les deux inverserait la vérité.

---

### 3.6 Comprendre et Paramètres — « comment ça marche, et où j'en suis »

**Comprendre** explique le fonctionnement de l'outil lui-même : c'est le support
direct de la soutenance.

**Paramètres** répond à trois questions :

| Section | Ce qu'elle montre |
|---|---|
| Configuration en vigueur | mode, interface, base de données, enrichissement |
| Services | ce qui répond et ce qui ne répond pas |
| **Données conservées** | la taille de la base, et de quoi la réduire |

**Aucun secret n'est affiché** : les clés apparaissent comme « fournie » ou
« absente », jamais en clair. Une page de réglages ne doit pas devenir un moyen
de lire les secrets d'une installation.

#### La base grossit à chaque capture

Une capture qui tourne enregistre les sessions, les communications et les
paquets, et **rien n'est supprimé automatiquement**. Au bout de plusieurs heures,
la base peut occuper plusieurs centaines de mégaoctets.

La page Paramètres le signale et propose une purge : tu choisis **combien de
sessions récentes garder**, et l'outil supprime les autres. L'option *Compacter*
récupère ensuite l'espace disque — sans elle, supprimer des lignes ne réduit pas
le fichier.

**Rien n'est effacé sans que tu le demandes.**

---

### 3.7 Protocoles — « le dictionnaire »

La liste des ports et protocoles que l'outil sait reconnaître, avec leur
signification et leur niveau de confiance. Sers-t'en pour vérifier une
affirmation : si un port n'y figure pas, l'outil ne prétendra pas le connaître.

---

### 3.8 Historique — « ce qui s'est passé avant »

Les sessions précédentes : quand elles ont tourné, sur quelle interface, avec
quel volume, et les communications enregistrées.

Un analyseur réseau n'a de valeur que si l'on peut **rejouer** une capture.

---

## 4. Comment lire le risque

L'outil calcule une note de 0 à 100. **Ce n'est pas un verdict.**

- **0–24** — rien d'inquiétant ;
- **25–49** — à connaître, sans plus ;
- **50–74** — mérite un coup d'œil ;
- **75–100** — à examiner sérieusement.

Une note élevée veut dire « cette communication présente des caractéristiques qui
sortent de l'ordinaire », jamais « tu es attaqué ». Le détail des raisons est
toujours donné, pour que tu puisses juger toi-même.

---

## 5. Lire les chiffres sans se tromper

Trois pièges dans lesquels il est facile de tomber :

**« Pays : États-Unis » ne veut pas dire qu'une personne est aux États-Unis.**
Cela veut dire que l'adresse IP appartient à un bloc enregistré dans ce pays.
Un serveur d'hébergement, un CDN ou un VPN fausse complètement cette lecture.

**« — » dans la colonne Pays signifie « pas encore identifié », pas « anonyme ».**
L'identification se fait en arrière-plan, une adresse à la fois. Le compteur en
haut de la page indique combien restent à traiter.

**On ne voit pas le contenu des échanges.** La majorité du trafic est chiffrée
(TLS). L'outil en déduit le site visité à partir du nom que le client annonce en
clair au début de la connexion — jamais ce qui est échangé ensuite.

---

## 6. Ce que l'outil ne peut pas faire

**Il ne voit pas les conversations des autres appareils du réseau.** Sur un
Wi-Fi chiffré, chaque machine chiffre ses trames avec sa propre clé ; sur un
réseau à commutateur, une trame ne part que vers son destinataire. Aucun logiciel
ne contourne cela — **Wireshark, sur le même ordinateur et le même réseau, voit
exactement la même chose.**

Ce que l'on voit des autres appareils, c'est ce qu'ils **diffusent
volontairement** à tout le réseau (voir la page *Réseau local*). C'est suffisant
pour savoir qu'une télévision, un Chromecast ou un appareil utilisant Spotify est
présent, mais pas pour lire son trafic.

Pour aller plus loin, il faudrait du matériel : mode moniteur (carte compatible,
droits administrateur), port miroir sur un commutateur administrable, ou un
concentrateur réseau.

---

## 7. En cas de problème

| Symptôme | Cause probable | Solution |
|---|---|---|
| La page ne s'ouvre pas | le moteur n'est pas démarré | relance le `.bat` |
| « Aucun paquet capturé » | la capture n'est pas lancée | clique sur **Démarrer** |
| « Capture impossible » | droits insuffisants | vérifie que Npcap est installé |
| La liste ne bouge pas | interface réseau mal choisie | essaie « Wi-Fi » ou une autre interface |
| L'outil semble lent | trafic très dense | utilise le filtre de capture (ex. `tcp port 443`) |

---

*Intelligent Network Packet Analyzer — SPRINT PYTHON 3, HACKTUALIZ ACADEMY CÔTE D'IVOIRE.*
