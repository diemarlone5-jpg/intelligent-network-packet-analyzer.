# Préparer la soutenance

Ce document sert à **démontrer** l'outil puis à **répondre** aux questions. Il se
lit en deux temps : la démonstration (§2), puis les questions du jury (§3).

---

## 1. Avant de commencer — la checklist

Trois minutes, à faire **avant** d'entrer dans la salle :

1. **Lance l'outil** : double-clique `Demarrer-Packet-Analyzer.bat`
   (ou ouvre `http://127.0.0.1:8000` si une page s'ouvre déjà).
2. **Démarre une capture** et laisse-la tourner pendant que tu parles. Tu veux
   des données réelles à l'écran, pas une page vide.
3. **Ouvre un onglet** sur YouTube ou Wikipédia dans un autre onglet, pour
   générer du trafic pendant la démonstration.

**Si Internet tombe** : l'outil continue de capturer, mais la colonne
*Organisation* restera vide. Ce n'est **pas** une panne — dis-le simplement.

---

## 2. La démonstration — 7 minutes, dans cet ordre

### Étape 1 — Le message central (30 s)

> « Cet outil ne se contente pas d'afficher des paquets. Son but est de faire
> comprendre ce qui se passe sur le réseau. La chaîne est : **CAPTURER →
> ANALYSER → COMPRENDRE → EXPLIQUER**. »

Montre le **Tableau de bord**. Fais remarquer :

- la **courbe d'activité** : « on voit le débit seconde par seconde, les pics » ;
- **qui occupe le réseau** : « c'est calculé en **volume**, pas en nombre de
  paquets — un téléchargement est minoritaire en paquets et majoritaire en
  octets. Compter les paquets ne répond pas à la question. »

### Étape 2 — La matière première (1 min 30)

Va sur **Paquets**. Clique une ligne.

> « Les trois volets se remplissent : la liste, les couches empilées, et le
> contenu brut en hexadécimal. C'est la disposition de Wireshark. »

Puis tape dans le filtre :

```
tcp.port == 443
```

> « Le filtre d'affichage fonctionne comme celui de Wireshark. »

Puis **fais volontairement une faute** :

```
tcp.pot == 443
```

> « Il me dit précisément ce qui ne va pas, **et il garde ma liste à l'écran**.
> Une faute de frappe ne doit jamais passer pour *aucun paquet trouvé* : c'est
> une erreur de conception classique, et elle fait perdre confiance dans tout
> l'affichage. »

*(Ce point marque : peu d'étudiants pensent à ce cas.)*

### Étape 3 — Le cœur du projet (2 min)

Va sur **Communications**. Montre la **carte des relations** en haut.

> « Le centre, c'est ma machine. L'épaisseur des traits suit le volume échangé. »

**Dis la limite toi-même, avant qu'on te la demande** :

> « Cette carte ne montre **que le trafic de cette machine**. On ne voit pas
> celui des autres appareils du réseau : le chiffrement Wi-Fi donne une clé
> différente à chaque appareil, et un commutateur n'envoie une trame qu'au port
> concerné. Pour voir tout le réseau, il faudrait un port miroir sur un
> commutateur administrable — c'est du matériel, pas du logiciel. »

Puis clique **Analyser** sur une communication.

> « Chaque conclusion est séparée en **faits observés** et **interprétations**.
> Le jury peut vérifier : aucun fait n'est inventé, chaque interprétation est
> rattachée à sa justification. »

Ensuite, sur la page d'analyse, clique **Reconstituer l'échange**.

- Sur une communication **chiffrée**, il annonce « contenu chiffré ».
- Sur du **HTTP en clair**, il montre le texte réel.

> « C'est le *Follow TCP Stream* de Wireshark. Et quand le contenu est chiffré,
> il le **dit** — il ne présente pas des octets illisibles comme un bug. »

### Étape 4 — La preuve par un outil externe (1 min)

Sur **Paquets**, clique **PCAP**, puis **Ouvrir un .pcap** et choisis le fichier
que tu viens de télécharger.

> « J'exporte la capture au format PCAP — le format de Wireshark. Je peux la
> rouvrir dans mon outil, ou dans Wireshark. Et le nombre de paquets est
> exactement le même des deux côtés : c'est ce qui prouve que mon analyse repose
> sur les vrais octets, pas sur une reconstruction. »

*(Si Wireshark est installé sur le PC de la salle, ouvre le fichier dedans. C'est
la démonstration la plus convaincante.)*

⚠️ **Une précision à connaître.** L'export porte sur les **5 000 derniers
paquets** conservés en mémoire, pas sur la totalité de la capture. Si ta capture
a dépassé ce nombre, l'outil te le signale à l'écran — et tu peux le dire
toi-même avant qu'on te le demande :

> « L'export est borné à ce que l'outil garde en mémoire. Au-delà, il l'indique
> au lieu de laisser croire que le fichier contient tout. »

**Pour une démonstration propre** : vide la capture juste avant l'étape 4
(*Capture → Vider*), génère une trentaine de paquets, puis exporte. Les deux
comptes seront alors identiques, et c'est vérifiable en direct.

### Étape 5 — Les limites (1 min)

Va sur **Comprendre**, puis **Paramètres**.

> « Deux points d'honnêteté.
>
> **Un** : l'outil ne crie jamais au loup. Un comportement inhabituel n'est pas
> automatiquement une attaque. Chaque événement est classé, et la note de risque
> va de 0 à 100 — jamais une accusation.
>
> **Deux** : la base grossit à chaque capture. La page Paramètres montre
> l'occupation réelle et permet de purger. **Rien n'est effacé sans que
> l'utilisateur le demande.** »

### Étape 6 — La clôture (30 s)

> « 322 tests automatisés, 10 pages, et le code est sur GitHub. L'outil
> fonctionne : je peux capturer, analyser, expliquer, et exporter vers un outil
> reconnu. »

---

## 3. Les questions probables, et quoi répondre

### « C'est quoi la différence avec Wireshark ? »

> « Pour **lire** un paquet, c'est la même chose : liste, couches, hexadécimal,
> filtre d'affichage. Pour **comprendre**, non. Wireshark affiche des données
> brutes et laisse l'utilisateur conclure. Mon outil produit une explication en
> français, sépare les faits des interprétations, et ne prétend jamais qu'un
> comportement inhabituel est une attaque. Wireshark est un outil d'expert ; le
> mien s'adresse à quelqu'un qui doit comprendre. »

### « Comment tu sais qu'un paquet est du HTTPS ? »

> « Par le port : 443 est le port déclaré de HTTPS. C'est une **déduction**, pas
> une certitude — le port peut être changé. C'est pour ça que l'outil écrit
> « probable ». Le niveau de confiance est indiqué dans la page Protocoles, et
> un port inconnu n'est jamais présenté comme connu. »

### « Tu peux voir ce que les gens disent ? »

> « Non, et je ne peux pas. Sur du HTTPS, le contenu est chiffré : on voit *qui*
> parle à *qui*, la taille et le moment, mais pas *ce qui est dit*. L'outil
> l'annonce explicitement quand on lui demande de reconstituer un échange. »

### « Tu vois le trafic des autres appareils du réseau ? »

> « Non. Chaque appareil a sa propre clé de chiffrement Wi-Fi, donc les trames
> des autres me sont illisibles. Et un commutateur n'envoie une trame qu'au port
> concerné. Il faudrait un port miroir sur un commutateur administrable, ou un
> hub. C'est une limite du réseau, pas de mon code — et la carte le dit au lieu
> de le cacher. »

### « Pourquoi Supabase ? »

*(Réponse honnête selon l'état réel du projet.)*

> « Pour archiver les sessions et permettre la consultation depuis un autre
> poste. Le code du mode consultation est écrit et testé ; il n'a pas encore été
> exécuté contre une instance réelle, faute de compte. »

**Ne prétends jamais que ça tourne si ça n'a pas tourné.** Le jury vérifie.

### « Comment tu sais que ça marche ? »

> « 322 tests automatisés. Et pour l'export, la vérification n'est pas la mienne :
> j'écris un fichier PCAP, et c'est **Scapy** — une bibliothèque écrite par
> d'autres — qui le relit. Sur une capture de 964 paquets, mon outil, Scapy et
> mon propre lecteur comptent exactement 964. »

### « C'est sécurisé ? »

> « Les secrets ne sont jamais dans le code : tout passe par un fichier `.env`
> qui n'est pas enregistré dans Git — je peux le montrer. La politique de
> sécurité du navigateur interdit tout script externe, et les actions qui
> modifient quelque chose exigent un jeton. La page Paramètres n'affiche jamais
> une clé, seulement « fournie » ou « absente ». »

### « Qu'est-ce que tu n'as pas fini ? »

**Dis-le franchement.** C'est une force, pas une faiblesse :

> « Trois choses : la connexion à Supabase, qui demande un compte ; l'assistant
> de reformulation par un modèle de langage, qui demande une clé d'API ; et la
> mise en ligne. Les trois sont bloquées par des accès que je n'ai pas, pas par
> du code manquant. »

---

## 4. Les chiffres à retenir

| | |
|---|---|
| **322** | tests automatisés |
| **10** | pages |
| **30+** | routes d'API |
| **5 000** | paquets conservés en mémoire, et donc exportables au maximum |
| **0** | erreur de capture sur les sessions réelles |

Pour la vérification de l'export : capture **moins de 5 000 paquets**, puis
compare. C'est là que les trois comptes (outil, Scapy, lecteur maison) sont
identiques — vérifié à 964 sur une capture de 964.

---

## 5. Le piège à éviter

**Ne dis jamais « ça marche » sans l'avoir montré.**

Ouvre la page, clique, montre le résultat. Une affirmation vérifiée en direct
vaut mieux que dix phrases. Et si quelque chose ne marche pas devant le jury :
dis-le, explique la cause, montre le test qui l'attrape. **Un bug reconnu vaut
mieux qu'un bug caché.**
