/* ==========================================================================
   Intelligent Network Packet Analyzer — logique de l'interface

   Regles respectees :
     - aucun gestionnaire en ligne (onclick="...") : tout passe par
       addEventListener, ce qui est compatible avec la politique de securite
       stricte du serveur (script-src 'self', pas d'inline) ;
     - aucune donnee serveur n'est injectee avec innerHTML : tout element
       affiche est construit avec textContent, ce qui rend toute injection
       de balise impossible depuis un nom de domaine ou un en-tete capture ;
     - une seule boucle de rafraichissement par page, jamais une par section.
   ========================================================================== */

(function () {
  "use strict";

  var CSRF = (document.querySelector('meta[name="csrf-token"]') || {}).content || "";
  var REFRESH_MS = 2500;

  /* ------------------------------------------------------------- utilitaires */

  function $(selector, root) {
    return (root || document).querySelector(selector);
  }

  function h(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (key) {
        var value = attrs[key];
        if (value === null || value === undefined) return;
        if (key === "class") node.className = value;
        else if (key === "text") node.textContent = value;
        else node.setAttribute(key, value);
      });
    }
    if (children) {
      (Array.isArray(children) ? children : [children]).forEach(function (child) {
        if (child === null || child === undefined || child === false) return;
        node.append(child instanceof Node ? child : document.createTextNode(String(child)));
      });
    }
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function replace(node, children) {
    clear(node);
    (Array.isArray(children) ? children : [children]).forEach(function (child) {
      if (child) node.append(child);
    });
  }

  function emptyRow(colspan, message) {
    return h("tr", null, h("td", { colspan: String(colspan), class: "empty", text: message }));
  }

  /* Une ligne d'etat de service. Definie au niveau du fichier, et non dans la
     fonction qui l'a introduite : le tableau de bord ET la page Parametres
     affichent tous les deux cette liste. */
  function serviceRow(label, state, detail) {
    return h("div", { class: "service-item", "data-state": state }, [
      h("span", { class: "service-dot", "aria-hidden": "true" }),
      h("span", { class: "service-label", text: label }),
      h("span", { class: "service-detail", text: detail })
    ]);
  }

  function etat(flag) {
    if (flag === true) return "ok";
    if (flag === false) return "ko";
    return "off";
  }

  /* ------------------------------------------------------------------ SVG */

  /* Le SVG n'utilise pas les memes fonctions que le HTML : ses elements
     doivent etre crees dans l'espace de noms SVG, sinon le navigateur les
     traite comme des balises inconnues et rien ne s'affiche. */
  var SVG_NS = "http://www.w3.org/2000/svg";

  function s(tag, attrs, children) {
    var node = document.createElementNS(SVG_NS, tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (key) {
        var valeur = attrs[key];
        if (valeur === null || valeur === undefined) return;
        node.setAttribute(key, String(valeur));
      });
    }
    if (children) {
      (Array.isArray(children) ? children : [children]).forEach(function (enfant) {
        if (enfant === null || enfant === undefined) return;
        // Un texte doit devenir un noeud texte : appendChild refuse une chaine
        // de caracteres, et l'erreur serait invisible si elle est avalee plus
        // haut par un catch.
        if (typeof enfant === "string" || typeof enfant === "number") {
          node.appendChild(document.createTextNode(String(enfant)));
        } else {
          node.appendChild(enfant);
        }
      });
    }
    return node;
  }

  /* Courbe d'activite : un point par seconde, sur les deux dernieres minutes.
     Dessinee a la main plutot qu'avec une bibliotheque : la politique de
     securite du serveur n'autorise que nos propres ressources, et un graphique
     n'a pas besoin de plus de vingt lignes de code. */
  function dessinerCourbe(zone, points) {
    if (!zone) return;
    if (!points || points.length < 2) {
      replace(zone, h("p", { class: "empty", text: points && points.length === 1
        ? "Première mesure en cours…"
        : "Démarrez une capture pour voir l'activité." }));
      return;
    }

    var L = 900, H = 160, marge = 28;
    var maxi = Math.max.apply(null, points.map(function (p) { return p.packets; })) || 1;
    var pas = (L - marge * 1.6) / (points.length - 1);
    var base = H - marge;

    var coords = points.map(function (p, i) {
      return {
        x: marge * 0.6 + i * pas,
        y: base - (p.packets / maxi) * (base - marge * 0.5)
      };
    });

    var trace = coords.map(function (c, i) {
      return (i ? "L" : "M") + Math.round(c.x) + " " + Math.round(c.y);
    }).join(" ");
    var dernier = coords[coords.length - 1];

    var enfants = [
      s("path", { class: "courbe-aire", d: trace
          + " L" + Math.round(dernier.x) + " " + base
          + " L" + Math.round(coords[0].x) + " " + base + " Z" }),
      s("path", { class: "courbe-ligne", d: trace }),
      s("line", { class: "courbe-repere", x1: 0, y1: base, x2: L, y2: base }),
      s("text", { class: "courbe-legende", x: 4, y: marge * 0.7 },
        "maximum " + maxi + " paquets/s"),
      s("text", { class: "courbe-legende", x: L - 150, y: base + 18 },
        "maintenant : " + points[points.length - 1].packets + " paquets/s"),
      // Duree reelle de la fenetre, deduite des horodatages : l'annoncer en dur
      // serait faux des que l'intervalle de mesure change.
      s("text", { class: "courbe-legende", x: 4, y: base + 18 },
        "il y a " + dureeFenetre(points))
    ];

    replace(zone, s("svg", { viewBox: "0 0 " + L + " " + H,
                             preserveAspectRatio: "none",
                             role: "img",
                             "aria-label": "Activité réseau : jusqu'à " + maxi
                                           + " paquets par seconde sur "
                                           + dureeFenetre(points) },
                    enfants));
  }

  /* Duree couverte par la courbe, deduite des horodatages des points. */
  function dureeFenetre(points) {
    if (!points || points.length < 2) return "—";
    var secondes = points[points.length - 1].ts - points[0].ts;
    if (secondes < 90) return Math.round(secondes) + " s";
    return Math.round(secondes / 60) + " min";
  }

  /* Carte des relations : cette machine au centre, ses interlocuteurs autour.

     Le centre est le seul point de vue que la capture permet de connaitre : on
     ne voit pas le trafic des autres appareils du reseau. La carte le dit, au
     lieu de laisser croire qu'elle montre tout le reseau.

     Dessinee en SVG, sans bibliotheque : la politique de securite du serveur
     n'autorise que nos propres ressources. */
  function dessinerCarteRelations(zone, donnees) {
    if (!zone) return;
    var pairs = (donnees && donnees.peers) || [];
    if (!pairs.length) {
      replace(zone, h("p", { class: "empty", text: "Aucune communication pour l'instant." }));
      return;
    }

    var L = 900, H = 470;
    var cx = L / 2, cy = H / 2;
    var rayon = Math.min(L / 2 - 150, H / 2 - 62);
    var maxi = Math.max.apply(null, pairs.map(function (p) { return p.bytes; })) || 1;
    var enfants = [];

    pairs.forEach(function (pair, i) {
      var angle = (-Math.PI / 2) + (i * 2 * Math.PI / pairs.length);
      var x = cx + Math.cos(angle) * rayon;
      var y = cy + Math.sin(angle) * rayon;
      var part = pair.bytes / maxi;

      // Le trait : son epaisseur suit le volume, donc le trafic reel.
      enfants.push(s("line", {
        class: "relation" + (pair.direction === "interne" ? " relation--interne" : ""),
        x1: cx, y1: cy, x2: Math.round(x), y2: Math.round(y),
        "stroke-width": (0.7 + 6 * part).toFixed(2)
      }));

      // Le noeud : la taille suit aussi le volume.
      enfants.push(s("circle", {
        class: "relation-noeud",
        cx: Math.round(x), cy: Math.round(y), r: (3 + 6 * part).toFixed(2)
      }));

      // L'etiquette : l'organisation si on la connait, sinon l'adresse.
      var nom = pair.organization || pair.ip;
      if (nom.length > 26) nom = nom.slice(0, 25) + "…";
      var aDroite = Math.cos(angle) >= 0;
      var texte = s("text", {
        class: "relation-etiquette",
        x: Math.round(cx + Math.cos(angle) * (rayon + 16)),
        y: Math.round(cy + Math.sin(angle) * (rayon + 16) + 4),
        "text-anchor": aDroite ? "start" : "end"
      }, nom);
      enfants.push(texte);

      enfants.push(s("text", {
        class: "relation-part",
        x: Math.round(cx + Math.cos(angle) * (rayon + 16)),
        y: Math.round(cy + Math.sin(angle) * (rayon + 16) + 18),
        "text-anchor": aDroite ? "start" : "end"
      }, fmtBytes(pair.bytes) + " · " + pair.percent + " %"));
    });

    // Le centre.
    enfants.push(s("circle", { class: "relation-centre", cx: cx, cy: cy, r: 13 }));
    enfants.push(s("text", {
      class: "relation-centre-texte", x: cx, y: cy + 4, "text-anchor": "middle"
    }, "moi"));

    var reste = (donnees && donnees.others) || { count: 0, bytes: 0 };
    if (reste.count > 0) {
      enfants.push(s("text", {
        class: "relation-reste", x: cx, y: H - 8, "text-anchor": "middle"
      }, "et " + reste.count + " autre(s) interlocuteur(s), " +
         fmtBytes(reste.bytes) + " — non représentés pour rester lisible"));
    }

    replace(zone, s("svg", {
      viewBox: "0 0 " + L + " " + H,
      preserveAspectRatio: "xMidYMid meet",
      role: "img",
      "aria-label": "Carte des relations : " + pairs.length +
                    " interlocuteur(s) de cette machine"
    }, enfants));
  }

  function fmtBytes(n) {
    var value = Number(n) || 0;
    if (value < 1024) return value + " o";
    if (value < 1048576) return (value / 1024).toFixed(1) + " Ko";
    if (value < 1073741824) return (value / 1048576).toFixed(1) + " Mo";
    return (value / 1073741824).toFixed(2) + " Go";
  }

  function fmtDuration(seconds) {
    var s = Number(seconds) || 0;
    if (s < 1) return "< 1 s";
    if (s < 60) return Math.round(s) + " s";
    if (s < 3600) return Math.round(s / 60) + " min";
    return (s / 3600).toFixed(1) + " h";
  }

  function fmtClock(epoch) {
    var d = new Date((Number(epoch) || 0) * 1000);
    return d.toLocaleTimeString("fr-FR", { hour12: false }) +
      "." + String(d.getMilliseconds()).padStart(3, "0");
  }

  function fmtDateTime(epoch) {
    if (!epoch) return "—";
    return new Date(Number(epoch) * 1000).toLocaleString("fr-FR", { hour12: false });
  }

  function endpoint(host, port) {
    if (host === undefined || host === null) return "—";
    return port === null || port === undefined ? String(host) : host + ":" + port;
  }

  function badgeFor(protocol) {
    var map = {
      TLS: "badge--tls", HTTP: "badge--http", DNS: "badge--dns",
      QUIC: "badge--tls", HTTPS: "badge--tls"
    };
    return h("span", {
      class: "badge " + (map[protocol] || ""),
      text: protocol || "?"
    });
  }

  function stateClass(state) {
    if (state === "etablie" || state === "en cours") return "state state--open";
    if (state === "echec") return "state state--failed";
    if (state === "inactive" || state === "nouvelle") return "state state--idle";
    return "state state--closed";
  }

  /* Le risque est calcule par le serveur a partir de faits observes. La page
     ne fait que l'afficher : elle n'attribue jamais de niveau elle-meme. */
  function riskBadge(risk) {
    if (!risk) return h("span", { class: "risk-badge", text: "—" });
    var niveau = risk.label || "inconnu";
    return h("span", {
      class: "risk-badge risk-badge--" + niveau,
      text: risk.score + " · " + niveau,
      title: risk.summary || ""
    });
  }

  /* ------------------------------------------------- paquets : aides d'affichage */

  /* Repere visuel par protocole, sur le principe des regles de colorisation de
     Wireshark : l'oeil trie la liste avant meme de lire les colonnes. */
  function protocolClass(protocol) {
    var connus = ["dns", "tls", "http", "udp", "tcp", "arp", "icmp", "ipv6"];
    var cle = String(protocol || "").toLowerCase();
    return connus.indexOf(cle) >= 0 ? "pkt--" + cle : "";
  }

  /* Une adresse dont la geographie n'est pas encore connue affiche un tiret.
     C'est different d'une adresse sans pays : on ne confond pas les deux. */
  function geoText(record, champ) {
    var geo = record.geo;
    if (!geo || geo.error) return "—";
    var valeur = geo[champ];
    if (valeur === null || valeur === undefined || valeur === "") return "—";
    return String(valeur);
  }

  function ouvrirPaquet(numero) {
    // Sur la page Paquets, cliquer sur une ligne SELECTIONNE le paquet et
    // remplit les deux volets du bas, sans quitter la page : c'est le
    // comportement de Wireshark. Ailleurs, on ouvre la page dediee.
    if (window.__pkaSelectPacket) {
      window.__pkaSelectPacket(numero);
      return;
    }
    window.location.href = "/packet?number=" + numero;
  }

  /* La source externe renvoie deja « AS16509 ». Prefixer sans verifier donnait
     « ASAS16509 » : on normalise au lieu de concatener. */
  function fmtAsn(asn) {
    if (!asn) return "—";
    var texte = String(asn).trim().toUpperCase();
    if (!texte) return "—";
    return texte.indexOf("AS") === 0 ? texte : "AS" + texte;
  }

  /* Le champ « org » de la source externe porte parfois un nom interne peu
     parlant : pour Google, il vaut « EU metro frontend », alors que le champ
     « isp » vaut « Google LLC ». Celui-ci nomme l'operateur du reseau, donc ce
     que l'utilisateur reconnait. Les deux sont conserves dans l'infobulle. */
  function orgText(geo) {
    if (!geo || geo.error) return "—";
    var principal = geo.isp || geo.org;
    if (!principal) return "—";
    return String(principal);
  }

  function orgTitle(geo) {
    if (!geo || geo.error) return "";
    var morceaux = [];
    if (geo.isp) morceaux.push("Opérateur : " + geo.isp);
    if (geo.org) morceaux.push("Organisation : " + geo.org);
    if (geo.asn) morceaux.push("Réseau : " + fmtAsn(geo.asn));
    if (geo.city) morceaux.push("Ville : " + geo.city);
    return morceaux.join("\n");
  }

  /* Cellule d'adresse : la largeur est bornee et le texte se termine par des
     points de suspension quand il ne tient pas. C'est le comportement des
     colonnes de Wireshark, et la valeur complete reste accessible au survol
     ainsi que dans le detail du paquet. Une colonne non bornee rendrait le
     tableau plus large que l'ecran et obligerait a defiler pour lire. */
  function endpointCell(host, port, extraClass) {
    var texte = endpoint(host, port);
    return h("td", {
      class: "mono endpoint " + (extraClass || ""),
      text: texte,
      title: texte
    });
  }

  /* Ligne du tableau des paquets. Cliquable et pilotable au clavier : ouvrir le
     detail d'un paquet est l'action principale de cette page. */
  function packetTableRow(record) {
    var ligne = h("tr", {
      class: "pkt-row " + protocolClass(record.protocol),
      tabindex: "0",
      title: "Afficher le contenu de ce paquet"
    }, [
      h("td", { class: "mono num", text: String(record.number) }),
      h("td", { class: "mono instant", text: fmtClock(record.ts) }),
      endpointCell(record.src, record.src_port),
      endpointCell(record.dst, record.dst_port),
      h("td", null, badgeFor(record.protocol)),
      h("td", { class: "mono num", text: (record.size || 0) + " o" }),
      h("td", { class: "mono pays", text: geoText(record, "country") }),
      h("td", { class: "org", text: orgText(record.geo), title: orgTitle(record.geo) }),
      h("td", { class: "summary-cell", text: record.info || "", title: record.info || "" })
    ]);

    ligne.addEventListener("click", function () { ouvrirPaquet(record.number); });
    ligne.addEventListener("keydown", function (evenement) {
      if (evenement.key === "Enter" || evenement.key === " ") {
        evenement.preventDefault();
        ouvrirPaquet(record.number);
      }
    });
    return ligne;
  }

  /* ------------------------------------------------------------------- flash */

  var flashTimer = null;
  function flash(message, kind) {
    var box = $("#flash");
    if (!box) return;
    box.textContent = message;
    box.setAttribute("data-kind", kind || "ok");
    box.hidden = false;
    if (flashTimer) clearTimeout(flashTimer);
    flashTimer = setTimeout(function () { box.hidden = true; }, 6000);
  }

  /* --------------------------------------------------------------------- API */

  function api(path, options) {
    options = options || {};
    var init = { method: options.method || "GET", headers: {} };
    if (init.method !== "GET") {
      init.headers["X-CSRF-Token"] = CSRF;
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(options.body || {});
    }
    return fetch(path, init).then(function (response) {
      return response.json()
        .catch(function () { return { ok: false, error: "Réponse illisible du serveur." }; })
        .then(function (data) {
          if (!response.ok || data.ok === false) {
            throw new Error(data.error || data.message || ("Erreur HTTP " + response.status));
          }
          return data;
        });
    });
  }

  /* ------------------------------------------------------- pilotage de capture */

  function initCaptureControls() {
    var startBtn = $("#btn-start");
    var stopBtn = $("#btn-stop");
    var resetBtn = $("#btn-reset");
    var ifaceSelect = $("#iface-select");
    var filterInput = $("#bpf-filter");
    if (!startBtn) return;

    var statusPill = $("#capture-status");
    var statusText = $("#capture-status-text");

    function setState(state, text) {
      if (statusPill) statusPill.setAttribute("data-state", state);
      if (statusText) statusText.textContent = text;
      startBtn.disabled = state === "running";
      if (stopBtn) stopBtn.disabled = state !== "running";
    }

    function loadInterfaces() {
      return api("/api/interfaces").then(function (data) {
        clear(ifaceSelect);
        if (!data.interfaces.length) {
          ifaceSelect.append(h("option", { value: "", text: "Aucune interface détectée" }));
          return;
        }
        data.interfaces.forEach(function (iface) {
          ifaceSelect.append(h("option", {
            value: iface.id,
            text: iface.display + (iface.is_virtual ? " — carte virtuelle" : "")
          }));
        });
        if (data.default) ifaceSelect.value = data.default;
      }).catch(function (error) {
        flash("Interfaces indisponibles : " + error.message, "error");
      });
    }

    /* L'etat affiche doit venir du SERVEUR, jamais d'une supposition locale.
       Sinon une capture reellement en cours peut apparaitre comme arretee, et
       une erreur passagere comme une panne definitive. */
    function applyCaptureState(capture) {
      if (!capture) return;
      if (capture.running) {
        setState("running", "Capture en cours");
      } else {
        setState("idle", "Capture arrêtée");
      }
    }

    function refreshState(selectInterface) {
      return api("/api/stats").then(function (data) {
        var capture = data.capture || {};
        applyCaptureState(capture);
        if (selectInterface && capture.interface_id && ifaceSelect) {
          var match = Array.prototype.find.call(
            ifaceSelect.options,
            function (option) { return option.value === capture.interface_id; }
          );
          if (match) ifaceSelect.value = match.value;
        }
        return capture;
      }).catch(function () {
        setState("idle", "État indisponible");
      });
    }

    // Le tableau de bord recoit deja cet etat par le flux temps reel : on
    // expose donc la fonction pour qu'il n'ait pas a interroger le serveur
    // en plus, ce qui doublerait les requetes sans rien apporter.
    window.__pkaApplyCaptureState = applyCaptureState;

    startBtn.addEventListener("click", function () {
      startBtn.disabled = true;
      api("/api/capture/start", {
        method: "POST",
        body: { interface: ifaceSelect.value, filter: filterInput.value }
      }).then(function (data) {
        flash(data.message, "ok");
        setState("running", "Capture en cours");
        if (window.__pkaRefresh) window.__pkaRefresh();
      }).catch(function (error) {
        // Un echec peut simplement signifier qu'une capture tourne deja :
        // on interroge le serveur avant d'afficher une quelconque panne.
        flash(error.message, "error");
        refreshState(true).then(function (capture) {
          if (window.__pkaRefresh) window.__pkaRefresh();
        });
      });
    });

    if (stopBtn) {
      stopBtn.addEventListener("click", function () {
        stopBtn.disabled = true;
        api("/api/capture/stop", { method: "POST" })
          .then(function (data) {
            flash(data.message, "ok");
            setState("idle", "Capture arrêtée");
          })
          .catch(function (error) { flash(error.message, "error"); })
          .finally(function () { refreshState(); });
      });
    }

    if (resetBtn) {
      resetBtn.addEventListener("click", function () {
        api("/api/reset", { method: "POST" })
          .then(function (data) {
            flash(data.message, "ok");
            setState("idle", "Capture arrêtée");
            if (window.__pkaRefresh) window.__pkaRefresh();
          })
          .catch(function (error) { flash(error.message, "error"); });
      });
    }

    // On attend d'avoir la liste des interfaces avant de refleter l'etat, pour
    // pouvoir y selectionner celle qui capture reellement.
    loadInterfaces().then(function () { refreshState(true); });

    // Le tableau de bord est alimente en continu par le flux temps reel : il
    // n'a pas besoin d'interroger en plus. Les autres pages, elles, n'ont pas
    // de flux, d'ou ce sondage. La fonction est enveloppee car setInterval lui
    // transmettrait sinon l'identifiant du minuteur.
    var tableauDeBord = document.querySelector("#stat-packets");
    if (!tableauDeBord) {
      setInterval(function () { refreshState(false); }, 8000);
    }

    return { setState: setState };
  }

  /* ------------------------------------------- 0. resume et etat des services */

  function initSummaryAndServices() {
    var summaryText = $("#summary-text");
    if (summaryText) {
      /* Le resume est un instantane : ses chiffres datent de son calcul, alors
         que les cartes au-dessus se rafraichissent en continu. Sans
         rafraichissement, les deux finissaient par se contredire a l'ecran —
         « 4850 paquets » en haut et « 4076 » dans le texte. On le recalcule donc
         regulierement, sans afficher « Composition… » a chaque fois (le texte
         sauterait pendant la lecture), et on affiche l'heure du calcul pour que
         le lecteur sache de quand datent ces chiffres. */
      var loadSummary = function (silencieux) {
        if (!silencieux) summaryText.textContent = "Composition du résumé…";
        api("/api/summary").then(function (data) {
          var summary = data.summary || {};
          var heure = new Date().toLocaleTimeString("fr-FR");
          $("#summary-source").textContent =
            "source : " + (summary.provider || "—") + " · calculé à " + heure;
          summaryText.textContent = summary.text || "";

          var guardrail = $("#summary-guardrail");
          guardrail.hidden = false;
          if (summary.fallback) {
            guardrail.setAttribute("data-kind", "warn");
            guardrail.textContent = summary.error ||
              "La reformulation automatique a été écartée ; le résumé par règles est affiché.";
          } else {
            guardrail.setAttribute("data-kind", "ok");
            var g = summary.guardrails || {};
            guardrail.textContent =
              "Aucun fait ajouté : " + (g.entites_autorisees || 0) +
              " entité(s) issue(s) des observations, " +
              ((g.inventions_detectees || []).length) + " invention(s) détectée(s).";
          }
        }).catch(function (error) {
          summaryText.textContent = "Résumé indisponible : " + error.message;
        });
      };

      var button = $("#btn-summary");
      if (button) button.addEventListener("click", function () { loadSummary(false); });
      window.__pkaSummaryRefresh = loadSummary;
      loadSummary(false);
      setInterval(function () { loadSummary(true); }, 5000);
    }

    var servicesBox = $("#services-state");
    if (servicesBox) {
      api("/api/dependencies").then(function (data) {
        replace(servicesBox, [
          serviceRow("Base locale", etat(data.base_locale.disponible),
            data.base_locale.chemin),
          serviceRow("Supabase",
            data.supabase.active === false ? "off" : etat(data.supabase.disponible),
            data.supabase.active === false
              ? "désactivé (SUPABASE_ENABLED=false)"
              : (data.supabase.erreur || "connecté")),
          serviceRow("Capture réseau", etat(data.capture.disponible),
            data.capture.disponible
              ? (data.capture.interfaces + " interface(s) disponible(s)")
              : data.capture.message),
          serviceRow("Enrichissement",
            data.enrichissement.active ? "ok" : "off",
            data.enrichissement.active
              ? (data.enrichissement.appels_externes + " appel(s), " +
                 data.enrichissement.reponses_en_cache + " depuis le cache — " +
                 data.enrichissement.source)
              : "désactivé"),
          serviceRow("Reformulation", "ok",
            data.reformulation.modele_actif
              ? ("modèle " + data.reformulation.fournisseur)
              : "résumé par règles (aucune configuration requise)"),
          serviceRow("Traduction d'adresses",
            data.traduction && data.traduction.prefixes_nat64 &&
            data.traduction.prefixes_nat64.length ? "ok" : "off",
            data.traduction && data.traduction.prefixes_nat64 &&
            data.traduction.prefixes_nat64.length
              ? ("préfixe(s) détecté(s) : " +
                 data.traduction.prefixes_nat64.join(", ") +
                 " — ces adresses représentent plusieurs destinations")
              : "aucun préfixe de traduction détecté sur ce réseau")
        ]);
      }).catch(function (error) {
        replace(servicesBox, h("p", { class: "empty", text: "État indisponible : " + error.message }));
      });
    }
  }

  /* --------------------------------------------------------- 1. tableau de bord */

  function initDashboard() {
    var root = $("#stat-packets");
    if (!root) return;

    var protoChart = $("#protocol-chart");
    var portChart = $("#port-chart");
    var trafficChart = $("#traffic-chart");
    var sizeChart = $("#size-chart");
    var hierarchyChart = $("#hierarchy-chart");
    var sources = $("#top-sources");
    var destinations = $("#top-destinations");
    var eventsBox = $("#recent-events");
    var packetsBody = $("#recent-packets");

    function barRows(items, labelKey, countKey, unitLabel) {
      if (!items.length) return h("p", { class: "empty", text: "Aucune donnée pour l'instant." });
      var max = Math.max.apply(null, items.map(function (i) { return i[countKey]; })) || 1;
      return items.map(function (item) {
        /* La largeur est posee par le CSSOM et NON par un attribut style="...".
           La politique de securite du serveur (style-src 'self') bloque les
           attributs de style en ligne : les barres se retrouvaient sans largeur
           et les graphiques du tableau de bord etaient casses. Le CSSOM n'est
           pas concerne par cette restriction. */
        var remplissage = h("div", { class: "bar-fill" });
        remplissage.style.width = Math.max(3, (item[countKey] / max) * 100) + "%";

        return h("div", { class: "bar-row" }, [
          h("span", { class: "bar-label", text: item[labelKey], title: item[labelKey] }),
          h("div", { class: "bar-track" }, remplissage),
          h("span", { class: "bar-value", text: String(item[countKey]) + (unitLabel || "") })
        ]);
      });
    }

    /* Hierarchie par volume : la barre represente la PART du total, alors que
       barRows la represente par rapport au plus gros. Deux graphiques de la meme
       page ne doivent pas melanger les deux echelles sans le dire : ici, la
       longueur totale de la piste vaut 100 %.

       Aucune largeur minimale n'est imposee. Une barre d'appoint visible pour un
       protocole a 0 % serait un graphique qui exagere ; le chiffre exact est
       ecrit juste a cote, c'est lui qui fait foi. */
    function hierRows(items) {
      return items.map(function (item) {
        var remplissage = h("div", { class: "bar-fill" });
        remplissage.style.width = Math.min(100, item.percent) + "%";
        return h("div", { class: "bar-row" }, [
          h("span", { class: "bar-label", text: item.name, title: item.name }),
          h("div", { class: "bar-track" }, remplissage),
          h("span", { class: "bar-value",
                      text: fmtBytes(item.bytes) + " · " + item.percent + " %" })
        ]);
      });
    }

    function listRows(items, labelKey, countKey, emptyMessage) {
      if (!items.length) return [h("li", { class: "empty", text: emptyMessage })];
      return items.map(function (item) {
        return h("li", null, [
          h("span", { class: "mono", text: item[labelKey] }),
          h("span", { class: "count", text: String(item[countKey]) + " paquets" })
        ]);
      });
    }

    function eventNode(event) {
      return h("article", { class: "event", "data-kind": event.kind, "data-severity": event.severity }, [
        h("div", { class: "event-head" }, [
          h("h3", { class: "event-title", text: event.title }),
          h("span", { class: "event-meta", text: event.kind + " · " + event.severity })
        ]),
        h("p", { class: "event-body", text: event.explanation })
      ]);
    }

    function packetRow(record) {
      return h("tr", null, [
        h("td", { class: "mono num", text: String(record.number) }),
        h("td", { class: "mono endpoint", text: endpoint(record.src, record.src_port) }),
        h("td", { class: "mono endpoint", text: endpoint(record.dst, record.dst_port) }),
        h("td", null, badgeFor(record.protocol)),
        h("td", { class: "mono", text: record.tcp_flags || "—" }),
        h("td", { class: "mono num", text: record.size + " o" }),
        h("td", { class: "summary-cell", text: record.info || "" })
      ]);
    }

    function render(payload) {
      var stats = payload.stats || (payload.type === "stats" ? payload : null);
      if (!stats) {
        if (payload.capture) { /* reponse de /api/stats */ }
      }
      stats = stats || payload;

      // L'etat de capture arrive avec les statistiques : on en profite pour
      // mettre a jour la pastille, sans requete supplementaire.
      if (stats.capture && window.__pkaApplyCaptureState) {
        window.__pkaApplyCaptureState(stats.capture);
      }

      $("#stat-packets").textContent = String(stats.packets || 0);
      $("#stat-flows").textContent = String(stats.flows || 0);
      $("#stat-active").textContent = String(stats.active_flows || 0);
      $("#stat-bytes").textContent = fmtBytes(stats.bytes);
      $("#stat-events").textContent = String(stats.events || 0);

      var note = $("#stat-events-note");
      if (note) {
        var kinds = stats.events_by_kind || {};
        var parts = Object.keys(kinds).map(function (key) { return kinds[key] + " " + key.toLowerCase(); });
        note.textContent = parts.length ? parts.join(", ") : "aucun pour l'instant";
      }

      var protoItems = stats.protocols || [];
      // Courbe d'activite : le serveur fournit un debit par seconde, la page
      // ne fait que le dessiner.
      dessinerCourbe(trafficChart, stats.traffic_series || []);

      // Repartition par taille : on garde toutes les tranches, y compris vides,
      // pour que les barres ne se collent pas les unes aux autres.
      var tailles = stats.size_distribution || [];
      var taillesUtiles = tailles.filter(function (t) { return t.count > 0; });
      replace(sizeChart, tailles.length && taillesUtiles.length
        ? barRows(tailles, "label", "count", " paquets")
        : h("p", { class: "empty", text: "Aucune donnée pour l'instant." }));

      // Hierarchie par volume : ce qui occupe reellement le reseau.
      var hierarchie = stats.protocol_hierarchy || [];
      replace(hierarchyChart, hierarchie.length
        ? hierRows(hierarchie)
        : h("p", { class: "empty", text: "Aucune donnée pour l'instant." }));
      replace(protoChart, protoItems.length
        ? barRows(protoItems, "name", "count", "")
        : h("p", { class: "empty", text: "Aucune donnée : démarrez une capture pour observer le trafic." }));

      var portItems = stats.top_ports || [];
      replace(portChart, portItems.length
        ? barRows(portItems, "port", "count", "")
        : h("p", { class: "empty", text: "Aucune donnée pour l'instant." }));

      replace(sources, listRows(stats.top_sources || [], "ip", "count", "Aucune donnée."));
      replace(destinations, listRows(stats.top_destinations || [], "ip", "count", "Aucune donnée."));

      if (payload.recent_events) {
        replace(eventsBox, payload.recent_events.length
          ? payload.recent_events.map(eventNode)
          : h("p", { class: "empty", text: "Aucun événement détecté pour l'instant." }));
      }

      if (payload.recent_packets && packetsBody) {
        var recent = payload.recent_packets.slice(0, 12);
        replace(packetsBody, recent.length
          ? recent.map(packetRow)
          : emptyRow(7, "Aucun paquet capturé pour l'instant."));
      }

      var errs = stats.errors || [];
      var notes = stats.notes || [];
      if (errs.length) {
        flash("Analyse : " + errs[0], "error");
      } else if (notes.length) {
        // Une note n'est pas une erreur : la presenter comme telle ferait
        // perdre confiance dans les avertissements qui comptent vraiment.
        flash(notes[0], "info");
      }
    }

    window.__pkaRefresh = function () {
      api("/api/stats").then(render).catch(function () { /* silencieux */ });
    };
    window.__pkaRefresh();

    /* Flux temps reel : le serveur pousse, la page ne demande rien. */
    var socket = null;
    var attempts = 0;

    function connect() {
      var protocol = location.protocol === "https:" ? "wss:" : "ws:";
      try {
        socket = new WebSocket(protocol + "//" + location.host + "/api/ws/live");
      } catch (error) {
        return;
      }

      socket.addEventListener("message", function (message) {
        attempts = 0;
        try {
          render(JSON.parse(message.data));
        } catch (error) {
          // Un catch totalement muet masquerait une vraie panne d'affichage :
          // on signale la premiere erreur, une seule fois.
          if (!window.__pkaErreurFlux) {
            window.__pkaErreurFlux = String(error && error.message || error);
            if (window.console) console.error("Flux temps réel :", error);
          }
        }
      });

      socket.addEventListener("close", function () {
        if (attempts > 8) return;
        attempts += 1;
        setTimeout(connect, Math.min(1000 * attempts, 8000));
      });

      socket.addEventListener("error", function () {
        if (socket) socket.close();
      });
    }

    connect();
  }

  /* ------------------------------------------------------------- 2. paquets */

  function initPackets() {
    var body = $("#packet-rows");
    if (!body) return;

    var champFiltre = $("#display-filter");
    var boutonEffacer = $("#filtre-effacer");
    var zoneMessage = $("#filtre-message");
    var counter = $("#packet-count");
    var voletDetails = $("#packet-details");
    var voletOctets = $("#packet-bytes");
    var refVolet = $("#volet-ref");
    var hote = $(".wireshark");
    var selection = null;     // numero du paquet actuellement selectionne
    var derniers = [];        // paquets affiches, conserves pour la selection

    /* Les deux volets du bas ne servent a rien tant qu'aucun paquet n'est
       choisi : on les replie pour rendre la place a la liste, qui n'affichait
       que sept lignes a l'ouverture. */
    function replierVolets(replies) {
      if (!hote) return;
      if (replies) hote.classList.add("sans-selection");
      else hote.classList.remove("sans-selection");
    }
    replierVolets(true);

    /* Le message affiche appartient a quelqu'un : soit au filtre (une expression
       refusee), soit a l'import d'un fichier. Sans cette distinction, le
       rafraichissement de la liste effacait aussitot la confirmation d'import,
       et l'utilisateur n'avait aucun retour. */
    var messageDuFiltre = false;

    function afficherMessage(texte, genre, origine) {
      if (!zoneMessage) return;
      if (!texte) {
        messageDuFiltre = false;
        zoneMessage.hidden = true;
        zoneMessage.textContent = "";
        return;
      }
      messageDuFiltre = (origine === "filtre");
      zoneMessage.hidden = false;
      zoneMessage.setAttribute("data-kind", genre || "erreur");
      zoneMessage.textContent = texte;
    }

    function load() {
      var params = new URLSearchParams({ limit: "300" });
      var expression = champFiltre ? champFiltre.value.trim() : "";
      if (expression) params.set("filter", expression);

      api("/api/packets?" + params.toString()).then(function (data) {
        derniers = data.packets || [];
        // On n'efface que le message du filtre : la confirmation d'un import de
        // fichier doit rester lisible apres le rafraichissement de la liste.
        if (messageDuFiltre) afficherMessage("");
        if (champFiltre) champFiltre.setAttribute("aria-invalid", "false");

        var total = (typeof data.filtered_total === "number") ? data.filtered_total : null;
        counter.textContent = (expression && total !== null)
          ? derniers.length + " affiché(s) sur " + total + " filtré(s)"
          : derniers.length + " paquet(s) affiché(s)";

        replace(body, derniers.length ? derniers.map(function (record) {
          return packetTableRow(record);
        }) : emptyRow(9, expression
            ? "Aucun paquet ne correspond à ce filtre."
            : "Aucun paquet capturé pour l'instant."));
        suivreNouveaux();
        remettreLaMarque();
      }).catch(function (error) {
        // Expression refusee par le serveur : on le dit, et on LAISSE la liste
        // precedente a l'ecran. La remplacer par un message d'erreur ferait
        // perdre le travail en cours pour une simple faute de frappe.
        if (champFiltre) champFiltre.setAttribute("aria-invalid", "true");
        afficherMessage("Filtre refusé — " + error.message + " Corrigez l'expression "
                        + "ou cliquez sur « Effacer ».", "erreur", "filtre");
        counter.textContent = derniers.length + " paquet(s) affiché(s)";
      });
    }

    /* Les paquets les plus recents arrivent en tete. On ne repositionne la vue
       que si l'utilisateur est deja en haut : le remonter de force pendant qu'il
       lit une ligne plus bas rendrait la liste impossible a consulter. */
    function suivreNouveaux() {
      var suivi = $("#packet-follow");
      var zone = $("#packet-scroll");
      if (!suivi || !zone || !suivi.checked) return;
      if (zone.scrollTop < 60) zone.scrollTop = 0;
    }

    /* Apres un rafraichissement, les lignes sont reconstruites : il faut
       remettre la marque sur celle qui est selectionnee, sinon la selection
       disparait a l'ecran toutes les 2,5 secondes. */
    function remettreLaMarque() {
      if (selection === null) return;
      var lignes = body.querySelectorAll("tr.pkt-row");
      for (var i = 0; i < lignes.length; i++) {
        var premiere = lignes[i].querySelector("td");
        if (premiere && premiere.textContent.trim() === String(selection)) {
          lignes[i].classList.add("is-selected");
          return;
        }
      }
    }

    function marquer(numero) {
      var lignes = body.querySelectorAll("tr.pkt-row");
      for (var i = 0; i < lignes.length; i++) {
        lignes[i].classList.remove("is-selected");
      }
      selection = numero;
      remettreLaMarque();
    }

    /* Remplit les deux volets du bas. On ne recharge PAS la liste : c'est la
       meme page, comme dans Wireshark. */
    function selectionner(numero) {
      marquer(numero);
      replierVolets(false);
      if (refVolet) refVolet.textContent = "paquet n° " + numero + " — chargement…";

      api("/api/packet?number=" + numero).then(function (data) {
        var paquet = data.packet || {};
        afficherDetails(paquet);
        afficherOctets(paquet);
        if (refVolet) {
          refVolet.textContent = "paquet n° " + paquet.number + " · "
            + (paquet.protocol || "?") + " · " + (paquet.size || 0) + " octets";
        }
      }).catch(function (error) {
        if (refVolet) refVolet.textContent = "paquet n° " + numero;
        replace(voletDetails, h("p", { class: "empty", text: error.message }));
        if (voletOctets) voletOctets.textContent = "";
      });
    }

    function afficherDetails(paquet) {
      if (!voletDetails) return;
      var dissection = paquet.dissection || {};
      var morceaux = [];

      if (dissection.error) {
        morceaux.push(h("p", { class: "empty", text: dissection.error }));
      }

      var couches = dissection.layers || [];
      if (!couches.length) {
        morceaux.push(h("p", { class: "empty", text: "Aucune couche identifiée." }));
      }

      couches.forEach(function (couche) {
        var lignes = (couche.fields || []).map(function (champ) {
          return h("tr", { title: champ.label }, [
            h("td", { class: "mono", text: champ.name }),
            h("td", { class: "mono detail-value", text: champ.value })
          ]);
        });
        morceaux.push(h("div", { class: "layer" }, [
          h("p", { class: "layer-title", text: couche.name }),
          h("p", { class: "layer-summary mono", text: couche.summary || "" }),
          couches.length && lignes.length
            ? h("table", { class: "table table--dense" }, h("tbody", null, lignes))
            : null
        ]));
      });

      replace(voletDetails, morceaux);
    }

    function afficherOctets(paquet) {
      if (!voletOctets) return;
      var lignes = (paquet.dissection || {}).hex || [];
      voletOctets.textContent = lignes.map(function (ligne) {
        return ligne.offset + "  " + ligne.hex + "  " + ligne.ascii;
      }).join("\n") || "(aucun contenu disponible)";
    }

    /* ---- evenements ---- */

    if (champFiltre) {
      champFiltre.addEventListener("keydown", function (evenement) {
        if (evenement.key === "Enter") {
          evenement.preventDefault();
          load();
        }
      });
    }
    if (boutonEffacer) {
      boutonEffacer.addEventListener("click", function () {
        if (champFiltre) champFiltre.value = "";
        afficherMessage("");
        if (champFiltre) champFiltre.setAttribute("aria-invalid", "false");
        load();
      });
    }

    /* Ouverture d'un fichier .pcap enregistre.

       Le fichier part en corps brut, pas dans un formulaire multipart : cela
       evite une dependance supplementaire pour une seule fonctionnalite. */
    var boutonOuvrir = $("#pcap-open");
    var champFichier = $("#pcap-file");
    if (boutonOuvrir && champFichier) {
      boutonOuvrir.addEventListener("click", function () { champFichier.click(); });

      champFichier.addEventListener("change", function () {
        var fichier = champFichier.files && champFichier.files[0];
        if (!fichier) return;

        afficherMessage("Lecture de « " + fichier.name + " » (" +
                        fmtBytes(fichier.size) + ")…", "ok");
        boutonOuvrir.disabled = true;

        fetch("/api/pcap/open", {
          method: "POST",
          headers: { "X-CSRF-Token": CSRF, "Content-Type": "application/octet-stream" },
          body: fichier
        }).then(function (reponse) {
          return reponse.json().catch(function () {
            return { ok: false, error: "Réponse illisible du serveur." };
          });
        }).then(function (data) {
          if (!data.ok) throw new Error(data.error || "Import impossible.");
          afficherMessage(
            data.loaded + " paquet(s) analysé(s) depuis « " + fichier.name +
            " » (lien " + data.link_type_label + ")" +
            (data.unreadable ? " — " + data.unreadable + " illisible(s), ignoré(s)" : ""),
            "ok");
          // Le fichier remplace la capture : la selection precedente ne designe
          // plus rien, et les volets du bas doivent repasser au repos.
          selection = null;
          if (refVolet) refVolet.textContent = "aucun paquet sélectionné — cliquez sur une ligne";
          replierVolets(true);
          load();
        }).catch(function (erreur) {
          afficherMessage("Import refusé — " + erreur.message);
        }).then(function () {
          boutonOuvrir.disabled = false;
          // Remettre a vide permet de rouvrir immediatement le meme fichier.
          champFichier.value = "";
        });
      });

      // Arrivee depuis « Fichier > Ouvrir un .pcap » d'une autre page : le
      // selecteur s'ouvre directement, sinon l'utilisateur devrait deviner qu'il
      // doit cliquer sur le bouton qui vient de defiler sous ses yeux.
      if (window.location.hash === "#ouvrir-pcap") {
        history.replaceState(null, "", window.location.pathname);
        champFichier.click();
      }
    }

    /* Combien de paquets l'export contient reellement.

       Le moteur ne garde que les derniers octets bruts en memoire. Sans cette
       mention, un utilisateur qui exporte 5 000 paquets sur une capture de
       28 000 croit avoir tout emporte — et ne s'en apercevrait qu'en ouvrant le
       fichier ailleurs. */
    var noteExport = $("#export-note");
    function majNoteExport() {
      if (!noteExport) return;
      api("/api/stats").then(function (data) {
        var exportables = data.packets_exportable || 0;
        var total = data.packets || 0;
        if (total > exportables) {
          noteExport.textContent = "Export : les " + exportables +
            " derniers paquets sur " + total + " capturés";
          noteExport.setAttribute("data-alerte", "oui");
        } else if (exportables) {
          noteExport.textContent = "Export : " + exportables + " paquets";
          noteExport.removeAttribute("data-alerte");
        } else {
          noteExport.textContent = "";
          noteExport.removeAttribute("data-alerte");
        }
      }).catch(function () { /* la note n'est pas essentielle */ });
    }
    majNoteExport();
    setInterval(majNoteExport, REFRESH_MS);

    // La selection est exposee pour que packetTableRow puisse l'appeler depuis
    // n'importe quelle page.
    window.__pkaSelectPacket = selectionner;

    /* La syntaxe acceptee est demandee au serveur : l'aide reste ainsi
       exactement alignee sur ce que le serveur sait interpreter. */
    api("/api/filter/syntax").then(function (data) {
      var syntaxe = data.syntax || {};
      var zone = $("#aide-syntaxe");
      if (zone) {
        var champs = Object.keys(syntaxe.champs || {}).map(function (nom) {
          return nom + " (" + syntaxe.champs[nom] + ")";
        }).join(", ");
        zone.textContent = "Champs disponibles : " + champs
          + ".  Opérateurs : " + (syntaxe.operateurs || []).join(" ")
          + ".  Logiques : " + (syntaxe.logiques || []).join(" ") + ".";
      }
    }).catch(function () { /* l'aide est secondaire */ });

    window.__pkaRefresh = load;
    load();
    setInterval(load, REFRESH_MS);
  }

  /* ------------------------------------------------------- 3. communications */

  function initFlows() {
    var body = $("#flow-rows");
    if (!body) return;

    // Carte des relations : chargee une fois puis rafraichie moins souvent que
    // la liste, car elle resume l'ensemble et change lentement.
    var carte = $("#peermap");
    function chargerCarte() {
      if (!carte) return;
      api("/api/peermap").then(function (data) {
        dessinerCarteRelations(carte, data);
      }).catch(function (erreur) {
        replace(carte, h("p", { class: "empty", text: "Indisponible : " + erreur.message }));
      });
    }
    chargerCarte();
    setInterval(chargerCarte, REFRESH_MS * 3);

    var activeOnly = $("#flows-active-only");
    var counter = $("#flow-count");

    function load() {
      var params = new URLSearchParams({ limit: "300" });
      if (activeOnly.checked) params.set("active_only", "true");

      api("/api/flows?" + params.toString()).then(function (data) {
        var flows = data.flows || [];
        counter.textContent = flows.length + " communication(s)";
        replace(body, flows.length ? flows.map(function (flow) {
          var link = h("a", {
            class: "btn btn--ghost btn--small",
            href: "/flow?key=" + encodeURIComponent(flow.key),
            text: "Analyser"
          });
          return h("tr", null, [
            endpointCell(flow.observer, null),
            // L'organisation s'affiche sous l'adresse distante : sur un flux
            // QUIC (video YouTube), c'est le seul repere qui permette de
            // reconnaitre l'interlocuteur, le nom de domaine etant chiffre.
            h("td", { class: "addresses" }, [
              h("div", { class: "mono", text: endpoint(flow.distant, flow.distant_port) }),
              flow.distant_isp || flow.distant_org
                ? h("div", { class: "hostname", text: (flow.distant_isp || flow.distant_org) })
                : null
            ]),
            // Service et protocole dans une seule cellule : deux colonnes pour
            // deux informations courtes elargissaient le tableau sans rien
            // apporter a la lecture.
            h("td", null, [
              flow.service
                ? h("span", { class: flow.service_sensitive ? "badge badge--risk" : "badge",
                              text: flow.service,
                              title: flow.service_port === null ? "" : "port " + flow.service_port })
                : h("span", { class: "mono", text: flow.service_port === null ? "—" : String(flow.service_port) }),
              h("span", { class: "cell-sep", text: " " }),
              badgeFor(flow.app_protocol || flow.transport)
            ]),
            h("td", null, h("span", { class: stateClass(flow.state), text: flow.state_label || flow.state })),
            // Paquets et volume reunis : ils decrivent la meme chose, l'ampleur
            // de l'echange.
            h("td", { class: "mono num trafic",
                      text: String(flow.packets) + " · " + fmtBytes(flow.bytes_total),
                      title: String(flow.packets) + " paquets, " + fmtBytes(flow.bytes_total)
                             + ", duree " + fmtDuration(flow.duration) }),
            h("td", {
              text: flow.domain ? flow.domain : (flow.direction === "local" ? "sortant" : flow.direction === "distant" ? "entrant" : "indéterminé"),
              title: flow.domain || ""
            }),
            h("td", null, riskBadge(flow.risk)),
            h("td", null, link)
          ]);
        }) : emptyRow(8, "Aucune communication observée pour l'instant."));
      }).catch(function (error) {
        counter.textContent = "Erreur : " + error.message;
      });
    }

    activeOnly.addEventListener("change", load);
    window.__pkaRefresh = load;
    load();
    setInterval(load, REFRESH_MS);
  }

  /* ---------------------------------------------------- 4. detail d'un flux */

  function initFlowDetail() {
    var root = $("#detail-root");
    if (!root) return;

    var key = root.getAttribute("data-flow-key");
    var loading = $("#detail-loading");
    var errorBox = $("#detail-error");

    function factNode(fact) {
      return h("li", null, [
        h("span", { class: "fact-label", text: fact.label }),
        h("span", { class: "fact-value", text: fact.value }),
        h("span", { class: "fact-origin", text: fact.origin || "" })
      ]);
    }

    function interpNode(interp) {
      return h("li", null, [
        h("p", { class: "interp-statement", text: interp.statement }),
        h("p", { class: "interp-basis" }, [
          h("strong", { text: "Justification : " }),
          document.createTextNode(interp.basis),
          h("span", { class: "interp-confidence", text: "confiance " + interp.confidence })
        ])
      ]);
    }

    function kvRow(label, value, mono) {
      return h("div", { class: "kv-row" }, [
        h("dt", { text: label }),
        h("dd", { class: value === null || value === undefined ? "muted" : (mono ? "mono" : ""),
                  text: value === null || value === undefined ? "—" : String(value) })
      ]);
    }

    function render(data) {
      $("#detail-headline").textContent = data.headline;
      $("#detail-plain-text").textContent = data.plain_text;

      var conf = $("#detail-confidence");
      var confValue = $("#detail-confidence-value");
      confValue.textContent = data.confidence;
      conf.className = "confidence confidence--" + data.confidence;

      var flow = data.flow || {};

      replace($("#detail-technical"), [
        kvRow("Hôte local", flow.observer),
        kvRow("Hôte distant", flow.distant),
        kvRow("Port du service", flow.service_port !== undefined ? flow.service_port : "—"),
        kvRow("Ports observés", (flow.src_port === null ? "—" : flow.src_port) + " \u2192 " + (flow.dst_port === null ? "—" : flow.dst_port)),
        kvRow("Protocole de transport", flow.transport, true),
        kvRow("Protocole applicatif", flow.app_protocol || "non identifié", true),
        kvRow("Nom de domaine observé", flow.domain),
        kvRow("Début de l'observation", fmtDateTime(flow.first_seen)),
        kvRow("Dernier paquet", fmtDateTime(flow.last_seen))
      ]);

      replace($("#detail-state"), [
        kvRow("État", flow.state_label || flow.state),
        kvRow("Détail TCP", flow.tcp_state || "—"),
        kvRow("Paquets échangés", flow.packets, true),
        kvRow("Volume total", fmtBytes(flow.bytes_total), true),
        kvRow("Sens aller", fmtBytes(flow.bytes_fwd), true),
        kvRow("Sens retour", fmtBytes(flow.bytes_rev), true),
        kvRow("Durée observée", fmtDuration(flow.duration), true),
        kvRow("Début de connexion observé", flow.handshake_seen ? "oui" : "non — déduit"),
        kvRow("Retransmissions estimées", flow.retransmissions)
      ]);

      var facts = data.facts || [];
      replace($("#detail-facts"), facts.length
        ? facts.map(factNode)
        : h("li", { class: "empty", text: "Aucun fait mesuré disponible." }));

      var interps = data.interpretations || [];
      replace($("#detail-interps"), interps.length
        ? interps.map(interpNode)
        : h("li", { class: "empty", text: "Aucune interprétation produite." }));

      var caveats = data.caveats || [];
      replace($("#detail-caveats"), caveats.length
        ? caveats.map(function (text) { return h("li", { text: text }); })
        : h("li", { text: "Aucune réserve particulière sur cette analyse." }));

      renderRisk(data.risk);

      if (data.intel && data.intel.source) {
        renderIntel(data.intel);
      }
    }

    function renderRisk(risk) {
      var panel = document.querySelector(".panel--risk");
      if (!risk) return;
      if (panel) panel.setAttribute("data-level", risk.label || "inconnu");

      $("#detail-risk-score").textContent = String(risk.score);
      $("#detail-risk-label").textContent = risk.label || "—";
      $("#detail-risk-summary").textContent = risk.summary || "";

      var reasons = risk.reasons || [];
      replace($("#detail-risk-reasons"), reasons.length
        ? reasons.map(function (reason) {
            return h("li", null, [
              h("span", { class: "reason-points", text: "+" + reason.points }),
              h("span", { text: reason.fact }),
              h("span", { class: "reason-basis", text: "pourquoi : " + reason.basis })
            ]);
          })
        : h("li", { class: "empty", text: "Aucun élément particulier ne retient l'attention." }));
    }

    function renderIntel(intel) {
      var box = $("#detail-intel");
      if (!intel || (!intel.source && !intel.error)) {
        replace(box, h("p", { class: "empty", text: "Aucune donnée externe disponible." }));
        return;
      }
      if (intel.error) {
        replace(box, h("p", { class: "empty", text: intel.error }));
        return;
      }
      replace(box, h("dl", { class: "kv" }, [
        kvRow("Portée", intel.scope),
        kvRow("Pays", intel.country),
        kvRow("Ville", intel.city),
        kvRow("Opérateur", intel.isp || intel.org),
        kvRow("Système autonome", intel.asn),
        kvRow("Nom DNS inverse", intel.reverse_dns),
        kvRow("Source", intel.source)
      ]));
    }

    function load() {
      api("/api/flow?key=" + encodeURIComponent(key)).then(function (data) {
        loading.hidden = true;
        root.hidden = false;
        render(data);
      }).catch(function (error) {
        loading.hidden = true;
        errorBox.hidden = false;
        $("#detail-error-text").textContent = error.message;
      });
    }

    var enrichBtn = $("#btn-enrich");
    if (enrichBtn) {
      enrichBtn.addEventListener("click", function () {
        enrichBtn.disabled = true;
        enrichBtn.textContent = "Interrogation…";
        api("/api/flow?key=" + encodeURIComponent(key)).then(function (data) {
          if (data.intel && data.intel.source) {
            renderIntel(data.intel);
            flash("Informations externes récupérées (" + data.intel.source + ").", "ok");
          } else {
            flash("La source externe n'a pas répondu pour cette adresse.", "warn");
          }
        }).catch(function (error) {
          flash(error.message, "error");
        }).finally(function () {
          enrichBtn.disabled = false;
          enrichBtn.textContent = "Interroger la source externe";
        });
      });
    }

    /* Suivre la conversation : reconstitution du contenu echange, sens par sens.
       Chargee a la demande seulement : rien ne justifie de re-disséquer tous les
       paquets d'une communication si l'utilisateur ne le demande pas. */
    var streamBtn = $("#btn-stream");
    var streamZone = $("#stream-zone");
    if (streamBtn && streamZone) {
      streamBtn.addEventListener("click", function () {
        streamBtn.disabled = true;
        streamBtn.textContent = "Reconstitution…";
        api("/api/stream?key=" + encodeURIComponent(key)).then(function (data) {
          rendreFlux(streamZone, data.stream);
        }).catch(function (erreur) {
          replace(streamZone, h("p", { class: "empty", text: erreur.message }));
        }).finally(function () {
          streamBtn.disabled = false;
          streamBtn.textContent = "Reconstituer l'échange";
        });
      });
    }

    load();
  }

  /* Reconstitution d'une conversation : un bloc par sens de circulation. */
  function rendreFlux(zone, flux) {
    if (!zone) return;
    if (!flux || !flux.sens || !flux.sens.length) {
      replace(zone, h("p", { class: "empty", text: (flux && flux.note) ||
        "Aucun contenu à reconstituer pour cette communication." }));
      return;
    }

    var blocs = [];
    if (flux.note) {
      // La reserve vient en premier : elle change la lecture de tout ce qui
      // suit, et la placer apres reviendrait a la cacher.
      blocs.push(h("p", { class: "stream-note", text: flux.note }));
    }

    flux.sens.forEach(function (sens) {
      blocs.push(h("div", { class: "stream-sens" }, [
        h("h3", { class: "stream-titre", text: sens.label }),
        h("p", { class: "stream-meta",
                 text: sens.segments + " segment(s) · " + fmtBytes(sens.octets) }),
        sens.sans_contenu
          ? h("p", { class: "empty",
                     text: "Aucun contenu dans ce sens : uniquement de la "
                           + "signalisation (ouverture, acquittements, fermeture)." })
          : sens.binaire
            ? h("p", { class: "empty",
                       text: "Contenu non textuel : " + fmtBytes(sens.octets) +
                             " d'octets conservés, mais ils ne se lisent pas." })
            : h("pre", { class: "stream-texte", text: sens.texte })
      ]));
    });

    replace(zone, blocs);
  }

  /* ------------------------------------------------------------ 5. evenements */

  function initEvents() {
    var box = $("#event-list");
    if (!box) return;

    var filter = $("#event-kind-filter");
    var counter = $("#event-count");
    var buffer = [];

    function render() {
      var wanted = filter.value;
      var events = wanted ? buffer.filter(function (e) { return e.kind === wanted; }) : buffer;
      counter.textContent = events.length + " événement(s)";

      replace(box, events.length ? events.map(function (event) {
        var chips = Object.keys(event.evidence || {}).map(function (key) {
          var value = event.evidence[key];
          var text = Array.isArray(value) ? value.slice(0, 6).join(", ") : String(value);
          return h("span", { class: "evidence-chip" }, [
            h("b", { text: key + " : " }),
            document.createTextNode(text)
          ]);
        });
        return h("article", { class: "event", "data-kind": event.kind, "data-severity": event.severity }, [
          h("div", { class: "event-head" }, [
            h("div", null, [
              h("span", { class: "kind kind--" + event.kind.toLowerCase(), text: event.kind }),
              h("h3", { class: "event-title", text: event.title })
            ]),
            h("span", { class: "event-meta" }, [
              document.createTextNode(fmtClock(event.ts) + " · "),
              h("span", { class: "sev sev--" + event.severity, text: "gravité " + event.severity })
            ])
          ]),
          h("p", { class: "event-body", text: event.explanation }),
          event.actor ? h("p", { class: "event-meta", text: "hôte concerné : " + event.actor }) : null,
          chips.length ? h("div", { class: "event-evidence" }, chips) : null
        ]);
      }) : h("p", { class: "empty", text: "Aucun événement détecté pour l'instant." }));
    }

    function load() {
      api("/api/events?limit=200").then(function (data) {
        buffer = data.events || [];
        render();
      }).catch(function (error) { counter.textContent = "Erreur : " + error.message; });
    }

    filter.addEventListener("change", render);
    window.__pkaRefresh = load;
    load();
    setInterval(load, REFRESH_MS);
  }

  /* ------------------------------------------------------------- 6. historique */

  function initHistory() {
    var select = $("#session-select");
    if (!select) return;

    var flowsBody = $("#history-flows");
    var eventsBox = $("#history-events");
    var summary = $("#session-summary");
    var counter = $("#history-count");
    var sessionsLoaded = false;

    function kvRow(label, value) {
      return h("div", { class: "kv-row" }, [
        h("dt", { text: label }),
        h("dd", { text: value === null || value === undefined || value === "" ? "—" : String(value) })
      ]);
    }

    function render(data) {
      var session = data.session;
      counter.textContent = (data.sessions || []).length + " session(s) enregistrée(s)";

      if (!session) {
        replace(summary, kvRow("—", "Aucune session enregistrée pour l'instant."));
        replace(flowsBody, emptyRow(8, "Aucune donnée enregistrée."));
        replace(eventsBox, h("p", { class: "empty", text: "Aucun événement enregistré." }));
        return;
      }

      // Une session non clôturée n'a pas encore de totaux : les afficher a zero
      // laisserait croire qu'aucun paquet n'a ete capture.
      var enCours = !session.stopped_at;
      var total = function (value) { return enCours ? "en cours" : value; };

      var lignes = [
        kvRow("Session", "#" + session.id),
        kvRow("Démarrée le", fmtDateTime(session.started_at)),
        kvRow("Terminée le", session.stopped_at ? fmtDateTime(session.stopped_at) : "en cours"),
        kvRow("Mode", session.mode),
        kvRow("Interface", session.interface_name || session.interface),
        kvRow("Filtre de capture", session.filter || "aucun"),
        kvRow("Paquets (total de la session)", total(session.packets)),
        kvRow("Volume (total de la session)", total(fmtBytes(session.bytes_total))),
        kvRow("Communications enregistrées", (data.flows || []).length),
        kvRow("Événements enregistrés", (data.events || []).length)
      ];
      // La note explique pourquoi une session s'est terminee : sans elle, une
      // session interrompue ressemble a une capture qui a echoue.
      if (session.note) lignes.push(kvRow("Note", session.note));

      replace(summary, lignes);

      var flows = data.flows || [];
      replace(flowsBody, flows.length ? flows.map(function (flow) {
        return h("tr", null, [
          h("td", { class: "mono endpoint", text: flow.src }),
          h("td", { class: "mono endpoint", text: flow.dst }),
          h("td", { class: "mono num", text: flow.dst_port === null ? "—" : String(flow.dst_port) }),
          h("td", null, badgeFor(flow.app_protocol || flow.transport)),
          h("td", { class: "mono", text: flow.domain || "—" }),
          h("td", { class: "mono num", text: String(flow.packets) }),
          h("td", { class: "mono num", text: fmtBytes(flow.bytes_total) }),
          h("td", { class: "summary-cell", text: flow.explanation || "—" })
        ]);
      }) : emptyRow(8, "Aucune communication enregistrée pour cette session."));

      var events = data.events || [];
      replace(eventsBox, events.length ? events.map(function (event) {
        return h("article", { class: "event", "data-kind": event.kind, "data-severity": event.severity }, [
          h("div", { class: "event-head" }, [
            h("h3", { class: "event-title", text: event.title }),
            h("span", { class: "event-meta", text: fmtClock(event.ts) })
          ]),
          h("p", { class: "event-body", text: event.explanation })
        ]);
      }) : h("p", { class: "empty", text: "Aucun événement enregistré." }));
    }

    function load(sessionId) {
      var path = "/api/history" + (sessionId ? "?session_id=" + encodeURIComponent(sessionId) : "");
      api(path).then(function (data) {
        // Le gabarit contient deja une option « Chargement… » : tester la
        // longueur de la liste ne suffit donc jamais a detecter le premier
        // remplissage. On utilise un drapeau explicite.
        if (!sessionsLoaded) {
          sessionsLoaded = true;
          clear(select);

          var sessions = data.sessions || [];
          if (!sessions.length) {
            select.append(h("option", { value: "", text: "aucune session enregistrée" }));
          } else {
            sessions.forEach(function (session) {
              // Le nombre de paquets d'une session n'est ecrit qu'a sa cloture :
              // afficher « 0 paquets » pour une capture en cours serait faux.
              var detail = session.stopped_at
                ? (session.packets || 0) + " paquets"
                : "en cours";
              select.append(h("option", {
                value: String(session.id),
                text: "#" + session.id + " — " + fmtDateTime(session.started_at) +
                      " (" + (session.interface_name || session.interface || "interface inconnue") +
                      ") — " + detail
              }));
            });
            if (data.session) select.value = String(data.session.id);
          }
        }
        render(data);
      }).catch(function (error) { counter.textContent = "Erreur : " + error.message; });
    }

    select.addEventListener("change", function () { load(select.value); });
    load();
  }

  /* ------------------------------------------------- 8. base de connaissance */

  function initProtocols() {
    var body = $("#kb-ports");
    if (!body) return;

    var counter = $("#kb-count");
    var searchInput = $("#kb-search");
    var filterSelect = $("#kb-filter");
    var ports = [];
    var debounce = null;

    function renderPorts() {
      var needle = (searchInput.value || "").trim().toLowerCase();
      var mode = filterSelect.value;

      var filtered = ports.filter(function (entry) {
        if (mode === "sensitive" && !entry.sensitive) return false;
        if (mode === "cleartext" && entry.cleartext !== true) return false;
        if (!needle) return true;
        return String(entry.port).indexOf(needle) !== -1
          || entry.service.toLowerCase().indexOf(needle) !== -1
          || entry.meaning.toLowerCase().indexOf(needle) !== -1
          || entry.why.toLowerCase().indexOf(needle) !== -1;
      });

      counter.textContent = filtered.length + " service(s) sur " + ports.length;

      replace(body, filtered.length ? filtered.map(function (entry) {
        var proprietes = [];
        if (entry.sensitive) {
          proprietes.push(h("span", { class: "badge badge--risk", text: "à surveiller" }));
        }
        if (entry.cleartext === true) {
          proprietes.push(h("span", { class: "badge badge--http", text: "en clair" }));
        }
        if (entry.cleartext === false || entry.cleartext === null) {
          if (entry.cleartext === false) {
            proprietes.push(h("span", { class: "badge", text: "chiffré" }));
          }
        }
        return h("tr", null, [
          h("td", { class: "mono", text: String(entry.port) }),
          h("td", { class: "mono", text: entry.transport }),
          h("td", { text: entry.service }),
          h("td", { text: entry.meaning }),
          h("td", { text: entry.why }),
          h("td", null, h("span", { class: "badge", text: entry.confidence })),
          h("td", null, proprietes.length ? proprietes : h("span", { class: "muted", text: "—" }))
        ]);
      }) : emptyRow(7, "Aucun service ne correspond à cette recherche."));
    }

    function card(title, lines) {
      return h("div", { class: "kb-card" }, [
        h("h3", { class: "kb-card-title", text: title }),
        h("dl", { class: "kv" }, lines)
      ]);
    }

    function kvPair(label, value) {
      return h("div", { class: "kv-row" }, [
        h("dt", { text: label }),
        h("dd", { text: value })
      ]);
    }

    api("/api/protocols").then(function (data) {
      ports = data.ports || [];
      renderPorts();

      replace($("#kb-transports"), (data.transports || []).map(function (item) {
        return card(item.name + " — " + item.reliability, [
          kvPair("Rôle", item.role),
          kvPair("Usage typique", item.example)
        ]);
      }));

      replace($("#kb-applications"), (data.applications || []).map(function (item) {
        return card(item.name + (item.readable ? " — lisible" : " — chiffré"), [
          kvPair("Ce que c'est", item.what),
          kvPair("Comment on le reconnaît", item.clues)
        ]);
      }));

      replace($("#kb-flags"), (data.tcp_flags || []).map(function (item) {
        return kvPair(item.flags, item.meaning);
      }));

      replace($("#kb-network"), (data.network || []).map(function (item) {
        return kvPair(item.term, item.meaning);
      }));

      replace($("#kb-scopes"), (data.scopes || []).map(function (item) {
        return kvPair(item.key, item.label);
      }));
    }).catch(function (error) {
      counter.textContent = "Erreur : " + error.message;
    });

    searchInput.addEventListener("input", function () {
      if (debounce) clearTimeout(debounce);
      debounce = setTimeout(renderPorts, 200);
    });
    filterSelect.addEventListener("change", renderPorts);
  }

  /* ---------------------------------------------------------------- 9. theme */

  function initTheme() {
    var toggle = $("#theme-toggle");
    var sombre = $("#btn-theme-sombre");
    var clair = $("#btn-theme-clair");

    function appliquer(nom) {
      document.documentElement.setAttribute("data-theme", nom);
      document.cookie = "pka_theme=" + nom + ";path=/;max-age=31536000;samesite=lax";
      if (toggle) toggle.setAttribute("aria-pressed", nom === "light" ? "true" : "false");
    }

    if (toggle) {
      toggle.addEventListener("click", function () {
        var actuel = document.documentElement.getAttribute("data-theme") || "dark";
        appliquer(actuel === "dark" ? "light" : "dark");
      });
    }
    // La page Parametres propose les deux choix explicitement, plutot qu'une
    // bascule : on ne devine pas dans quel theme on se trouve.
    if (sombre) sombre.addEventListener("click", function () { appliquer("dark"); });
    if (clair) clair.addEventListener("click", function () { appliquer("light"); });
  }

  /* ----------------------------------------------------- 9. detail d'un paquet */

  function initPacketDetail() {
    var zone = $("#packet-body");
    if (!zone) return;

    var numero = parseInt(zone.getAttribute("data-packet-number") || "0", 10);
    if (!numero) {
      replace(zone, h("p", { class: "empty", text: "Aucun paquet n'a ete designe." }));
      return;
    }

    api("/api/packet?number=" + numero).then(function (data) {
      afficherPaquet(zone, data.packet || {});
    }).catch(function (erreur) {
      replace(zone, h("div", { class: "callout callout--warning" }, [
        h("h3", { text: "Contenu indisponible" }),
        h("p", { text: erreur.message })
      ]));
    });
  }

  function afficherPaquet(zone, paquet) {
    var dissection = paquet.dissection || {};
    var morceaux = [];

    var resume = [
      ["Numero", String(paquet.number)],
      ["Instant", fmtClock(paquet.ts)],
      ["Protocole", paquet.protocol || "?"],
      ["Taille", (paquet.size || 0) + " octets"],
      ["Source", endpoint(paquet.src, paquet.src_port)],
      ["Destination", endpoint(paquet.dst, paquet.dst_port)]
    ];
    if (paquet.domain) resume.push(["Nom de domaine", paquet.domain]);
    if (paquet.geo && !paquet.geo.error) {
      resume.push(["Pays (source externe)",
                   (paquet.geo.country || "—") + (paquet.geo.city ? " · " + paquet.geo.city : "")]);
      if (paquet.geo.org) resume.push(["Organisation", paquet.geo.org]);
    }

    var enfants = [];
    resume.forEach(function (paire) {
      enfants.push(h("dt", { text: paire[0] }));
      enfants.push(h("dd", { class: "mono", text: paire[1] }));
    });
    morceaux.push(h("section", { class: "panel" }, [
      h("h2", { class: "panel-title", text: "Resume du paquet" }),
      h("dl", { class: "detail-list" }, enfants)
    ]));

    if (dissection.error) {
      morceaux.push(h("div", { class: "callout callout--warning" }, [
        h("h3", { text: "Dissection partielle" }),
        h("p", { text: dissection.error })
      ]));
    }

    var couches = h("section", { class: "panel" }, [
      h("h2", { class: "panel-title", text: "Couches du protocole" }),
      h("p", { class: "panel-note",
               text: "Chaque bloc est un protocole empile dans le paquet, avec les valeurs reellement lues. Le nom technique du champ est conserve pour permettre de le retrouver dans la documentation du protocole." })
    ]);
    var listeCouches = dissection.layers || [];
    if (!listeCouches.length) {
      couches.append(h("p", { class: "empty", text: "Aucune couche n'a pu etre identifiee." }));
    }
    listeCouches.forEach(function (couche) {
      var lignes = (couche.fields || []).map(function (champ) {
        return h("tr", null, [
          h("td", { class: "mono", text: champ.name }),
          h("td", { text: champ.label }),
          h("td", { class: "mono detail-value", text: champ.value })
        ]);
      });
      couches.append(h("div", { class: "layer" }, [
        h("h3", { class: "layer-title", text: couche.name }),
        h("p", { class: "layer-summary mono", text: couche.summary || "" }),
        h("div", { class: "table-wrap" }, h("table", { class: "table table--dense" }, [
          h("thead", null, h("tr", null, [
            h("th", { scope: "col", text: "Champ" }),
            h("th", { scope: "col", text: "Signification" }),
            h("th", { scope: "col", text: "Valeur" })
          ])),
          h("tbody", null, lignes)
        ]))
      ]));
    });
    morceaux.push(couches);

    var lignesHex = dissection.hex || [];
    var texteHex = lignesHex.map(function (ligne) {
      return ligne.offset + "  " + ligne.hex + "  " + ligne.ascii;
    }).join("\n");
    morceaux.push(h("section", { class: "panel" }, [
      h("h2", { class: "panel-title", text: "Contenu brut" }),
      h("p", { class: "panel-note",
               text: "Octets tels qu'ils ont circule sur le reseau : a gauche leur position, au centre leur valeur en hexadecimal, a droite leur equivalent en caracteres. Un point remplace un octet non affichable." }),
      h("pre", { class: "hexdump", text: texteHex || "(aucun contenu)" })
    ]));

    replace(zone, morceaux);
  }

  /* --------------------------------------------------------- 10. reseau local */

  function initNetwork() {
    var corpsAppareils = $("#net-devices");
    if (!corpsAppareils) return;

    function charger() {
      api("/api/devices").then(function (data) {
        var appareils = data.devices || [];
        var services = data.services || [];

        $("#net-count").textContent = appareils.length
          ? appareils.length + " appareil(s) observé(s)"
          : "Aucun appareil observé pour l'instant.";

        replace(corpsAppareils, appareils.length ? appareils.map(function (appareil) {
          var annonces = (appareil.services || []).filter(function (s) { return s.label; });
          var contenu = annonces.length ? annonces.map(function (s) {
            var sens = s.announced && s.searched ? "annonce et recherche"
                     : (s.announced ? "annonce" : "recherche");
            return h("span", {
              class: "badge " + (s.announced ? "badge--http" : ""),
              text: s.label + " — " + sens,
              title: s.type
            });
          }) : "—";

          var adresses = (appareil.addresses || [appareil.ip]);
          var cellulesAdresses = adresses.map(function (a) {
            return h("div", { class: "mono", text: a });
          });
          if (appareil.hostname) {
            cellulesAdresses.push(h("div", { class: "hostname", text: appareil.hostname }));
          }
          if (appareil.is_local) {
            cellulesAdresses.push(h("div", { class: "hostname", text: "cette machine" }));
          }

          return h("tr", null, [
            h("td", { class: "addresses" }, cellulesAdresses),
            h("td", { class: "mono", text: appareil.mac || "inconnue" }),
            h("td", { class: "mono num", text: String(appareil.packets || 0) }),
            h("td", null, contenu),
            h("td", { class: "mono instant", text: fmtClock(appareil.last_seen) })
          ]);
        }) : emptyRow(5, "Aucun appareil observé pour l'instant. Démarrez une capture."));

        replace($("#net-services"), services.length ? services.map(function (service) {
          var sens = service.announced && service.searched ? "annoncé et recherché"
                   : (service.announced ? "annoncé" : "recherché");
          return h("tr", null, [
            h("td", { text: service.label || ("Services propriétaires non documentés (" + String(service.count || 0) + ")") ,
                      title: (service.types || []).join(", ") }),
            h("td", { class: "mono", text: service.type }),
            h("td", null, h("span", {
              class: "badge" + (service.announced ? " badge--http" : ""),
              text: sens
            })),
            h("td", { class: "mono", text: (service.actors || []).join(", ") || "—" }),
            h("td", { text: (service.instances || []).join(", ") || "—" })
          ]);
        }) : emptyRow(5, "Aucun service observé pour l'instant."));
      }).catch(function (erreur) {
        $("#net-count").textContent = "Erreur : " + erreur.message;
      });
    }

    charger();
    setInterval(charger, REFRESH_MS * 2);
    window.__pkaRefresh = charger;
  }

  /* ------------------------------------------------------- 10. parametres */

  /* ----------------------------------------------------- barre de menus */

  /* Les menus s'ouvrent au clic, pas au survol : sur un ecran tactile le survol
     n'existe pas, et un menu qui s'ouvre au passage de la souris se referme des
     qu'on descend vers l'element vise. */
  function initMenubar() {
    var barre = $("#menubar");
    if (!barre) return;

    var menus = [].slice.call(barre.querySelectorAll("[data-menu]"));

    function fermer(except) {
      menus.forEach(function (menu) {
        if (menu === except) return;
        menu.removeAttribute("data-ouvert");
        var titre = menu.querySelector(".menu-titre");
        if (titre) titre.setAttribute("aria-expanded", "false");
      });
    }

    menus.forEach(function (menu) {
      var titre = menu.querySelector(".menu-titre");
      if (!titre) return;
      titre.addEventListener("click", function (evenement) {
        evenement.stopPropagation();
        var ouvert = menu.getAttribute("data-ouvert") === "oui";
        fermer(null);
        if (!ouvert) {
          menu.setAttribute("data-ouvert", "oui");
          titre.setAttribute("aria-expanded", "true");
        }
      });
    });

    // Un clic ailleurs, ou Echap, referme : sans cela le menu resterait ouvert
    // au-dessus de la page et masquerait ce qu'on vient de demander.
    document.addEventListener("click", function () { fermer(null); });
    document.addEventListener("keydown", function (evenement) {
      if (evenement.key === "Escape") fermer(null);
    });

    // Les actions sont confiees aux boutons qui existent deja dans la barre du
    // haut : deux codes differents pour la meme action finiraient par diverger.
    barre.addEventListener("click", function (evenement) {
      var cible = evenement.target.closest("[data-menu-action]");
      if (!cible) return;
      var action = cible.getAttribute("data-menu-action");
      fermer(null);

      if (action === "open-pcap") {
        // Le champ de fichier vit sur la page des paquets : on y va, et la page
        // ouvre le selecteur a l'arrivee (voir initPackets).
        if (document.querySelector("#pcap-file")) {
          document.querySelector("#pcap-file").click();
        } else {
          window.location.href = "/packets#ouvrir-pcap";
        }
        return;
      }

      var bouton = { "capture-start": "#capture-start",
                     "capture-stop": "#capture-stop",
                     "capture-clear": "#capture-clear" }[action];
      var vrai = bouton && document.querySelector(bouton);
      if (vrai && !vrai.disabled) vrai.click();
    });
  }

  function initSettings() {
    var config = $("#settings-config");
    var problemes = $("#settings-problems");
    var services = $("#settings-services");
    var donnees = $("#settings-data");
    if (!config) return;

    function ligne(terme, valeur) {
      return h("div", { class: "kv-row" }, [
        h("dt", { text: terme }),
        h("dd", { text: valeur })
      ]);
    }

    api("/api/settings").then(function (data) {
      var s = data.settings || {};
      replace(config, [
        ligne("Environnement", s.environnement || "—"),
        ligne("Mode", s.mode === "cloud"
          ? "cloud (lecture seule de l'historique)"
          : "local (capture en direct)"),
        ligne("Capture réseau", s.capture_locale
          ? "disponible" : "indisponible dans ce mode"),
        ligne("Interface par défaut", s.interface_par_defaut || "détection automatique"),
        ligne("Paquets gardés en mémoire", String(s.memoire_paquets || "—")),
        ligne("Base de données locale", s.base_locale || "—"),
        ligne("Enrichissement des adresses",
          (s.enrichissement.actif ? "activé" : "désactivé") +
          (s.enrichissement.actif ? " — " + s.enrichissement.adresses_connues +
            " adresse(s) connue(s), " + s.enrichissement.en_attente + " en attente" : "") +
          ", cache de " + s.enrichissement.cache_heures + " h"),
        ligne("Supabase",
          (s.supabase.actif ? "activé" : "désactivé") +
          " — adresse " + (s.supabase.adresse_fournie ? "fournie" : "absente") +
          ", clé " + (s.supabase.cle_fournie ? "fournie" : "absente")),
        ligne("Assistant IA",
          (s.assistant_ia.actif ? "activé" : "désactivé") +
          " (" + s.assistant_ia.fournisseur + " / " + s.assistant_ia.modele + ")" +
          ", clé " + (s.assistant_ia.cle_fournie ? "fournie" : "absente")),
        ligne("AbuseIPDB", s.abuseipdb.cle_fournie ? "clé fournie" : "clé absente"),
        ligne("Clé de signature des sessions",
          s.secret_signe.fourni ? "fournie (32 caractères ou plus)" : "absente ou trop courte")
      ]);

      var liste = data.problems || [];
      replace(problemes, liste.length
        ? h("ul", { class: "problemes-liste" }, liste.map(function (texte) {
            return h("li", { text: texte });
          }))
        : h("p", { class: "vide-ok", text: "Aucun problème détecté dans la configuration." }));
    }).catch(function (erreur) {
      replace(config, h("div", { class: "kv-row" }, [
        h("dt", { text: "Erreur" }), h("dd", { text: erreur.message })
      ]));
    });

    api("/api/dependencies").then(function (data) {
      replace(services, [
        serviceRow("Base locale", etat(data.base_locale.disponible), data.base_locale.chemin),
        serviceRow("Supabase",
          data.supabase.active === false ? "off" : etat(data.supabase.disponible),
          data.supabase.active === false
            ? "désactivé (SUPABASE_ENABLED=false)"
            : (data.supabase.erreur || "connecté")),
        serviceRow("Capture réseau", etat(data.capture.disponible),
          data.capture.disponible
            ? data.capture.interfaces + " interface(s) disponible(s)"
            : data.capture.message),
        serviceRow("Enrichissement",
          data.enrichissement.active ? "ok" : "off",
          data.enrichissement.active
            ? data.enrichissement.appels_externes + " appel(s) externe(s)"
            : "désactivé")
      ]);
    }).catch(function (erreur) {
      replace(services, h("p", { class: "empty", text: "Indisponible : " + erreur.message }));
    });

    api("/api/stats").then(function (data) {
      replace(donnees, [
        ligne("Paquets capturés depuis le démarrage", String(data.packets || 0)),
        ligne("Communications observées", String(data.flows || 0)),
        ligne("Appareils vus sur le réseau local", String(data.devices ? data.devices.length : 0)),
        ligne("Volume total", fmtBytes(data.bytes || 0)),
        ligne("Sessions enregistrées", String(data.sessions || 0))
      ]);
    }).catch(function () {
      replace(donnees, h("div", { class: "kv-row" }, [
        h("dt", { text: "Indisponible" }), h("dd", { text: "Démarrez une capture." })
      ]));
    });

    /* Ce qui est ecrit sur le disque.

       Une capture qui tourne grossit sans fin : sans ce rapport, l'utilisateur
       ne peut pas savoir que sa base occupe des centaines de megaoctets, ni
       pourquoi l'application ralentit au demarrage. */
    function chargerStockage() {
      api("/api/data/storage").then(function (data) {
        var lignes = data.rows || {};
        replace(donnees, [
          ligne("Taille de la base",
            fmtBytes(data.bytes) + (data.free_bytes
              ? " — dont " + fmtBytes(data.free_bytes) + " récupérables par compactage"
              : "")),
          ligne("Sessions enregistrées", String(lignes.capture_sessions || 0)),
          ligne("Communications enregistrées", String(lignes.flows || 0)),
          ligne("Paquets enregistrés", String(lignes.packets || 0)),
          ligne("Événements enregistrés", String(lignes.events || 0)),
          ligne("Adresses enrichies", String(lignes.ip_intel || 0)),
          ligne("Lignes sans session", data.orphans === 0
            ? "aucune" : String(data.orphans) + " — anormal, à signaler")
        ]);

        // L'avertissement n'apparait que s'il a une raison d'etre : l'afficher
        // en permanence banaliserait l'alerte.
        var alerte = $("#storage-alerte");
        if (alerte) alerte.hidden = data.bytes < 50 * 1024 * 1024;
      }).catch(function (erreur) {
        replace(donnees, h("div", { class: "kv-row" }, [
          h("dt", { text: "Indisponible" }), h("dd", { text: erreur.message })
        ]));
      });
    }
    chargerStockage();

    var boutonPurge = $("#btn-purge");
    if (boutonPurge) {
      boutonPurge.addEventListener("click", function () {
        var champGarder = $("#purge-keep");
        var garder = parseInt((champGarder && champGarder.value) || "10", 10);
        if (!(garder >= 0)) garder = 10;
        var compacter = !!($("#purge-vacuum") || {}).checked;
        var resultat = $("#purge-resultat");

        // Suppression definitive : on demande confirmation, en annoncant le
        // nombre de sessions concernees.
        if (!window.confirm(
              "Supprimer toutes les sessions sauf les " + garder +
              " plus récentes ?\n\nCette action est définitive.")) {
          return;
        }

        boutonPurge.disabled = true;
        boutonPurge.textContent = "Suppression en cours…";
        api("/api/data/purge?keep=" + garder + (compacter ? "&vacuum=true" : ""),
            { method: "POST" })
          .then(function (data) {
            if (resultat) {
              resultat.textContent = data.removed === 0
                ? "Aucune session à supprimer : " + data.kept + " session(s) conservée(s)."
                : data.removed + " session(s) supprimée(s), " + data.kept +
                  " conservée(s)." + (data.vacuumed ? " Base compactée." : "");
            }
            chargerStockage();
          })
          .catch(function (erreur) {
            if (resultat) resultat.textContent = "Suppression refusée — " + erreur.message;
          })
          .finally(function () {
            boutonPurge.disabled = false;
            boutonPurge.textContent = "Supprimer les sessions plus anciennes";
          });
      });
    }
  }

  /* ------------------------------------------------------------------ demarrage */

  function boot() {
    initCaptureControls();
    initMenubar();
    initSummaryAndServices();
    initDashboard();
    initPackets();
    initFlows();
    initFlowDetail();
    initEvents();
    initHistory();
    initProtocols();
    initPacketDetail();
    initNetwork();
    initSettings();
    initTheme();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
