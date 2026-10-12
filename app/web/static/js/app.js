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
      var serviceRow = function (label, state, detail) {
        return h("div", { class: "service-item", "data-state": state }, [
          h("span", { class: "service-dot", "aria-hidden": "true" }),
          h("span", { class: "service-label", text: label }),
          h("span", { class: "service-detail", text: detail })
        ]);
      };

      var etat = function (flag) {
        if (flag === true) return "ok";
        if (flag === false) return "ko";
        return "off";
      };

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
        try { render(JSON.parse(message.data)); } catch (error) { /* ignore */ }
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

    var searchInput = $("#packet-search");
    var protocolSelect = $("#packet-protocol");
    var counter = $("#packet-count");
    var debounce = null;

    function load() {
      var params = new URLSearchParams({ limit: "300" });
      if (searchInput.value.trim()) params.set("search", searchInput.value.trim());
      if (protocolSelect.value) params.set("protocol", protocolSelect.value);

      api("/api/packets?" + params.toString()).then(function (data) {
        var records = data.packets || [];
        counter.textContent = records.length + " paquet(s) affiché(s)";
        replace(body, records.length ? records.map(function (record) {
          return packetTableRow(record);
        }) : emptyRow(9, "Aucun paquet capturé pour l'instant."));
        suivreNouveaux();
      }).catch(function (error) {
        counter.textContent = "Erreur : " + error.message;
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

    searchInput.addEventListener("input", function () {
      if (debounce) clearTimeout(debounce);
      debounce = setTimeout(load, 220);
    });
    protocolSelect.addEventListener("change", load);

    /* L'identification geographique se fait en arriere-plan, une adresse a la
       fois. Tant qu'il en reste, un tiret dans la colonne Pays ne veut pas dire
       « adresse sans pays » : on le dit explicitement. */
    function noteGeographique() {
      var note = $("#geo-note");
      if (!note) return;
      api("/api/stats").then(function (stats) {
        var attente = stats.geo_pending || 0;
        var connues = stats.geo_known || 0;
        if (attente > 0) {
          note.textContent = "· " + attente + " adresse(s) en cours d'identification";
          note.title = "Les tirets de la colonne Pays correspondent à des adresses "
                     + "pas encore identifiées, pas à des adresses sans pays.";
        } else {
          note.textContent = connues ? "· " + connues + " adresse(s) identifiée(s)" : "";
          note.title = "";
        }
      }).catch(function () { /* l'absence de cette note n'empeche pas la lecture */ });
    }

    window.__pkaRefresh = load;
    load();
    noteGeographique();
    setInterval(load, REFRESH_MS);
    setInterval(noteGeographique, 10000);
  }

  /* ------------------------------------------------------- 3. communications */

  function initFlows() {
    var body = $("#flow-rows");
    if (!body) return;

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

    load();
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
    if (!toggle) return;
    toggle.addEventListener("click", function () {
      var current = document.documentElement.getAttribute("data-theme") || "dark";
      var next = current === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      document.cookie = "pka_theme=" + next + ";path=/;max-age=31536000;samesite=lax";
      toggle.setAttribute("aria-pressed", next === "light" ? "true" : "false");
    });
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

  /* ------------------------------------------------------------------ demarrage */

  function boot() {
    initCaptureControls();
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
    initTheme();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
