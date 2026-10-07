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
      api("/api/interfaces").then(function (data) {
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
        flash(error.message, "error");
        setState("error", "Capture impossible");
        startBtn.disabled = false;
      });
    });

    if (stopBtn) {
      stopBtn.addEventListener("click", function () {
        api("/api/capture/stop", { method: "POST" })
          .then(function (data) {
            flash(data.message, "ok");
            setState("idle", "Capture arrêtée");
          })
          .catch(function (error) { flash(error.message, "error"); });
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

    loadInterfaces();

    // Etat initial : l'application peut avoir ete lancee avec une capture deja
    // en cours (ou avoir redemarre). On interroge le serveur au lieu de supposer.
    api("/api/stats").then(function (data) {
      if (data.capture && data.capture.running) {
        setState("running", "Capture en cours");
        if (data.capture.interface) {
          var match = Array.prototype.find.call(
            ifaceSelect.options, function (option) { return option.value === data.capture.interface_id; }
          );
          if (match) ifaceSelect.value = match.value;
        }
      } else {
        setState("idle", "Capture arrêtée");
      }
    }).catch(function () { setState("idle", "Capture arrêtée"); });

    return { setState: setState };
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
        return h("div", { class: "bar-row" }, [
          h("span", { class: "bar-label", text: item[labelKey], title: item[labelKey] }),
          h("div", { class: "bar-track" }, h("div", {
            class: "bar-fill", style: "width:" + Math.max(3, (item[countKey] / max) * 100) + "%"
          })),
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
        h("td", { class: "mono", text: String(record.number) }),
        h("td", { class: "mono", text: endpoint(record.src, record.src_port) }),
        h("td", { class: "mono", text: endpoint(record.dst, record.dst_port) }),
        h("td", null, badgeFor(record.protocol)),
        h("td", { class: "mono", text: record.tcp_flags || "—" }),
        h("td", { class: "mono", text: record.size + " o" }),
        h("td", { text: record.info || "" })
      ]);
    }

    function render(payload) {
      var stats = payload.stats || (payload.type === "stats" ? payload : null);
      if (!stats) {
        if (payload.capture) { /* reponse de /api/stats */ }
      }
      stats = stats || payload;

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
      if (errs.length) flash("Analyse : " + errs[0], "warn");
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
          return h("tr", null, [
            h("td", { class: "mono", text: String(record.number) }),
            h("td", { class: "mono", text: fmtClock(record.ts) }),
            h("td", { class: "mono", text: endpoint(record.src, record.src_port) }),
            h("td", { class: "mono", text: endpoint(record.dst, record.dst_port) }),
            h("td", null, badgeFor(record.protocol)),
            h("td", { class: "mono", text: record.tcp_flags || "—" }),
            h("td", { class: "mono", text: record.ttl === null ? "—" : String(record.ttl) }),
            h("td", { class: "mono", text: record.size + " o" }),
            h("td", { text: record.info || "", title: record.info || "" })
          ]);
        }) : emptyRow(9, "Aucun paquet capturé pour l'instant."));
      }).catch(function (error) {
        counter.textContent = "Erreur : " + error.message;
      });
    }

    searchInput.addEventListener("input", function () {
      if (debounce) clearTimeout(debounce);
      debounce = setTimeout(load, 220);
    });
    protocolSelect.addEventListener("change", load);

    window.__pkaRefresh = load;
    load();
    setInterval(load, REFRESH_MS);
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
            h("td", { class: "mono", text: flow.observer }),
            h("td", { class: "mono", text: flow.distant }),
            h("td", null, flow.service
              ? h("span", { class: flow.service_sensitive ? "badge badge--risk" : "badge", text: flow.service })
              : h("span", { class: "mono", text: flow.service_port === null ? "—" : String(flow.service_port) })),
            h("td", null, badgeFor(flow.app_protocol || flow.transport)),
            h("td", null, h("span", { class: stateClass(flow.state), text: flow.state_label || flow.state })),
            h("td", { class: "mono", text: String(flow.packets) }),
            h("td", { class: "mono", text: fmtBytes(flow.bytes_total) }),
            h("td", { class: "mono", text: fmtDuration(flow.duration) }),
            h("td", {
              text: flow.domain ? flow.domain : (flow.direction === "local" ? "sortant" : flow.direction === "distant" ? "entrant" : "indéterminé"),
              title: flow.domain || ""
            }),
            h("td", null, link)
          ]);
        }) : emptyRow(10, "Aucune communication observée pour l'instant."));
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

      if (data.intel && data.intel.source) {
        renderIntel(data.intel);
      }
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

      replace(summary, [
        kvRow("Session", "#" + session.id),
        kvRow("Démarrée le", fmtDateTime(session.started_at)),
        kvRow("Terminée le", session.stopped_at ? fmtDateTime(session.stopped_at) : "en cours"),
        kvRow("Mode", session.mode),
        kvRow("Interface", session.interface_name || session.interface),
        kvRow("Filtre de capture", session.filter || "aucun"),
        kvRow("Paquets", session.packets),
        kvRow("Volume", fmtBytes(session.bytes_total)),
        kvRow("Communications", session.flows_count),
        kvRow("Événements", session.events_count)
      ]);

      var flows = data.flows || [];
      replace(flowsBody, flows.length ? flows.map(function (flow) {
        return h("tr", null, [
          h("td", { class: "mono", text: flow.src }),
          h("td", { class: "mono", text: flow.dst }),
          h("td", { class: "mono", text: flow.dst_port === null ? "—" : String(flow.dst_port) }),
          h("td", null, badgeFor(flow.app_protocol || flow.transport)),
          h("td", { text: flow.domain || "—" }),
          h("td", { class: "mono", text: String(flow.packets) }),
          h("td", { class: "mono", text: fmtBytes(flow.bytes_total) }),
          h("td", { text: flow.explanation || "—" })
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
        if (!select.options.length) {
          (data.sessions || []).forEach(function (session) {
            select.append(h("option", {
              value: String(session.id),
              text: "#" + session.id + " — " + fmtDateTime(session.started_at) +
                    " (" + (session.interface_name || session.interface || "interface inconnue") + ")"
            }));
          });
          if (data.session) select.value = String(data.session.id);
        }
        render(data);
      }).catch(function (error) { counter.textContent = "Erreur : " + error.message; });
    }

    select.addEventListener("change", function () { load(select.value); });
    load();
  }

  /* ---------------------------------------------------------------- 7. theme */

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

  /* ------------------------------------------------------------------ demarrage */

  function boot() {
    initCaptureControls();
    initDashboard();
    initPackets();
    initFlows();
    initFlowDetail();
    initEvents();
    initHistory();
    initTheme();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
