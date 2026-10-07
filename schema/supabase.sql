-- ============================================================================
-- Intelligent Network Packet Analyzer — schema Supabase (PostgreSQL)
--
-- A APPLIQUER : Supabase -> SQL Editor -> coller ce fichier -> Run.
-- Le schema est idempotent : le relancer ne detruit aucune donnee.
--
-- Justification du modele (questions du cahier des charges) :
--
--   capture_sessions  Une ligne par campagne d'observation. Sans cette table,
--                     impossible de comparer deux analyses ni de savoir a
--                     quelle capture appartient une communication.
--
--   flows             Une ligne par COMMUNICATION, pas par paquet. C'est
--                     l'unite qui a du sens pour un analyste, et cela divise
--                     le volume stocke par plusieurs milliers.
--
--   events            Une ligne par fait remarquable, avec ses preuves
--                     chiffrees. Permet de rejouer une detection.
--
--   packets           Un echantillon plafonne de paquets bruts, pour la
--                     verification et la demonstration. Jamais l'integralite
--                     du trafic.
--
--   ip_intel          Cache de l'enrichissement externe : une adresse n'est
--                     interrogee qu'une fois par periode de validite.
-- ============================================================================

-- ---------------------------------------------------------------- sessions --

create table if not exists capture_sessions (
    id              bigserial primary key,
    started_at      double precision not null,
    stopped_at      double precision,
    mode            text not null default 'local',
    interface       text,
    interface_name  text,
    filter          text,
    packets         bigint not null default 0,
    bytes_total     bigint not null default 0,
    flows_count     integer not null default 0,
    events_count    integer not null default 0,
    note            text
);

-- ------------------------------------------------------------------- flux --

create table if not exists flows (
    id              bigserial primary key,
    session_id      bigint not null references capture_sessions(id) on delete cascade,
    flow_key        text not null,
    first_seen      double precision not null,
    last_seen       double precision not null,
    duration        double precision not null default 0,
    src             text not null,
    dst             text not null,
    src_port        integer,
    dst_port        integer,
    transport       text,
    app_protocol    text,
    domain          text,
    state           text,
    tcp_state       text,
    packets         integer not null default 0,
    bytes_total     bigint not null default 0,
    bytes_fwd       bigint not null default 0,
    bytes_rev       bigint not null default 0,
    retransmissions integer not null default 0,
    risk_score      integer not null default 0,
    explanation     text,
    -- Contrainte indispensable : l'application ecrit en mode "upsert", et
    -- c'est cette contrainte qui distingue une mise a jour d'un doublon.
    constraint flows_session_key_unique unique (session_id, flow_key)
);

-- --------------------------------------------------------------- evenements --

create table if not exists events (
    id              bigserial primary key,
    session_id      bigint not null references capture_sessions(id) on delete cascade,
    ts              double precision not null,
    kind            text not null check (kind in ('OBSERVATION', 'HYPOTHESE', 'ALERTE')),
    rule            text not null,
    severity        text not null default 'info'
                    check (severity in ('info', 'faible', 'moyen', 'eleve')),
    title           text not null,
    explanation     text not null,
    evidence        jsonb default '{}'::jsonb,
    actor           text,
    flow_key        text
);

-- ------------------------------------------------------- echantillon brut --

create table if not exists packets (
    id              bigserial primary key,
    session_id      bigint not null references capture_sessions(id) on delete cascade,
    number          integer not null,
    ts              double precision not null,
    src             text,
    dst             text,
    src_port        integer,
    dst_port        integer,
    protocol        text,
    transport       text,
    size            integer,
    tcp_flags       text,
    ttl             integer,
    info            text,
    domain          text
);

-- ------------------------------------------------- enrichissement (cache) --

create table if not exists ip_intel (
    ip              text primary key,
    scope           text,
    country         text,
    country_code    text,
    city            text,
    isp             text,
    org             text,
    asn             text,
    reverse_dns     text,
    source          text,
    fetched_at      double precision not null default 0,
    error           text
);

-- ------------------------------------------------------------------ index --

create index if not exists idx_flows_session     on flows(session_id);
create index if not exists idx_flows_last_seen   on flows(session_id, last_seen desc);
create index if not exists idx_flows_domain      on flows(domain);
create index if not exists idx_events_session    on events(session_id, ts desc);
create index if not exists idx_events_kind       on events(session_id, kind);
create index if not exists idx_packets_session   on packets(session_id, number);
create index if not exists idx_intel_fetched     on ip_intel(fetched_at desc);

-- ============================================================================
-- SECURITE (Row Level Security)
--
-- L'application serveur utilise la cle `service_role`, qui contourne RLS :
-- elle ne doit JAMAIS etre exposee dans un navigateur ni commitee dans Git.
--
-- RLS est activee ci-dessous SANS politique permissive : aucune cle publique
-- ne peut donc lire les captures. Si un jour une interface cliente directe
-- etait ajoutee, il faudrait ecrire une politique explicite plutot que
-- d'ouvrir les tables.
-- ============================================================================

alter table capture_sessions enable row level security;
alter table flows            enable row level security;
alter table events           enable row level security;
alter table packets          enable row level security;
alter table ip_intel         enable row level security;

-- ============================================================================
-- Verifications utiles apres application :
--
--   select count(*) from capture_sessions;
--   select src, dst, dst_port, app_protocol, domain, packets
--     from flows order by last_seen desc limit 20;
--   select kind, severity, title from events order by ts desc limit 20;
-- ============================================================================
