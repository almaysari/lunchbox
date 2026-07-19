# PostgreSQL Schema — Verified (extracted from a live database)

> يُولَّد هذا الملف حصريًا بـ `npm run verify:schema -- --update` — لا يُحرر يدويًا.
> `npm run verify:schema` يفشل إذا اختلف الـSchema الفعلي عن هذا الملف (يعمل في CI).

## الجداول والأعمدة والقيود (pg_dump --schema-only)

```sql
COMMENT ON SCHEMA public IS '';

CREATE TABLE public.acceptance_incidents (
    id bigint NOT NULL,
    run_id bigint NOT NULL,
    at timestamp with time zone DEFAULT now() NOT NULL,
    kind text NOT NULL,
    detail jsonb
);

CREATE SEQUENCE public.acceptance_incidents_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.acceptance_incidents_id_seq OWNED BY public.acceptance_incidents.id;

CREATE TABLE public.acceptance_runs (
    id bigint NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    planned_hours numeric NOT NULL,
    sample_sec integer DEFAULT 60 NOT NULL,
    canary text,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    ends_at timestamp with time zone NOT NULL,
    finished_at timestamp with time zone,
    evaluation jsonb,
    created_by bigint,
    CONSTRAINT acceptance_runs_status_check CHECK ((status = ANY (ARRAY['active'::text, 'completed'::text, 'aborted'::text])))
);

CREATE SEQUENCE public.acceptance_runs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.acceptance_runs_id_seq OWNED BY public.acceptance_runs.id;

CREATE TABLE public.acceptance_samples (
    id bigint NOT NULL,
    run_id bigint NOT NULL,
    at timestamp with time zone DEFAULT now() NOT NULL,
    worker_alive boolean NOT NULL,
    heartbeat_age_sec integer,
    worker_pid integer,
    stuck_jobs integer DEFAULT 0 NOT NULL,
    stuck_mailboxes integer DEFAULT 0 NOT NULL,
    occurrences_total bigint DEFAULT 0 NOT NULL,
    duplicate_occurrences integer DEFAULT 0 NOT NULL,
    duplicate_canonicals integer DEFAULT 0 NOT NULL,
    transport_errors jsonb,
    rss_bytes bigint,
    detail jsonb
);

CREATE SEQUENCE public.acceptance_samples_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.acceptance_samples_id_seq OWNED BY public.acceptance_samples.id;

CREATE TABLE public.archive_imports (
    id bigint NOT NULL,
    mailbox_id bigint NOT NULL,
    filename text DEFAULT ''::text NOT NULL,
    size_bytes bigint DEFAULT 0 NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    totals jsonb,
    error_detail text,
    uploaded_by bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    finished_at timestamp with time zone,
    CONSTRAINT archive_imports_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'importing'::text, 'completed'::text, 'failed'::text])))
);

CREATE SEQUENCE public.archive_imports_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.archive_imports_id_seq OWNED BY public.archive_imports.id;

CREATE TABLE public.attachments (
    id bigint NOT NULL,
    canonical_message_id bigint NOT NULL,
    provider_attachment_id text DEFAULT ''::text NOT NULL,
    original_filename text NOT NULL,
    sanitized_filename text NOT NULL,
    size bigint DEFAULT 0 NOT NULL,
    provider_mime_type text DEFAULT ''::text NOT NULL,
    detected_mime_type text DEFAULT ''::text NOT NULL,
    quarantine_status text DEFAULT 'pending'::text NOT NULL,
    storage_key text NOT NULL,
    sha256 text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT attachments_quarantine_status_check CHECK ((quarantine_status = ANY (ARRAY['pending'::text, 'clean'::text, 'quarantined'::text]))),
    CONSTRAINT attachments_size_check CHECK ((size >= 0))
);

CREATE SEQUENCE public.attachments_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.attachments_id_seq OWNED BY public.attachments.id;

CREATE TABLE public.audit_log (
    id bigint NOT NULL,
    at timestamp with time zone DEFAULT now() NOT NULL,
    user_id bigint,
    action text NOT NULL,
    target text DEFAULT ''::text NOT NULL,
    details text DEFAULT ''::text NOT NULL
);

CREATE SEQUENCE public.audit_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.audit_log_id_seq OWNED BY public.audit_log.id;

CREATE TABLE public.canonical_messages (
    id bigint NOT NULL,
    dedup_hash text NOT NULL,
    rfc_message_id text DEFAULT ''::text NOT NULL,
    thread_id text DEFAULT ''::text NOT NULL,
    from_address text DEFAULT ''::text NOT NULL,
    from_name text DEFAULT ''::text NOT NULL,
    to_addresses text DEFAULT ''::text NOT NULL,
    cc_addresses text DEFAULT ''::text NOT NULL,
    subject text DEFAULT ''::text NOT NULL,
    snippet text DEFAULT ''::text NOT NULL,
    body_html text,
    sent_at timestamp with time zone NOT NULL,
    has_attachments boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    fts tsvector GENERATED ALWAYS AS (to_tsvector('simple'::regconfig, ((((COALESCE(subject, ''::text) || ' '::text) || COALESCE(snippet, ''::text)) || ' '::text) || COALESCE(from_address, ''::text)))) STORED,
    canonical_hash_version integer DEFAULT 2 NOT NULL
);

CREATE SEQUENCE public.canonical_messages_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.canonical_messages_id_seq OWNED BY public.canonical_messages.id;

CREATE TABLE public.connections (
    id bigint NOT NULL,
    provider text DEFAULT 'zoho'::text NOT NULL,
    label text DEFAULT ''::text NOT NULL,
    accounts_base text DEFAULT 'https://accounts.zoho.com'::text NOT NULL,
    api_base text DEFAULT 'https://mail.zoho.com'::text NOT NULL,
    client_id text NOT NULL,
    client_secret_enc text NOT NULL,
    refresh_token_enc text,
    scopes text DEFAULT ''::text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    status_detail text DEFAULT ''::text NOT NULL,
    created_by bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    encryption_key_version integer DEFAULT 1 NOT NULL,
    access_token_enc text,
    access_token_expires_at timestamp with time zone,
    CONSTRAINT connections_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'connected'::text, 'error'::text])))
);

CREATE SEQUENCE public.connections_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.connections_id_seq OWNED BY public.connections.id;

CREATE TABLE public.detection_reports (
    id bigint NOT NULL,
    mailbox_id bigint DEFAULT 0 NOT NULL,
    at timestamp with time zone DEFAULT now() NOT NULL,
    report jsonb NOT NULL
);

CREATE SEQUENCE public.detection_reports_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.detection_reports_id_seq OWNED BY public.detection_reports.id;

CREATE TABLE public.fingerprint_metrics (
    id bigint NOT NULL,
    event_type text NOT NULL,
    fp3 text,
    rfc_incoming text,
    rfc_existing text,
    canonical_a bigint,
    canonical_b bigint,
    mailbox_id bigint,
    detail text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.fingerprint_metrics_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.fingerprint_metrics_id_seq OWNED BY public.fingerprint_metrics.id;

CREATE TABLE public.folders (
    id bigint NOT NULL,
    mailbox_id bigint NOT NULL,
    provider_folder_id text NOT NULL,
    name text NOT NULL,
    folder_type text DEFAULT ''::text NOT NULL
);

CREATE SEQUENCE public.folders_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.folders_id_seq OWNED BY public.folders.id;

CREATE TABLE public.labels (
    id bigint NOT NULL,
    name text NOT NULL,
    color text DEFAULT '#2545d3'::text NOT NULL
);

CREATE SEQUENCE public.labels_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.labels_id_seq OWNED BY public.labels.id;

CREATE TABLE public.mailbox_aliases (
    address text NOT NULL,
    mailbox_id bigint NOT NULL
);

CREATE TABLE public.mailbox_grants (
    user_id bigint NOT NULL,
    mailbox_id bigint NOT NULL,
    can_view_messages boolean DEFAULT false NOT NULL,
    can_view_attachments boolean DEFAULT false NOT NULL,
    can_download_attachments boolean DEFAULT false NOT NULL,
    can_reply boolean DEFAULT false NOT NULL,
    can_send boolean DEFAULT false NOT NULL,
    can_manage_labels boolean DEFAULT false NOT NULL,
    can_manage_mailbox boolean DEFAULT false NOT NULL,
    can_manage_permissions boolean DEFAULT false NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.mailboxes (
    id bigint NOT NULL,
    address text NOT NULL,
    display_name text DEFAULT ''::text NOT NULL,
    provider text DEFAULT 'zoho'::text NOT NULL,
    connection_id bigint,
    detected_type text DEFAULT 'unknown'::text NOT NULL,
    strategy text DEFAULT 'none'::text NOT NULL,
    provider_account_id text,
    provider_group_id text,
    org_id text,
    access_level text DEFAULT ''::text NOT NULL,
    members jsonb DEFAULT '[]'::jsonb NOT NULL,
    moderators jsonb DEFAULT '[]'::jsonb NOT NULL,
    moderation_count integer DEFAULT 0 NOT NULL,
    capabilities jsonb DEFAULT '{}'::jsonb NOT NULL,
    is_pilot boolean DEFAULT false NOT NULL,
    sync_enabled boolean DEFAULT false NOT NULL,
    status text DEFAULT 'new'::text NOT NULL,
    status_detail text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mailboxes_detected_type_check CHECK ((detected_type = ANY (ARRAY['shared_mailbox'::text, 'user'::text, 'distribution_list'::text, 'stream_group'::text, 'unknown'::text]))),
    CONSTRAINT mailboxes_strategy_check CHECK ((strategy = ANY (ARRAY['mail_api'::text, 'ediscovery_import'::text, 'moderation_only'::text, 'none'::text])))
);

CREATE SEQUENCE public.mailboxes_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.mailboxes_id_seq OWNED BY public.mailboxes.id;

CREATE TABLE public.message_labels (
    canonical_message_id bigint NOT NULL,
    label_id bigint NOT NULL
);

CREATE TABLE public.message_occurrences (
    id bigint NOT NULL,
    canonical_message_id bigint NOT NULL,
    mailbox_id bigint NOT NULL,
    folder_id bigint NOT NULL,
    provider text DEFAULT 'zoho'::text NOT NULL,
    provider_message_id text NOT NULL,
    direction text DEFAULT 'in'::text NOT NULL,
    received_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    envelope_to text DEFAULT ''::text NOT NULL,
    envelope_cc text DEFAULT ''::text NOT NULL,
    envelope_bcc text DEFAULT ''::text NOT NULL,
    CONSTRAINT message_occurrences_direction_check CHECK ((direction = ANY (ARRAY['in'::text, 'out'::text])))
);

CREATE SEQUENCE public.message_occurrences_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.message_occurrences_id_seq OWNED BY public.message_occurrences.id;

CREATE TABLE public.oauth_states (
    state_hash text NOT NULL,
    connection_id bigint NOT NULL,
    created_by bigint,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone
);

CREATE TABLE public.roles (
    id bigint NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL
);

CREATE SEQUENCE public.roles_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.roles_id_seq OWNED BY public.roles.id;

CREATE TABLE public.schema_migrations (
    name text NOT NULL,
    checksum text NOT NULL,
    applied_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.sessions (
    token text NOT NULL,
    user_id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL
);

CREATE TABLE public.sync_diagnostics (
    id bigint NOT NULL,
    trace_id text NOT NULL,
    mailbox_id bigint,
    mailbox_address text DEFAULT ''::text NOT NULL,
    stage text DEFAULT ''::text NOT NULL,
    endpoint text,
    http_status integer,
    response_sample jsonb,
    read_count integer DEFAULT 0 NOT NULL,
    inserted_count integer DEFAULT 0 NOT NULL,
    skipped_count integer DEFAULT 0 NOT NULL,
    routed_count integer DEFAULT 0 NOT NULL,
    outcome text DEFAULT 'ok'::text NOT NULL,
    error_class text,
    error_message text,
    error_stack text,
    sql_state text,
    constraint_name text,
    routing_context jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.sync_diagnostics_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.sync_diagnostics_id_seq OWNED BY public.sync_diagnostics.id;

CREATE TABLE public.sync_jobs (
    id bigint NOT NULL,
    mailbox_id bigint NOT NULL,
    status text DEFAULT 'queued'::text NOT NULL,
    requested_by bigint,
    discovered integer DEFAULT 0 NOT NULL,
    imported integer DEFAULT 0 NOT NULL,
    skipped integer DEFAULT 0 NOT NULL,
    errors integer DEFAULT 0 NOT NULL,
    current_folder_id bigint,
    current_cursor integer DEFAULT 1 NOT NULL,
    error_detail text DEFAULT ''::text NOT NULL,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT sync_jobs_status_check CHECK ((status = ANY (ARRAY['queued'::text, 'running'::text, 'paused'::text, 'cancelled'::text, 'completed'::text, 'failed'::text])))
);

CREATE SEQUENCE public.sync_jobs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.sync_jobs_id_seq OWNED BY public.sync_jobs.id;

CREATE TABLE public.sync_state (
    mailbox_id bigint NOT NULL,
    folder_id bigint NOT NULL,
    backfill_done boolean DEFAULT false NOT NULL,
    next_start integer DEFAULT 1 NOT NULL,
    last_sync_at timestamp with time zone,
    last_error text DEFAULT ''::text NOT NULL
);

CREATE TABLE public.sync_worker_cycles (
    id bigint NOT NULL,
    source text DEFAULT 'worker'::text NOT NULL,
    pid integer,
    ok boolean DEFAULT true NOT NULL,
    synced integer DEFAULT 0 NOT NULL,
    failed integer DEFAULT 0 NOT NULL,
    skipped_busy integer DEFAULT 0 NOT NULL,
    skipped_backoff integer DEFAULT 0 NOT NULL,
    recovered integer DEFAULT 0 NOT NULL,
    duration_ms integer,
    result jsonb,
    error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.sync_worker_cycles_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.sync_worker_cycles_id_seq OWNED BY public.sync_worker_cycles.id;

CREATE TABLE public.sync_worker_heartbeat (
    id boolean DEFAULT true NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    interval_sec integer DEFAULT 120 NOT NULL,
    pid integer,
    hostname text,
    started_at timestamp with time zone,
    last_tick_at timestamp with time zone,
    next_tick_at timestamp with time zone,
    ticking boolean DEFAULT false NOT NULL,
    last_result jsonb,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT sync_worker_heartbeat_singleton CHECK ((id = true))
);

CREATE TABLE public.user_roles (
    user_id bigint NOT NULL,
    role_id bigint NOT NULL
);

CREATE TABLE public.users (
    id bigint NOT NULL,
    email text NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    password_hash text NOT NULL,
    disabled boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    must_change_password boolean DEFAULT false NOT NULL
);

CREATE SEQUENCE public.users_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;

ALTER TABLE ONLY public.acceptance_incidents ALTER COLUMN id SET DEFAULT nextval('public.acceptance_incidents_id_seq'::regclass);

ALTER TABLE ONLY public.acceptance_runs ALTER COLUMN id SET DEFAULT nextval('public.acceptance_runs_id_seq'::regclass);

ALTER TABLE ONLY public.acceptance_samples ALTER COLUMN id SET DEFAULT nextval('public.acceptance_samples_id_seq'::regclass);

ALTER TABLE ONLY public.archive_imports ALTER COLUMN id SET DEFAULT nextval('public.archive_imports_id_seq'::regclass);

ALTER TABLE ONLY public.attachments ALTER COLUMN id SET DEFAULT nextval('public.attachments_id_seq'::regclass);

ALTER TABLE ONLY public.audit_log ALTER COLUMN id SET DEFAULT nextval('public.audit_log_id_seq'::regclass);

ALTER TABLE ONLY public.canonical_messages ALTER COLUMN id SET DEFAULT nextval('public.canonical_messages_id_seq'::regclass);

ALTER TABLE ONLY public.connections ALTER COLUMN id SET DEFAULT nextval('public.connections_id_seq'::regclass);

ALTER TABLE ONLY public.detection_reports ALTER COLUMN id SET DEFAULT nextval('public.detection_reports_id_seq'::regclass);

ALTER TABLE ONLY public.fingerprint_metrics ALTER COLUMN id SET DEFAULT nextval('public.fingerprint_metrics_id_seq'::regclass);

ALTER TABLE ONLY public.folders ALTER COLUMN id SET DEFAULT nextval('public.folders_id_seq'::regclass);

ALTER TABLE ONLY public.labels ALTER COLUMN id SET DEFAULT nextval('public.labels_id_seq'::regclass);

ALTER TABLE ONLY public.mailboxes ALTER COLUMN id SET DEFAULT nextval('public.mailboxes_id_seq'::regclass);

ALTER TABLE ONLY public.message_occurrences ALTER COLUMN id SET DEFAULT nextval('public.message_occurrences_id_seq'::regclass);

ALTER TABLE ONLY public.roles ALTER COLUMN id SET DEFAULT nextval('public.roles_id_seq'::regclass);

ALTER TABLE ONLY public.sync_diagnostics ALTER COLUMN id SET DEFAULT nextval('public.sync_diagnostics_id_seq'::regclass);

ALTER TABLE ONLY public.sync_jobs ALTER COLUMN id SET DEFAULT nextval('public.sync_jobs_id_seq'::regclass);

ALTER TABLE ONLY public.sync_worker_cycles ALTER COLUMN id SET DEFAULT nextval('public.sync_worker_cycles_id_seq'::regclass);

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);

ALTER TABLE ONLY public.acceptance_incidents
    ADD CONSTRAINT acceptance_incidents_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.acceptance_runs
    ADD CONSTRAINT acceptance_runs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.acceptance_samples
    ADD CONSTRAINT acceptance_samples_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.archive_imports
    ADD CONSTRAINT archive_imports_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.attachments
    ADD CONSTRAINT attachments_canonical_message_id_sha256_original_filename_key UNIQUE (canonical_message_id, sha256, original_filename);

ALTER TABLE ONLY public.attachments
    ADD CONSTRAINT attachments_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.attachments
    ADD CONSTRAINT attachments_storage_key_key UNIQUE (storage_key);

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.canonical_messages
    ADD CONSTRAINT canonical_messages_dedup_hash_key UNIQUE (dedup_hash);

ALTER TABLE ONLY public.canonical_messages
    ADD CONSTRAINT canonical_messages_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.connections
    ADD CONSTRAINT connections_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.detection_reports
    ADD CONSTRAINT detection_reports_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.fingerprint_metrics
    ADD CONSTRAINT fingerprint_metrics_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.folders
    ADD CONSTRAINT folders_mailbox_id_provider_folder_id_key UNIQUE (mailbox_id, provider_folder_id);

ALTER TABLE ONLY public.folders
    ADD CONSTRAINT folders_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.labels
    ADD CONSTRAINT labels_name_key UNIQUE (name);

ALTER TABLE ONLY public.labels
    ADD CONSTRAINT labels_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.mailbox_aliases
    ADD CONSTRAINT mailbox_aliases_pkey PRIMARY KEY (address);

ALTER TABLE ONLY public.mailbox_grants
    ADD CONSTRAINT mailbox_grants_pkey PRIMARY KEY (user_id, mailbox_id);

ALTER TABLE ONLY public.mailboxes
    ADD CONSTRAINT mailboxes_address_key UNIQUE (address);

ALTER TABLE ONLY public.mailboxes
    ADD CONSTRAINT mailboxes_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.message_labels
    ADD CONSTRAINT message_labels_pkey PRIMARY KEY (canonical_message_id, label_id);

ALTER TABLE ONLY public.message_occurrences
    ADD CONSTRAINT message_occurrences_mailbox_canonical_key UNIQUE (mailbox_id, canonical_message_id);

ALTER TABLE ONLY public.message_occurrences
    ADD CONSTRAINT message_occurrences_mailbox_id_folder_id_canonical_message__key UNIQUE (mailbox_id, folder_id, canonical_message_id);

ALTER TABLE ONLY public.message_occurrences
    ADD CONSTRAINT message_occurrences_mailbox_id_folder_id_provider_message_i_key UNIQUE (mailbox_id, folder_id, provider_message_id);

ALTER TABLE ONLY public.message_occurrences
    ADD CONSTRAINT message_occurrences_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.oauth_states
    ADD CONSTRAINT oauth_states_pkey PRIMARY KEY (state_hash);

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_name_key UNIQUE (name);

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (name);

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (token);

ALTER TABLE ONLY public.sync_diagnostics
    ADD CONSTRAINT sync_diagnostics_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.sync_jobs
    ADD CONSTRAINT sync_jobs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.sync_state
    ADD CONSTRAINT sync_state_pkey PRIMARY KEY (mailbox_id, folder_id);

ALTER TABLE ONLY public.sync_worker_cycles
    ADD CONSTRAINT sync_worker_cycles_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.sync_worker_heartbeat
    ADD CONSTRAINT sync_worker_heartbeat_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_pkey PRIMARY KEY (user_id, role_id);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);

CREATE INDEX idx_acceptance_incidents_run ON public.acceptance_incidents USING btree (run_id, id);

CREATE UNIQUE INDEX idx_acceptance_one_active ON public.acceptance_runs USING btree ((true)) WHERE (status = 'active'::text);

CREATE INDEX idx_acceptance_samples_run ON public.acceptance_samples USING btree (run_id, id);

CREATE INDEX idx_archive_imports_mailbox ON public.archive_imports USING btree (mailbox_id, id DESC);

CREATE INDEX idx_audit_at ON public.audit_log USING btree (at DESC);

CREATE INDEX idx_canonical_fts ON public.canonical_messages USING gin (fts);

CREATE INDEX idx_canonical_rfc ON public.canonical_messages USING btree (rfc_message_id) WHERE (rfc_message_id <> ''::text);

CREATE INDEX idx_detection_mailbox ON public.detection_reports USING btree (mailbox_id, id DESC);

CREATE INDEX idx_fp_metrics_type ON public.fingerprint_metrics USING btree (event_type, id DESC);

CREATE INDEX idx_oauth_states_expiry ON public.oauth_states USING btree (expires_at);

CREATE INDEX idx_occ_canonical ON public.message_occurrences USING btree (canonical_message_id);

CREATE INDEX idx_occ_mailbox_time ON public.message_occurrences USING btree (mailbox_id, received_at DESC);

CREATE INDEX idx_sessions_expiry ON public.sessions USING btree (expires_at);

CREATE INDEX idx_sync_diag_mailbox ON public.sync_diagnostics USING btree (mailbox_id, id DESC);

CREATE INDEX idx_sync_diag_trace ON public.sync_diagnostics USING btree (trace_id);

CREATE INDEX idx_sync_jobs_mailbox ON public.sync_jobs USING btree (mailbox_id, id DESC);

CREATE UNIQUE INDEX idx_sync_jobs_one_active ON public.sync_jobs USING btree (mailbox_id) WHERE (status = ANY (ARRAY['queued'::text, 'running'::text, 'paused'::text]));

CREATE INDEX idx_worker_cycles_recent ON public.sync_worker_cycles USING btree (id DESC);

CREATE INDEX idx_worker_cycles_source ON public.sync_worker_cycles USING btree (source, id DESC);

ALTER TABLE ONLY public.acceptance_incidents
    ADD CONSTRAINT acceptance_incidents_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.acceptance_runs(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.acceptance_runs
    ADD CONSTRAINT acceptance_runs_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.acceptance_samples
    ADD CONSTRAINT acceptance_samples_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.acceptance_runs(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.archive_imports
    ADD CONSTRAINT archive_imports_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id);

ALTER TABLE ONLY public.archive_imports
    ADD CONSTRAINT archive_imports_uploaded_by_fkey FOREIGN KEY (uploaded_by) REFERENCES public.users(id);

ALTER TABLE ONLY public.attachments
    ADD CONSTRAINT attachments_canonical_message_id_fkey FOREIGN KEY (canonical_message_id) REFERENCES public.canonical_messages(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.connections
    ADD CONSTRAINT connections_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.folders
    ADD CONSTRAINT folders_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.mailbox_aliases
    ADD CONSTRAINT mailbox_aliases_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.mailbox_grants
    ADD CONSTRAINT mailbox_grants_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.mailbox_grants
    ADD CONSTRAINT mailbox_grants_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.mailboxes
    ADD CONSTRAINT mailboxes_connection_id_fkey FOREIGN KEY (connection_id) REFERENCES public.connections(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.message_labels
    ADD CONSTRAINT message_labels_canonical_message_id_fkey FOREIGN KEY (canonical_message_id) REFERENCES public.canonical_messages(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.message_labels
    ADD CONSTRAINT message_labels_label_id_fkey FOREIGN KEY (label_id) REFERENCES public.labels(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.message_occurrences
    ADD CONSTRAINT message_occurrences_canonical_message_id_fkey FOREIGN KEY (canonical_message_id) REFERENCES public.canonical_messages(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.message_occurrences
    ADD CONSTRAINT message_occurrences_folder_id_fkey FOREIGN KEY (folder_id) REFERENCES public.folders(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.message_occurrences
    ADD CONSTRAINT message_occurrences_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.oauth_states
    ADD CONSTRAINT oauth_states_connection_id_fkey FOREIGN KEY (connection_id) REFERENCES public.connections(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.oauth_states
    ADD CONSTRAINT oauth_states_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.sync_diagnostics
    ADD CONSTRAINT sync_diagnostics_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.sync_jobs
    ADD CONSTRAINT sync_jobs_current_folder_id_fkey FOREIGN KEY (current_folder_id) REFERENCES public.folders(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.sync_jobs
    ADD CONSTRAINT sync_jobs_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.sync_jobs
    ADD CONSTRAINT sync_jobs_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.sync_state
    ADD CONSTRAINT sync_state_folder_id_fkey FOREIGN KEY (folder_id) REFERENCES public.folders(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.sync_state
    ADD CONSTRAINT sync_state_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
```
