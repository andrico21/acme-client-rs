# Parameter Processing Decision Tree

```mermaid
graph TD
    START["acme-client-rs<br/>CLI Entry"] --> TRACE["Init tracing<br/>(RUST_LOG env)"]
    TRACE --> PARSE["Parse CLI args<br/>(clap derive)"]
    PARSE --> CFG_CHECK{"--config or<br/>ACME_CONFIG?"}

    %% Config loading
    CFG_CHECK -- Yes --> LOAD_CFG["Load TOML config<br/>config_mode = true"]
    CFG_CHECK -- No --> NO_CFG["config_mode = false"]
    LOAD_CFG --> MERGE["apply_config()<br/>Smart merging"]
    NO_CFG --> DISPATCH

    %% Config merge precedence
    MERGE --> PREC{"Value source?"}
    PREC -- "CommandLine" --> CLI_WINS["CLI wins<br/>(never overridden)"]
    PREC -- "EnvVariable" --> ENV_MODE{"config_mode?"}
    ENV_MODE -- Yes --> ENV_STRIP["Config overrides env<br/>+ strips non-secret env vars*"]
    ENV_MODE -- No --> ENV_OVER["Config overrides env"]
    PREC -- "DefaultValue" --> CFG_WINS["Config overrides default"]
    CLI_WINS --> DISPATCH
    ENV_STRIP --> DISPATCH
    ENV_OVER --> DISPATCH
    CFG_WINS --> DISPATCH

    %% Subcommand dispatch
    DISPATCH["Dispatch on<br/>subcommand"] --> CMD{"Command?"}

    CMD -- generate-config --> GEN_CFG["Print TOML template<br/>to stdout"]
    CMD -- show-config --> SHOW_CFG["Display effective<br/>config values"]
    CMD -- generate-key --> GEN_KEY["Generate account key<br/>--algorithm"]
    CMD -- account --> ACCT["Register/find<br/>account"]
    CMD -- order --> NEW_ORD["Create new order"]
    CMD -- get-authz --> GET_AZ["Fetch authorization"]
    CMD -- respond-challenge --> RESP_CH["Respond to challenge"]
    CMD -- serve-http01 --> SERVE["Start HTTP-01 server"]
    CMD -- show-dns01 --> SH_DNS["Print DNS TXT value"]
    CMD -- show-dns-persist01 --> SH_DNSP["Print DNS-PERSIST<br/>TXT value"]
    CMD -- finalize --> FIN_CMD["Generate CSR & finalize"]
    CMD -- poll-order --> POLL_ORD["Poll order status"]
    CMD -- download-cert --> DL_CERT["Download certificate"]
    CMD -- deactivate-account --> DEACT["Deactivate account"]
    CMD -- key-rollover --> ROLL["Rollover account key"]
    CMD -- pre-authorize --> PRE_CMD["Pre-authorize domain"]
    CMD -- revoke --> REVOKE["Revoke certificate"]
    CMD -- renewal-info --> REN_INFO["Get ARI renewal info"]
    CMD -- run --> RUN["cmd_run()<br/>Full automated flow"]

    %% Styling
    classDef success fill:#4caf50,color:white,stroke:#2e7d32
    classDef decision fill:#42a5f5,color:white,stroke:#1565c0

    class GEN_CFG,SHOW_CFG,GEN_KEY success
    class CFG_CHECK,CMD,PREC,ENV_MODE decision
```

---

## Subcommand Detail Flows

### run (Full Automated Flow)

```mermaid
graph TD
    RUN["run"] --> VALIDATE_DOMAINS{"domains<br/>provided?"}
    VALIDATE_DOMAINS -- No --> BAIL_DOMAIN["ERROR: at least one<br/>domain required"]
    VALIDATE_DOMAINS -- Yes --> CERT_EXISTS{"cert file<br/>exists?"}

    %% Renewal checks (only if cert exists)
    CERT_EXISTS -- No --> ACCT_STEP
    CERT_EXISTS -- Yes --> SAN_CHECK{"SANs match<br/>requested domains?"}

    %% Domain mismatch check (before ARI/days)
    SAN_CHECK -- Yes --> ARI_CHECK
    SAN_CHECK -- "parse failed" --> ARI_CHECK
    SAN_CHECK -- "No (mismatch)" --> REISSUE_FLAG{"--reissue-on-mismatch?"}
    REISSUE_FLAG -- Yes --> ACCT_STEP_REISSUE["Proceed to reissue<br/>(skip ARI/days,<br/>no replaceOrder)"]
    REISSUE_FLAG -- No --> SKIP_MISMATCH["SKIP: domain mismatch<br/>(use --reissue-on-mismatch)"]
    ACCT_STEP_REISSUE --> ACCT_STEP

    ARI_CHECK{"--ari flag?"}

    ARI_CHECK -- Yes --> ARI_QUERY["Query ACME server<br/>renewal info (RFC 9702)"]
    ARI_QUERY --> ARI_RESULT{"ARI result?"}
    ARI_RESULT -- "NOW < window.start" --> SKIP_ARI["SKIP: not yet<br/>in renewal window"]
    ARI_RESULT -- "window open" --> ARI_COMPUTE{"compute_cert_id<br/>succeeds?"}
    ARI_COMPUTE -- Yes --> ARI_SET_ID["Set ari_cert_id<br/>for replaceOrder"]
    ARI_SET_ID --> ACCT_STEP
    ARI_COMPUTE -- No --> DAYS_CHECK
    ARI_RESULT -- "ARI failed/unsupported" --> DAYS_CHECK
    ARI_CHECK -- No --> DAYS_CHECK

    %% Days-based renewal (only if ARI didn't set cert_id)
    DAYS_CHECK{"--days N?"}
    DAYS_CHECK -- Yes --> DAYS_LEFT{"remaining ><br/>threshold?"}
    DAYS_LEFT -- Yes --> SKIP_DAYS["SKIP: cert still<br/>has >N days"]
    DAYS_LEFT -- No --> ACCT_STEP
    DAYS_CHECK -- No --> ACCT_STEP

    %% Account + Pre-authorization
    ACCT_STEP["Step 1: Create/find<br/>account"] --> PREAUTH_CHECK{"--pre-authorize?"}
    PREAUTH_CHECK -- Yes --> PRE_AUTH["Step 2: Pre-authorize<br/>each domain (sequential)"]
    PRE_AUTH --> PRE_CH_TYPE{"challenge<br/>type?"}
    PRE_CH_TYPE -- http-01 --> PRE_HTTP["Setup HTTP-01<br/>(server or dir)"]
    PRE_CH_TYPE -- dns-01 --> PRE_DNS["Setup DNS-01<br/>(hook or manual)"]
    PRE_CH_TYPE -- dns-persist-01 --> PRE_DNSP["Setup DNS-PERSIST-01"]
    PRE_CH_TYPE -- tls-alpn-01 --> PRE_TLS["Setup TLS-ALPN-01<br/>(manual)"]
    PRE_HTTP --> NEW_ORDER
    PRE_DNS --> NEW_ORDER
    PRE_DNSP --> NEW_ORDER
    PRE_TLS --> NEW_ORDER
    PREAUTH_CHECK -- No --> NEW_ORDER

    %% Create order
    NEW_ORDER{"ari_cert_id<br/>available?"}
    NEW_ORDER -- Yes --> REPLACE_ORD["new_order_replacing()<br/>(RFC 9702)"]
    NEW_ORDER -- No --> NORMAL_ORD["new_order()"]
    REPLACE_ORD --> AUTHZ_MODE
    NORMAL_ORD --> AUTHZ_MODE

    %% Parallel vs Sequential
    AUTHZ_MODE{"--dns-hook +<br/>(dns-01 | dns-persist-01)?"}
    AUTHZ_MODE -- Yes --> PARALLEL["PHASED PARALLEL<br/>DNS Authorization"]
    AUTHZ_MODE -- No --> SEQUENTIAL["SEQUENTIAL<br/>Authorization"]

    %% ===== PARALLEL DNS PATH =====
    PARALLEL --> P1["Phase 1: Fetch all authz<br/>+ create ALL TXT records<br/>(dns-hook create)"]
    P1 --> P2_CHECK{"--dns-wait?"}
    P2_CHECK -- Yes --> P2["Phase 2: Parallel DNS<br/>propagation wait<br/>(semaphore, concurrency=5)"]
    P2 --> P3
    P2_CHECK -- No --> P3
    P3["Phase 3: on-challenge-ready<br/>hooks + respond (serial)"]
    P3 --> P4["Phase 4: Poll all authz<br/>until valid"]
    P4 --> P5["Phase 5: Cleanup ALL<br/>DNS records (dns-hook cleanup)"]
    P5 --> GEN_CSR

    %% ===== SEQUENTIAL PATH =====
    SEQUENTIAL --> SEQ_LOOP["For each authorization"]
    SEQ_LOOP --> CH_TYPE{"challenge<br/>type?"}

    %% HTTP-01 (no on_challenge_ready hook, goes straight to respond)
    CH_TYPE -- http-01 --> HTTP_MODE{"--challenge-dir?"}
    HTTP_MODE -- Yes --> FILE_MODE["Write token file<br/>to directory"]
    HTTP_MODE -- No --> SERVER_MODE["Bind TCP server<br/>on --http-port"]
    FILE_MODE --> RESPOND
    SERVER_MODE --> RESPOND

    %% DNS-01 (sequential = no dns-hook, always manual)
    CH_TYPE -- dns-01 --> DNS_IP{"IP identifier?"}
    DNS_IP -- Yes --> BAIL_IP["ERROR: dns-01 not<br/>supported for IPs"]
    DNS_IP -- No --> DNS_PRINT["Print TXT record<br/>instructions"]
    DNS_PRINT --> DNS_WAIT_SEQ{"--dns-wait?"}
    DNS_WAIT_SEQ -- Yes --> POLL_DNS_SEQ["Poll DNS TXT<br/>every 5s until timeout"]
    DNS_WAIT_SEQ -- No --> ENTER_DNS["Press Enter<br/>to continue"]
    POLL_DNS_SEQ --> ON_CH_READY
    ENTER_DNS --> ON_CH_READY

    %% DNS-PERSIST-01 (sequential = no dns-hook, always manual)
    CH_TYPE -- dns-persist-01 --> DNSP_IP{"IP identifier?"}
    DNSP_IP -- Yes --> BAIL_IP2["ERROR: not supported<br/>for IPs"]
    DNSP_IP -- No --> DNSP_VALID{"issuer-domain-names<br/>1-10 entries?"}
    DNSP_VALID -- No --> BAIL_IDN["ERROR: malformed<br/>dns-persist-01"]
    DNSP_VALID -- Yes --> DNSP_PRINT["Print TXT record<br/>instructions"]
    DNSP_PRINT --> DNSP_WAIT_SEQ{"--dns-wait?"}
    DNSP_WAIT_SEQ -- Yes --> DNSP_POLL_SEQ["Poll DNS TXT<br/>every 5s until timeout"]
    DNSP_WAIT_SEQ -- No --> ENTER_DNSP["Press Enter<br/>to continue"]
    DNSP_POLL_SEQ --> ON_CH_READY
    ENTER_DNSP --> ON_CH_READY

    %% TLS-ALPN-01
    CH_TYPE -- tls-alpn-01 --> TLS_PRINT["Print instructions"]
    TLS_PRINT --> ENTER_TLS["Press Enter<br/>to continue"]
    ENTER_TLS --> ON_CH_READY_TLS{"--on-challenge-ready<br/>hook?"}
    ON_CH_READY_TLS -- Yes --> RUN_HOOK_TLS["Run hook<br/>(ACME_DOMAIN, ACME_TOKEN,<br/>ACME_KEY_AUTH)"]
    ON_CH_READY_TLS -- No --> RESPOND
    RUN_HOOK_TLS --> RESPOND

    %% on-challenge-ready (DNS types only in sequential path)
    ON_CH_READY{"--on-challenge-ready<br/>hook?"}
    ON_CH_READY -- Yes --> RUN_HOOK["Run hook script<br/>(env vars per type)"]
    ON_CH_READY -- No --> RESPOND
    RUN_HOOK --> RESPOND

    RESPOND["respond_to_challenge()"] --> POLL_AUTH["Poll authorization<br/>until valid/invalid"]
    POLL_AUTH --> TERM_CHECK{"is_challenge_terminal()?<br/>(status == Invalid)"}
    TERM_CHECK -- Yes --> FAIL_AUTH["ERROR: challenge<br/>failed (Invalid)"]
    TERM_CHECK -- "No (Pending+error)" --> POLL_AUTH
    POLL_AUTH -- Valid --> CLEANUP_SEQ["Cleanup<br/>(file / server abort)"]
    CLEANUP_SEQ --> SEQ_LOOP
    SEQ_LOOP -- "All done" --> GEN_CSR

    %% CSR & Finalize
    GEN_CSR["Generate CSR<br/>--cert-key-algorithm"] --> CSR_ALG{"algorithm?"}
    CSR_ALG -- ec-p256 --> EC256["ECDSA P-256"]
    CSR_ALG -- ec-p384 --> EC384["ECDSA P-384"]
    CSR_ALG -- ed25519 --> ED25519["Ed25519"]
    EC256 --> FINALIZE
    EC384 --> FINALIZE
    ED25519 --> FINALIZE

    FINALIZE["finalize_order()<br/>Submit CSR"] --> POLL_FIN["Poll order until<br/>certificate URL ready"]
    POLL_FIN --> DOWNLOAD["Download certificate"]

    %% Save key first, then cert (matches code order)
    DOWNLOAD --> KEY_ENC{"--key-password or<br/>--key-password-file?"}
    KEY_ENC -- Yes --> ENCRYPT["Encrypt private key<br/>(scrypt + AES-256-CBC)"]
    KEY_ENC -- No --> SAVE_RAW["Save key unencrypted"]
    ENCRYPT --> SAVE_KEY["Save key to<br/>--key-output"]
    SAVE_RAW --> SAVE_KEY
    SAVE_KEY --> SAVE_CERT["Save cert to<br/>--cert-output"]

    %% Post-issue hook
    SAVE_CERT --> CERT_HOOK{"--on-cert-issued<br/>hook?"}
    CERT_HOOK -- Yes --> RUN_CERT_HOOK["Run hook<br/>(ACME_DOMAINS, ACME_CERT_PATH,<br/>ACME_KEY_PATH, ACME_KEY_ENCRYPTED)"]
    CERT_HOOK -- No --> DONE["SUCCESS"]
    RUN_CERT_HOOK --> DONE

    %% Styling
    classDef error fill:#f44,color:white,stroke:#d32f2f
    classDef skip fill:#ff9800,color:white,stroke:#e65100
    classDef success fill:#4caf50,color:white,stroke:#2e7d32
    classDef decision fill:#42a5f5,color:white,stroke:#1565c0

    class BAIL_DOMAIN,BAIL_IP,BAIL_IP2,BAIL_IDN,FAIL_AUTH error
    class SKIP_ARI,SKIP_DAYS,SKIP_MISMATCH skip
    class DONE success
    class VALIDATE_DOMAINS,CERT_EXISTS,SAN_CHECK,REISSUE_FLAG,ARI_CHECK,ARI_RESULT,ARI_COMPUTE,DAYS_CHECK,DAYS_LEFT,PREAUTH_CHECK,NEW_ORDER,AUTHZ_MODE,CH_TYPE,HTTP_MODE,DNS_IP,DNS_WAIT_SEQ,DNSP_IP,DNSP_VALID,DNSP_WAIT_SEQ,ON_CH_READY,ON_CH_READY_TLS,TERM_CHECK,KEY_ENC,CERT_HOOK,CSR_ALG,PRE_CH_TYPE,P2_CHECK decision
```

### Configuration Commands

```mermaid
graph TD
    %% === generate-config (trivial) ===
    GC["generate-config"] --> GC_OUT["generate_template()<br/>→ print to stdout"]
    GC_OUT --> GC_DONE["DONE"]

    %% === generate-key ===
    GK["generate-key"] --> GK_ALG{"--algorithm?"}
    GK_ALG -- es256 --> GK_GEN["Generate ES256 key"]
    GK_ALG -- es384 --> GK_GEN384["Generate ES384 key"]
    GK_ALG -- ed25519 --> GK_GENED["Generate Ed25519 key"]
    GK_GEN --> GK_WRITE["Write PEM to<br/>--account-key"]
    GK_GEN384 --> GK_WRITE
    GK_GENED --> GK_WRITE
    GK_WRITE --> GK_FMT{"--output-format?"}
    GK_FMT -- json --> GK_JSON["JSON: algorithm, path"]
    GK_FMT -- text --> GK_TEXT["Text: confirmation"]
    GK_JSON --> GK_DONE["DONE"]
    GK_TEXT --> GK_DONE

    classDef success fill:#4caf50,color:white,stroke:#2e7d32
    classDef decision fill:#42a5f5,color:white,stroke:#1565c0
    class GC_DONE,GK_DONE success
    class GK_ALG,GK_FMT decision
```

### show-config

```mermaid
graph TD
    SC["show-config"] --> SC_FMT{"--output-format?"}

    %% JSON path
    SC_FMT -- json --> SC_J_HDR["Build JSON: header +<br/>[global] section"]
    SC_J_HDR --> SC_J_V1{"--verbose?"}
    SC_J_V1 -- Yes --> SC_J_SRC1["Add source annotation<br/>per global field<br/>(cli|env|config|default)"]
    SC_J_V1 -- No --> SC_J_RUN
    SC_J_SRC1 --> SC_J_RUN{"[run] section<br/>in config?"}
    SC_J_RUN -- Yes --> SC_J_RUN_ADD["Add all [run] fields"]
    SC_J_RUN -- No --> SC_J_ACCT
    SC_J_RUN_ADD --> SC_J_V2{"--verbose?"}
    SC_J_V2 -- Yes --> SC_J_SRC2["Add source per<br/>run field"]
    SC_J_V2 -- No --> SC_J_ACCT
    SC_J_SRC2 --> SC_J_ACCT{"[account]<br/>in config?"}
    SC_J_ACCT -- Yes --> SC_J_ACCT_ADD["Add [account] fields<br/>(+ verbose sources)"]
    SC_J_ACCT -- No --> SC_PRINT
    SC_J_ACCT_ADD --> SC_PRINT["Print JSON"]

    %% Text path
    SC_FMT -- text --> SC_T_HDR["Print header"]
    SC_T_HDR --> SC_T_CM{"config_mode?"}
    SC_T_CM -- Yes --> SC_T_MODE["Print config-mode note"]
    SC_T_CM -- No --> SC_T_V
    SC_T_MODE --> SC_T_V{"--verbose?"}
    SC_T_V -- Yes --> SC_T_SRC["Print source legend"]
    SC_T_V -- No --> SC_T_GLOBAL
    SC_T_SRC --> SC_T_GLOBAL["Print [global] section<br/>with source annotations"]
    SC_T_GLOBAL --> SC_T_RUN{"[run] in config?"}
    SC_T_RUN -- Yes --> SC_T_RUN_P["Print [run] fields"]
    SC_T_RUN -- No --> SC_T_NORUN{"config loaded<br/>at all?"}
    SC_T_NORUN -- No --> SC_T_DEF["Print defaults-only<br/>message"]
    SC_T_NORUN -- Yes --> SC_T_ACCT
    SC_T_RUN_P --> SC_T_ACCT{"[account]?"}
    SC_T_DEF --> SC_T_ACCT
    SC_T_ACCT -- Yes --> SC_T_ACCT_P["Print [account]"]
    SC_T_ACCT -- No --> SC_DONE["DONE"]
    SC_T_ACCT_P --> SC_DONE
    SC_PRINT --> SC_DONE

    classDef success fill:#4caf50,color:white,stroke:#2e7d32
    classDef decision fill:#42a5f5,color:white,stroke:#1565c0
    class SC_DONE success
    class SC_FMT,SC_J_V1,SC_J_V2,SC_J_RUN,SC_J_ACCT,SC_T_CM,SC_T_V,SC_T_RUN,SC_T_NORUN,SC_T_ACCT decision
```

### Account & Key Management

```mermaid
graph TD
    %% === account ===
    ACC["account"] --> ACC_CONTACT{"--contact<br/>provided?"}
    ACC_CONTACT -- Yes --> ACC_MAILTO["Build mailto: URIs"]
    ACC_CONTACT -- No --> ACC_NONE["Lookup mode<br/>(no contact)"]
    ACC_MAILTO --> ACC_EAB
    ACC_NONE --> ACC_EAB{"EAB args?"}
    ACC_EAB -- "both --eab-kid<br/>+ --eab-hmac-key" --> ACC_EAB_OK["Parse EAB<br/>(base64url decode)"]
    ACC_EAB -- "neither" --> ACC_CREATE
    ACC_EAB -- "only one" --> ACC_EAB_ERR["ERROR: both<br/>--eab-kid and<br/>--eab-hmac-key required"]
    ACC_EAB_OK --> ACC_CREATE["create_account()"]
    ACC_CREATE --> ACC_FMT{"--output-format?"}
    ACC_FMT -- json --> ACC_JSON["JSON: status,<br/>account_url"]
    ACC_FMT -- text --> ACC_TEXT["Text: status,<br/>account_url (if known)"]
    ACC_JSON --> ACC_DONE["DONE"]
    ACC_TEXT --> ACC_DONE

    %% === deactivate-account (trivial) ===
    DEACT["deactivate-account"] --> DEACT_CALL["deactivate_account()"]
    DEACT_CALL --> DEACT_FMT{"--output-format?"}
    DEACT_FMT -- json --> DEACT_JSON["JSON: status"]
    DEACT_FMT -- text --> DEACT_TEXT["Text: status"]
    DEACT_JSON --> DEACT_DONE["DONE"]
    DEACT_TEXT --> DEACT_DONE

    %% === key-rollover ===
    ROLL["key-rollover"] --> ROLL_LOAD["Load new key<br/>from --new-key"]
    ROLL_LOAD --> ROLL_URL{"account_url<br/>known?"}
    ROLL_URL -- No --> ROLL_LOOKUP["Auto-lookup account<br/>(KID signing required<br/>per RFC 8555 §7.3.5)"]
    ROLL_URL -- Yes --> ROLL_CHANGE
    ROLL_LOOKUP --> ROLL_CHANGE["key_change()"]
    ROLL_CHANGE --> ROLL_FMT{"--output-format?"}
    ROLL_FMT -- json --> ROLL_JSON["JSON: new_key path"]
    ROLL_FMT -- text --> ROLL_TEXT["Text: success +<br/>new key path"]
    ROLL_JSON --> ROLL_DONE["DONE"]
    ROLL_TEXT --> ROLL_DONE

    classDef success fill:#4caf50,color:white,stroke:#2e7d32
    classDef decision fill:#42a5f5,color:white,stroke:#1565c0
    classDef error fill:#f44,color:white,stroke:#d32f2f
    class ACC_DONE,DEACT_DONE,ROLL_DONE success
    class ACC_EAB_ERR error
    class ACC_CONTACT,ACC_EAB,ACC_FMT,DEACT_FMT,ROLL_URL,ROLL_FMT decision
```

### Order Lifecycle Commands

```mermaid
graph TD
    %% === order ===
    ORD["order"] --> ORD_IDS["Build identifiers<br/>from domains (positional)"]
    ORD_IDS --> ORD_CALL["new_order()"]
    ORD_CALL --> ORD_FMT{"--output-format?"}
    ORD_FMT -- json --> ORD_JSON["JSON: order_url,<br/>status, finalize_url,<br/>authorizations[]"]
    ORD_FMT -- text --> ORD_TEXT["Text: order_url,<br/>status, finalize_url,<br/>authz list"]
    ORD_JSON --> ORD_DONE["DONE"]
    ORD_TEXT --> ORD_DONE

    %% === get-authz ===
    GAZ["get-authz"] --> GAZ_CALL["get_authorization(url)"]
    GAZ_CALL --> GAZ_FMT{"--output-format?"}
    GAZ_FMT -- json --> GAZ_JSON["JSON: identifier,<br/>type, status,<br/>challenges[]"]
    GAZ_FMT -- text --> GAZ_TEXT["Text: identifier, status<br/>+ per challenge:<br/>type, status, url, token"]
    GAZ_JSON --> GAZ_DONE["DONE"]
    GAZ_TEXT --> GAZ_DONE

    %% === respond-challenge (trivial) ===
    RC["respond-challenge"] --> RC_CALL["respond_to_challenge(url)"]
    RC_CALL --> RC_FMT{"--output-format?"}
    RC_FMT -- json --> RC_JSON["JSON: status"]
    RC_FMT -- text --> RC_TEXT["Text: status"]
    RC_JSON --> RC_DONE["DONE"]
    RC_TEXT --> RC_DONE

    %% === finalize ===
    FIN["finalize"] --> FIN_ALG{"--cert-key-algorithm?"}
    FIN_ALG -- ec-p256 --> FIN_CSR["CSR (P-256)"]
    FIN_ALG -- ec-p384 --> FIN_CSR2["CSR (P-384)"]
    FIN_ALG -- ed25519 --> FIN_CSR3["CSR (Ed25519)"]
    FIN_CSR --> FIN_CALL
    FIN_CSR2 --> FIN_CALL
    FIN_CSR3 --> FIN_CALL["finalize_order()"]
    FIN_CALL --> FIN_FMT{"--output-format?"}
    FIN_FMT -- json --> FIN_JSON["JSON: status,<br/>certificate_url"]
    FIN_FMT -- text --> FIN_TEXT["Text: status,<br/>certificate_url"]
    FIN_JSON --> FIN_DONE["DONE"]
    FIN_TEXT --> FIN_DONE

    %% === poll-order (trivial) ===
    PO["poll-order"] --> PO_CALL["poll_order(url)"]
    PO_CALL --> PO_FMT{"--output-format?"}
    PO_FMT -- json --> PO_JSON["JSON: status,<br/>certificate_url"]
    PO_FMT -- text --> PO_TEXT["Text: status,<br/>certificate_url"]
    PO_JSON --> PO_DONE["DONE"]
    PO_TEXT --> PO_DONE

    %% === download-cert ===
    DC["download-cert"] --> DC_CALL["download_certificate(url)"]
    DC_CALL --> DC_WRITE["Write cert to<br/>--cert-output"]
    DC_WRITE --> DC_FMT{"--output-format?"}
    DC_FMT -- json --> DC_JSON["JSON: path"]
    DC_FMT -- text --> DC_TEXT["Text: saved to path"]
    DC_JSON --> DC_DONE["DONE"]
    DC_TEXT --> DC_DONE

    classDef success fill:#4caf50,color:white,stroke:#2e7d32
    classDef decision fill:#42a5f5,color:white,stroke:#1565c0
    class ORD_DONE,GAZ_DONE,RC_DONE,FIN_DONE,PO_DONE,DC_DONE success
    class ORD_FMT,GAZ_FMT,RC_FMT,FIN_ALG,FIN_FMT,PO_FMT,DC_FMT decision
```

### Challenge Helper Commands

```mermaid
graph TD
    %% === serve-http01 ===
    SH["serve-http01"] --> SH_LOAD["Load account key"]
    SH_LOAD --> SH_MODE{"--challenge-dir?"}

    SH_MODE -- Yes --> SH_FILE["Write token file<br/>to directory"]
    SH_FILE --> SH_FILE_FMT{"--output-format?"}
    SH_FILE_FMT -- json --> SH_FILE_JSON["JSON: mode, path"]
    SH_FILE_FMT -- text --> SH_FILE_TEXT["Text: path"]
    SH_FILE_JSON --> SH_ENTER["Press Enter<br/>to clean up (stdin)"]
    SH_FILE_TEXT --> SH_ENTER
    SH_ENTER --> SH_CLEANUP["Cleanup<br/>challenge file"]
    SH_CLEANUP --> SH_DONE["DONE"]

    SH_MODE -- No --> SH_SERVER["Start HTTP server<br/>on --http-port"]
    SH_SERVER --> SH_SERVE["Serve challenge<br/>response (blocking)"]
    SH_SERVE --> SH_DONE

    %% === show-dns01 ===
    SD["show-dns01"] --> SD_LOAD["Load account key"]
    SD_LOAD --> SD_FMT{"--output-format?"}
    SD_FMT -- json --> SD_JSON["JSON: domain,<br/>record_name,<br/>type=TXT,<br/>record_value"]
    SD_FMT -- text --> SD_TEXT["print_instructions()<br/>(record name + value)"]
    SD_JSON --> SD_DONE["DONE"]
    SD_TEXT --> SD_DONE

    %% === show-dns-persist01 ===
    SDP["show-dns-persist01"] --> SDP_URL{"account_url<br/>known?"}
    SDP_URL -- No --> SDP_LOOKUP["Auto-lookup account"]
    SDP_URL -- Yes --> SDP_COMPUTE
    SDP_LOOKUP --> SDP_COMPUTE["Compute TXT value<br/>(issuer, account_uri,<br/>--persist-policy,<br/>--persist-until)"]
    SDP_COMPUTE --> SDP_FMT{"--output-format?"}
    SDP_FMT -- json --> SDP_JSON["JSON: domain,<br/>record_name, value,<br/>issuer, policy, until"]
    SDP_FMT -- text --> SDP_TEXT["print_instructions()"]
    SDP_JSON --> SDP_DONE["DONE"]
    SDP_TEXT --> SDP_DONE

    classDef success fill:#4caf50,color:white,stroke:#2e7d32
    classDef decision fill:#42a5f5,color:white,stroke:#1565c0
    class SH_DONE,SD_DONE,SDP_DONE success
    class SH_MODE,SH_FILE_FMT,SD_FMT,SDP_URL,SDP_FMT decision
```

### Certificate Operations

```mermaid
graph TD
    %% === revoke ===
    RV["revoke"] --> RV_URL{"account_url<br/>known?"}
    RV_URL -- No --> RV_LOOKUP["Auto-lookup account<br/>(KID signing required<br/>per RFC 8555 §7.6)"]
    RV_URL -- Yes --> RV_READ
    RV_LOOKUP --> RV_READ["Read cert PEM → DER"]
    RV_READ --> RV_CALL["revoke_certificate()<br/>(optional --reason code)"]
    RV_CALL --> RV_FMT{"--output-format?"}
    RV_FMT -- json --> RV_JSON["JSON: cert_path,<br/>reason"]
    RV_FMT -- text --> RV_TEXT["Text: revoked"]
    RV_JSON --> RV_DONE["DONE"]
    RV_TEXT --> RV_DONE

    %% === pre-authorize ===
    PA["pre-authorize"] --> PA_URL{"account_url<br/>known?"}
    PA_URL -- No --> PA_LOOKUP["Auto-lookup account<br/>(KID signing required)"]
    PA_URL -- Yes --> PA_CALL
    PA_LOOKUP --> PA_CALL["new_authorization(domain)"]
    PA_CALL --> PA_FMT{"--output-format?"}
    PA_FMT -- json --> PA_JSON["JSON: identifier, status,<br/>authz_url, ALL challenges[]"]
    PA_FMT -- text --> PA_TEXT["Print authz info"]
    PA_JSON --> PA_DONE["DONE"]
    PA_TEXT --> PA_LOOP["For each challenge"]
    PA_LOOP --> PA_MATCH{"type ==<br/>--challenge-type?"}
    PA_MATCH -- Yes --> PA_SHOW["Print challenge<br/>URL, status, token,<br/>key_authorization"]
    PA_MATCH -- No --> PA_SKIP["Skip"]
    PA_SHOW --> PA_DONE["DONE"]
    PA_SKIP --> PA_LOOP

    %% === renewal-info ===
    RI["renewal-info"] --> RI_URL{"account_url<br/>known?"}
    RI_URL -- No --> RI_LOOKUP["Auto-lookup account<br/>(POST-as-GET needs KID)"]
    RI_URL -- Yes --> RI_READ
    RI_LOOKUP --> RI_READ["Read cert PEM → DER"]
    RI_READ --> RI_CID["compute_cert_id()"]
    RI_CID --> RI_CALL["get_renewal_info()<br/>(RFC 9702)"]
    RI_CALL --> RI_FMT{"--output-format?"}

    RI_FMT -- json --> RI_JSON["JSON: cert_id,<br/>window.start/end,<br/>retry_after"]
    RI_JSON --> RI_DONE["DONE"]

    RI_FMT -- text --> RI_PRINT["Print cert_id +<br/>window start/end"]
    RI_PRINT --> RI_PARSE_END{"parse end time?"}
    RI_PARSE_END -- "now >= end" --> RI_OVERDUE["Status: renewal<br/>overdue"]
    RI_PARSE_END -- "now < end" --> RI_PARSE_START{"parse start<br/>time?"}
    RI_PARSE_END -- "parse fail" --> RI_RETRY
    RI_PARSE_START -- "now >= start" --> RI_RECO["Status: renewal<br/>recommended"]
    RI_PARSE_START -- "now < start" --> RI_WAIT["Status: not yet due<br/>(N days until window)"]
    RI_PARSE_START -- "parse fail" --> RI_RETRY
    RI_OVERDUE --> RI_RETRY{"retry_after?"}
    RI_RECO --> RI_RETRY
    RI_WAIT --> RI_RETRY
    RI_RETRY -- Yes --> RI_RETRY_PRINT["Print Retry-After"]
    RI_RETRY -- No --> RI_DONE
    RI_RETRY_PRINT --> RI_DONE

    classDef success fill:#4caf50,color:white,stroke:#2e7d32
    classDef decision fill:#42a5f5,color:white,stroke:#1565c0
    classDef error fill:#f44,color:white,stroke:#d32f2f
    classDef skip fill:#ff9800,color:white,stroke:#e65100
    class RV_DONE,PA_DONE,RI_DONE success
    class RI_OVERDUE error
    class RI_WAIT skip
    class RV_URL,RV_FMT,PA_URL,PA_FMT,PA_MATCH,RI_URL,RI_FMT,RI_PARSE_END,RI_PARSE_START,RI_RETRY decision
```

## Legend

- **Blue** — decision points
- **Red** — error/bail states
- **Orange** — skip (renewal not needed)
- **Green** — success/completion

## Key Flows

### Common Patterns

- **Output format branching**: Every command except `generate-config` checks `--output-format` (json/text) and formats output accordingly. JSON mode prints machine-readable objects; text mode prints human-friendly messages.
- **Account auto-lookup**: Five commands (`show-dns-persist01`, `key-rollover`, `revoke`, `renewal-info`, `pre-authorize`) need an account URL for KID-based JWS signing. If `--account-url` is not provided, they automatically call `create_account(None, true, None)` to look up/register the account.

### Run Flow Details

1. **Config precedence**: CLI > config file > env > defaults. Config overrides env in **both** modes. In config_mode, non-secret env vars (ACME_DIRECTORY_URL, ACME_ACCOUNT_KEY_FILE, etc.) are actively stripped.
2. **Renewal gate**: Both ARI and days checks are gated by `cert_output.exists()`. Before ARI/days, a **domain mismatch check** compares the existing cert's SANs against the requested domains. If they differ and `--reissue-on-mismatch` is set, ARI/days are bypassed entirely (reissuance, no `ari_cert_id`). If they differ without the flag, the tool skips with a warning. ARI (RFC 9702) checked first; if ARI succeeds and sets `ari_cert_id`, the days check is **skipped entirely**. Days check is a fallback when ARI is not used, fails, or is unsupported.
3. **Authorization path split**: `--dns-hook` + DNS challenge type triggers **phased parallel** (5 phases with concurrent propagation checks); everything else goes **sequential**. Sequential DNS paths are always manual (no hook) — hook-based DNS always takes the parallel path.
4. **Parallel phase 2 is conditional**: DNS propagation wait (phase 2) only runs if `--dns-wait` is set. Without it, phase 1 goes directly to phase 3.
5. **Challenge terminal logic**: Only `status == Invalid` is terminal; `Pending` with an error field keeps polling (allows step-ca retry).
6. **on-challenge-ready hook**: Called for dns-01, dns-persist-01, and tls-alpn-01 only. **NOT called for http-01** in any code path.
7. **"Press Enter" prompt**: Only shown when there is no `--dns-hook` AND no `--dns-wait` (interactive manual setup).
8. **Save order**: Private key is saved first (encrypted or not), then the certificate file.

## Secrets Allowed from Env in Config Mode

- `--key-password-file` (`ACME_KEY_PASSWORD_FILE`)
- `--eab-kid` (`ACME_EAB_KID`)
- `--eab-hmac-key` (`ACME_EAB_HMAC_KEY`)
