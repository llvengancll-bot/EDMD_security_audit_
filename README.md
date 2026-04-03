# EDMD_security_audit_ Back Doors are atainable by running this tool
Security risks of using EDMD builds
Filename: EDMD_security_audit_20260402a.md                      
                                                                                                                                
  # EDMD Security Audit — Release 20260402a                                                                                     
  **Audit date:** 2026-04-02                                                                                                    
  **Method:** Static code analysis of full source at tag `20260402a` (commit `9aac962`)                                         
  **Files reviewed:** `edmd.py`, `core/config.py`, `core/data.py`, `core/emit.py`, `core/journal.py`, `core/plugin_loader.py`,  
  `core/state.py`, `builtins/eddn/plugin.py`, `builtins/edsm/plugin.py`, `builtins/inara/plugin.py`,                            
  `docs/auth/callback/index.html`, `example.config.toml`, `.github/workflows/windows-build.yml`

  ## High Findings

  ### FIND-H1 — Plugin System Has No Process-Level Sandbox                                                                      
  **File:** `core/plugin_loader.py` — `_load_one()`, `_make_sandboxed_open()`
  **CVSS:** 7.8                                                                                                                 
                                                                  
  **Description:**                                                                                                              
  Plugins are loaded via `importlib.util.spec_from_file_location` and `exec_module()`. The only restriction applied is a
  monkey-patch of `open()` in the plugin module's namespace that blocks writes outside the plugin's data directory. The source  
  code explicitly acknowledges this is bypassable:                
                                                                                                                                
  ```                                                             
  # A deliberately hostile plugin can still import builtins directly to bypass this.
  ```                                                                                                                           
   
  A malicious plugin has full access to: the `os` module (subprocesses, environment), `socket` (arbitrary network),             
  `requests`/`urllib` (data exfiltration), and the `core` API object which contains OAuth tokens via `core.data.capi`.
                                                                                                                                
  **Plugins are enabled by default. No signature check. No user prompt.**

### FIND-H2 — CAPI OAuth Tokens Stored in Plaintext                                                                           
  **File:** `core/data.py` — `CAPISource._save_tokens()` (~line 472)
  **CVSS:** 7.0                                                                                                                 
                                                                                                                                
  **Description:**                                                                                                              
  `capi_tokens.json` is written with `access_token`, `refresh_token`, `expiry`, and `cmdr` in cleartext JSON. Frontier refresh  
  tokens are long-lived. Any entity with read access to the user's home directory can authenticate to the Frontier CAPI         
  indefinitely.
                                                                                                                                
  The `cryptography` package is listed as a required dependency and is bundled in the Windows installer (~15 MB). It is not     
  imported or used anywhere in the codebase at this tag.
                                                                                                                                
  **Immediate fix (one line):**                                                                                                 
  In `PluginStorage.write_json()`, add after the atomic rename:
  ```python                                                                                                                     
  p.chmod(0o600)                                                  
  ```

## Medium Findings                                                                                                            
                                                                  
  ### FIND-M1 — OAuth Callback Missing Nonce Validation
  **File:** `core/data.py` — `_listen_for_callback()` (~line 180)
  **CVSS:** 5.3                                                                                                                 
   
  The local HTTP callback server does not validate the nonce component of the `state` parameter. PKCE covers the practical      
  exploit path, but nonce validation is a defence-in-depth requirement of the OAuth 2.0 spec.

### FIND-M2 — API Keys Stored Plaintext Without File Permission Restrictions                                                  
  **File:** `core/config.py`
  **CVSS:** 4.3                                                                                                                 
                                                                  
  EDSM API key, Inara API key, and Discord webhook URL are stored in `config.toml` with no `chmod` applied on creation. On      
  Linux, default permissions are typically `0644` (world-readable to other local users).

### FIND-M3 — urlopen Without Explicit SSL Context                                                                            
  **File:** `core/data.py`, `builtins/eddn/plugin.py`, `builtins/edsm/plugin.py`, `builtins/inara/plugin.py`
  **CVSS:** 4.0                                                                                                                 
                                                                                                                                
  All outbound HTTP calls use `urllib.request.urlopen()` without passing an explicit `ssl.create_default_context()`. Relies on  
  the platform SSL default, which may silently degrade on a misconfigured system or older Python patch release.  

 ### FIND-M4 — No Resolved-Path Containment Check in Journal File Reader                                                       
  **File:** `builtins/eddn/plugin.py` — `_read_json_file()` (~line 602)
  **CVSS:** 4.0                                                                                                                 
                                                                  
  Paths are constructed from the journal directory and a hardcoded event name string. No `path.resolve()` check confirms the    
  result stays within the journal directory. A symlink at any of the expected filename positions (`Market.json`,
  `Outfitting.json`, etc.) could redirect the read to an arbitrary file. 

  ### FIND-M5 — TOCTOU Race on OAuth Callback Port                                                                              
  **File:** `core/data.py` — `_run_auth_flow()` (~line 537)
  **CVSS:** 4.0                                                                                                                 
                                                                  
  An ephemeral port is allocated by binding a socket, the port number is extracted, the socket is closed, and then `HTTPServer` 
  opens the same port. Between close and re-open there is a window where another local process could bind to the same port.

