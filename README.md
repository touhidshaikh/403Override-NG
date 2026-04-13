# 403Override-NG
An advanced, multi-threaded Burp Suite extension designed to automate the discovery of 401 Unauthorized and 403 Forbidden access control bypasses. This tool utilizes aggressive path mutation, header injection, and segment fuzzing to uncover hidden attack surfaces.

Inspired by [403Override](https://github.com/Writeup-DB/403Override) Tool.


### Prerequisites
- Burp Suite (Professional or Community Edition).
- Jython Standalone JAR (v2.7.x) loaded into Burp Suite (Extender > Options > Python Environment)
  
### Installation
- Save the extension script as `403Override-NG.py` or clone the repository.
- Open Burp Suite and navigate to the Extensions tab.
- Click Add under the Extensions list.
- Set the Extension Type to Python.
- Click Select file... and choose `403Override-NG.py`.
- Look for the "403Override Pro v1 Loaded" message in the output log. A new 403Override tab will appear in the main Burp UI.

### Quick Start
- Passive Mode: Browse your target normally through Burp Proxy. If the extension is set to "Auto-Scan" (enabled by default), any 401 or 403 response will automatically be sent to the background fuzzing engine.
- Active Mode: Right-click any HTTP request in Proxy, Repeater, or Target, and select "Send to 403Override".
- Review: Navigate to the 403Override tab to watch live progress, review the color-coded results, and inspect Request/Response differences.

## Feature Document

### Core Capabilities
- **Passive Auto-Scanning & Deduplication:** Listens to Burp Proxy traffic. Automatically intercepts 401/403 responses, deduplicates them by endpoint (Host + Path), and silently fuzzes them in the background.
-** Dynamic Body Normalization (Anti-CSRF):** Prevents false positives caused by dynamic content. Users can input a Regex pattern (e.g., `csrf_token="[^"]+"` or `timestamps`). The engine strips these patterns from the response body before calculating the length difference.
- **Automated Issue Reporting:** Seamlessly integrates with Burp's native Issue Tracker. If a bypass results in a 2xx or 3xx status, it generates an Issue containing both the baseline and bypassed Request/Response pairs as proof.
- **Smart UI & Color Ledger:** Features a Repeater-style interface. Sortable tables with custom renderers instantly highlight bypasses (Bold/Green), internal routing errors (404 Purple), and Verb rejections (405 Blue).
- **State Persistence:** Automatically saves your custom wordlists, thread counts, delays, and regex patterns to Burp's persistent storage so they survive application restarts.

### The 4-Phase Attack Engine
The engine intelligently compiles permutations based on your allowed Methods (GET, POST, etc.) and executes them concurrently:
- **Phase 1 (Header Injection):** Appends spoofed IP headers (e.g., X-Forwarded-For, X-Custom-IP-Authorization) to the original path.
- **Phase 2 (Path Trailings):** Appends standard bypass sequences to the end of the URL (e.g., /api/users/..;/, /api/users.json).
- **Phase 3 (Parser Normalization / Segment Fuzzing):** Injects traversal sequences into every directory boundary of the path to exploit front-end/back-end parser discrepancies (e.g., /api/..;/users/).
- **Phase 4 (Advanced Mutations):** Modifies the structural integrity of the path via Uppercase, Titlecase, URL-encoding slashes (%2f, %252f), and Null Byte injections.

## Working Workflow Diagram
Below is the logical execution flow of the extension from the moment a request is triggered to the final UI update.
```plaintext
[ Trigger Event ]
       │
       ├─► Manual: User Right-Clicks -> "Send to 403Override"
       └─► Passive: Proxy detects 401/403 -> Deduplicates Endpoint -> Auto-Triggers
               │
               ▼
[ Initialization Phase ]
       │
       ├─► Extract Configurations (Headers, IPs, Trailings, Parsers, Delays, Threads)
       ├─► Extract Base Request info (Path, Query, Headers, Body Offset)
       ├─► Fetch Base Response Status and Body Length
       │
       ▼
[ Normalization Phase (Optional) ]
       │
       └─► Does "Ignore Regex" exist?
             ├── YES: Run Regex on Base Body -> Strip matches -> Recalculate Length
             └── NO: Keep raw Base Length
               │
               ▼
[ Payload Compilation Matrix ] ───► Calculates Total Payloads for Progress UI
       │
       ├─► Phase 1: Methods x Headers x IPs
       ├─► Phase 2: Methods x Path Trailings
       ├─► Phase 3: Methods x (Parsers injected at every '/' boundary)
       └─► Phase 4: Methods x (URL Encoding, Case Switch, Null Bytes)
               │
               ▼
[ Multi-Threaded Execution ] (java.util.concurrent.Executors)
       │
       └─► Thread Pool processes payloads concurrently (Delay applied if > 0)
               │
               ▼
[ Request Evaluation ] (Per Thread)
       │
       ├─► Send mutated Request via Burp IHttpService
       ├─► Receive Response -> Extract Status Code & Body
       ├─► Does "Ignore Regex" exist? -> Clean Body
       │
       ▼
[ Diff Engine ]
       │
       └─► Check: (New Status != Base Status) OR (abs(New Length - Base Length) > Tolerance)
             │
             ├─► Diff is TRUE: Mark as Bypass (Bold/Green in UI)
             │      └─► Is Status 2xx or 3xx? 
             │             └── YES: Generate IScanIssue & push to Burp Dashboard
             │
             └─► Diff is FALSE: Log standard attempt
               │
               ▼
[ UI Update & Teardown ]
       │
       ├─► Update Live Progress Bar (Task Table)
       ├─► Append attempt to Attempt Table (if Task is currently selected)
       └─► Shut down Thread Pool when complete -> Mark Task as "Completed"
```

## Lab for Testing
Found a Lab link below for Testing.
- [TheForbiddenFortress](https://github.com/Writeup-DB/TheForbiddenFortress) : This intentionally vulnerable environment is designed to demonstrate and test the capabilities of the **403Override-NG** Burp Suite extension. It simulates real-world architecture discrepancies between reverse proxies (Nginx) and back-end application servers.