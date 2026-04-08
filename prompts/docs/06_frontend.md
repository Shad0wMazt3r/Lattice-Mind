# Frontend Reference

> Covers: `frontend/index.html`, `frontend/script.js`, `frontend/style.css`

---

## Stack

| Item | Detail |
|------|--------|
| Framework | None — vanilla JS (no React, Vue, etc.) |
| Lines | `script.js` ~1644, `index.html` ~500, `style.css` ~800 |
| Theme | Cyberpunk dark |
| Static serving | Mounted at `/static/` by FastAPI |

---

## Boot Sequence

1. Page load → animated terminal lines (ASCII art + boot messages)
2. Fade transition → Matrix canvas rain animation
3. JWT check: if `localStorage.token` valid → skip login, go to dashboard
4. Login form appears over Matrix canvas
5. `POST /auth/login` → store `{token, role}` in `localStorage`
6. Dashboard initializes (5 tabs rendered)

---

## 5 Tabs

### Tab 1: ACTIVE RUN

| Panel | Detail |
|-------|--------|
| SVG decision tree | BFS layout; nodes color-coded by status |
| Node inspector | Click a node → shows `data`, `error`, `next_node` |
| Terminal output | Last 50 progress steps in a scrollable pre block |
| Confidence bar chart | One bar per YAML tree; updates live |
| Observations panel | `tech_stack`, `found_paths`, `params` from recon |

**Node SVG colors:**
- `running` → amber
- `success` → teal
- `failure` → red
- `flag_found` → cyan

**WebSocket subscription:** opened on tab load for the active `run_id`. Reconnects automatically on disconnect. Messages:
- `init` → populate all panels from full run state
- `step` → append to terminal, update tree node color, update confidence bar
- `update` → refresh status badge and timestamps

### Tab 2: HISTORY

- Searchable run table (run_id, name, status, flag, timestamps)
- Per-row actions:
  - **VIEW** — loads run into Active Run tab, opens WS
  - **DETAILS** — 3-tab modal: Summary / Steps / Observations
  - **RERUN** — `POST /runs/{run_id}/rerun`

### Tab 3: HITL

- Polls `GET /hitl/pending` every 2 seconds
- Pending question count shown as badge in header
- For each question: shows `question_text`, `qid`, an answer input, and Submit button
- Submit → `POST /hitl/{qid}/answer`

### Tab 4: RULES

- Lists all YAML trees from `GET /rules`
- Enable/disable toggle per tree (via `PUT /settings` or tree-specific endpoint)
- **Reload** button → `POST /rules/reload`
- Click tree → inline YAML viewer

### Tab 5: CRYPTO TOOLS

- Client-side decoder UI
- Supported operations: `base64`, `hex`, `url`, `caesar`, `xor`, `rsa`, `binary`, `morse`
- Each decodes client-side where possible, or calls `POST /crypto/solve` for complex operations

---

## Panel Persistence

Three panel widths saved in `localStorage`:

| Key | Panel |
|-----|-------|
| `lattice_sidebar_width` | Left sidebar |
| `lattice_tree_panel_width` | Decision tree SVG panel |
| `lattice_node_details_height` | Node details panel height |

On load: `parseInt(localStorage.getItem(key)) || DEFAULT_VALUE`. Restored via inline style.

---

## WebSocket Client

```javascript
function connectWebSocket(runId) {
    const token = localStorage.getItem('token');
    const ws = new WebSocket(`ws://${location.host}/ws/${runId}?token=${token}`);

    ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        if (msg.type === 'init')   handleInit(msg.run);
        if (msg.type === 'step')   handleStep(msg.event);
        if (msg.type === 'update') handleUpdate(msg.run);
    };

    ws.onclose = () => setTimeout(() => connectWebSocket(runId), 3000);  // auto-reconnect
}
```

---

## SVG Tree Layout (BFS)

- Each progress event with `node_id` is placed as a `<circle>` + `<text>` node
- `parent_node_id` draws an `<line>` edge
- BFS x/y positions calculated on the fly as new nodes arrive
- Colors updated in-place via `document.getElementById(nodeId).setAttribute('fill', color)`

---

## API Interaction Pattern

All API calls go through a `request(method, path, body)` helper:

```javascript
async function request(method, path, body = null) {
    const res = await fetch(path, {
        method,
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${localStorage.getItem('token')}`,
        },
        body: body ? JSON.stringify(body) : null,
    });
    if (res.status === 401) {
        localStorage.removeItem('token');
        location.reload();   // force re-login on token expiry
    }
    return res.json();
}
```

---

## Modifying the Frontend

- **No build step** — edit `frontend/script.js` / `frontend/style.css` directly; browser refresh picks up changes
- **Static path:** `frontend/` files served from `/static/` — `index.html` is served at `/` by FastAPI's HTML response route
- **Adding a new tab:** add `<li>` to the tab bar in `index.html`, add `<div id="tab-X">` content section, add `switchTab('X')` handler in `script.js`
- **New API calls:** add a branch to the `request()` wrapper or call directly; always include the Bearer header
