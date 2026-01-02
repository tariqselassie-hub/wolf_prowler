# Frontend Architecture & Asset Management

## 🎯 Architecture Overview
The Wolf Prowler frontend (`wolf_web`) is designed as a **Single Source of Truth** for all user interface components. It operates independently of the backend logic structure but shares the same Axum server instance.

### 🔑 Core Principles
1.  **Centralized Assets**: All static files (HTML, CSS, JS, Images) reside exclusively in `wolf_web/static/`.
2.  **Explicit Routing**: The backend server explicitly maps `/static` URL paths to this specific directory.
3.  **No "Rogue" Statics**: Do **NOT** create top-level `static/` or `assets/` directories in the project root.

## 📂 Directory Structure

```plaintext
wolf_web/
├── static/                # The ONLY place for frontend assets
│   ├── css/               # Stylesheets (shared & page-specific)
│   ├── js/                # Client-side scripts
│   │   ├── api.js         # Centralized API client (Auth/Errors)
│   │   ├── websocket.js   # Real-time connection handler
│   │   └── ...            # Feature-specific scripts
│   ├── img/               # Images and icons
│   ├── api/               # API Documentation & Test Pages
│   └── *.html             # Dashboard pages
├── src/                   # (Optional) Rust-based frontend logic (WASM/Leptos in future)
└── README.md              # Component documentation
```

## 🛤️ URL Routing & Serving Strategy

The backend (`src/main.rs`) handles static file requests using a specific strategy to ensure 404s are minimized and paths are predictable.

### 1. Embedded Routes (Primary)
Critical pages are **compiled into the binary** using `include_str!`. This allows the server to serve them directly from memory, reducing I/O and modifying response headers easily.

- **Route**: `GET /dashboard`
- **File**: `wolf_web/static/dashboard_modern.html`
- **Handler**: `include_str!("../../wolf_web/static/dashboard_modern.html")`

### 2. Static Nesting (Secondary)
The `/static` prefix is explicitly nested to serve any file within the `wolf_web/static` directory. This is how images, CSS, JS, and non-embedded HTML pages are served.

- **Route**: `GET /static/*`
- **Source**: `wolf_web/static`
- **Mechanism**: `nest_service("/static", ServeDir::new("wolf_web/static"))`

### 3. Fallback Service (Safety Net)
If a route is not matched by API or explicit handlers, the fallback attempts to find it in `wolf_web/static`.

- **Mechanism**: `.fallback_service(ServeDir::new("wolf_web/static"))`

## 🚫 Anti-Patterns (Do NOT Do This!)
- ❌ **Root Static**: Never create a `static/` folder in the project root. It confuses the build and deployment logic.
- ❌ **Asset Duplication**: Do not copy assets to `target/` or `debug/`. The server reads directly from source during dev.
- ❌ **Hardcoded Paths**: In Rust code, avoid `File::open("static/...")`. Always use relative paths from `wolf_web/` or the configured static directory constant.

## 🔌 API Integration (`api.js`)
All frontend pages must use `wolf_web/static/js/api.js` for backend communication. This ensures:
- **Authentication**: Usage of `X-API-Key`.
- **Error Handling**: Unified 401/403 redirects.
- **Type Safety**: Consistent JSON parsing.

```javascript
import { getJson } from '/static/js/api.js';

async function loadData() {
    try {
        const data = await getJson('/api/v1/resource');
        updateUI(data);
    } catch (e) {
        console.error("Failed to load:", e);
    }
}
```
