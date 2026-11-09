TECH_SIGNATURES = {
    "React": {
        "methods": ["html", "script"],
        "signatures": {
            "html": ["data-reactroot", "data-reactid", "react-root", "__react"],
            "script": ["react.", "react-dom.", "react.production.min.js"]
        },
        "category": "frontend_framework",
        "icon": "⚛️"
    },

    "Next.js": {
        "methods": ["html", "script"],
        "signatures": {
            "html": ["__NEXT_DATA__", "id=\"__next\"", "__NEXT_LOADED_PAGES__"],
            "script": ["/_next/static/", "/_next/chunks/"]
        },
        "category": "frontend_framework",
        "icon": "▲"
    },

    "Django": {
        "methods": ["cookie", "html"],
        "signatures": {
            "cookie": ["csrftoken", "django_session", "sessionid"],
            "html": ["csrfmiddlewaretoken", "__debug__", "Django administration"]
        },
        "category": "backend_framework",
        "icon": "🐍"
    },
    
    "nginx": {
        "methods": ["header"],
        "signatures": {
            "header": ["Server: nginx", "nginx/"]
        },
        "category": "web_server",
        "icon": "🟩"
    },
    
    "Cloudflare": {
        "methods": ["header", "cookie"],
        "signatures": {
            "header": ["CF-RAY", "CF-Cache-Status", "cloudflare"],
            "cookie": ["__cfduid", "__cflb", "__cf_bm"]
        },
        "category": "cdn",
        "icon": "☁️"
    },
}