"""Local test HTTP servers for integration testing.

Two aiohttp apps:
- Web app: serves pages the crawler navigates
- API app: acts as an "external" API on a different port (different netloc = detected as external)
"""
from aiohttp import web


CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "*",
    "Access-Control-Allow-Methods": "*",
}


def create_web_app(api_port: int) -> web.Application:
    """Create the main web app that serves pages for the crawler."""

    async def home(request):
        html = f"""<!DOCTYPE html>
<html><head><title>Test Home</title></head>
<body>
<nav>
  <a href="/page1">Page 1</a>
  <a href="/page2">Page 2</a>
  <a href="/logout">Logout</a>
</nav>
<p>Welcome to the test site.</p>
</body></html>"""
        return web.Response(text=html, content_type="text/html")

    async def page1(request):
        html = f"""<!DOCTYPE html>
<html><head><title>Page 1 - Form</title></head>
<body>
<h1>Page 1</h1>
<a href="/page2">Go to Page 2</a>
<form id="testform">
  <input type="email" name="email" placeholder="Email" />
  <input type="password" name="password" placeholder="Password" />
  <select name="role">
    <option value="">--Select--</option>
    <option value="admin">Admin</option>
    <option value="user">User</option>
  </select>
  <button type="submit">Submit</button>
</form>
<script>
document.getElementById('testform').addEventListener('submit', function(e) {{
  e.preventDefault();
  fetch('http://localhost:{api_port}/v1/users', {{
    method: 'POST',
    headers: {{
      'Authorization': 'Bearer test-token-123',
      'Content-Type': 'application/json'
    }},
    body: JSON.stringify({{ email: document.querySelector('[name=email]').value }})
  }});
}});
</script>
</body></html>"""
        return web.Response(text=html, content_type="text/html")

    async def page2(request):
        html = f"""<!DOCTYPE html>
<html><head><title>Page 2 - Actions</title></head>
<body>
<h1>Page 2</h1>
<button id="load-data">Load Data</button>
<script>
document.getElementById('load-data').addEventListener('click', function() {{
  fetch('http://localhost:{api_port}/v1/data', {{
    headers: {{ 'x-api-key': 'test-key-123' }}
  }});
}});
</script>
</body></html>"""
        return web.Response(text=html, content_type="text/html")

    async def logout(request):
        html = """<!DOCTYPE html>
<html><head><title>Logout</title></head>
<body><p>You have been logged out.</p></body></html>"""
        return web.Response(text=html, content_type="text/html")

    async def login_get(request):
        html = """<!DOCTYPE html>
<html><head><title>Login</title></head>
<body>
<form method="POST" action="/login">
  <input id="username" name="username" type="text" />
  <input name="password" type="password" />
  <button type="submit">Sign in</button>
</form>
</body></html>"""
        return web.Response(text=html, content_type="text/html")

    async def login_post(request):
        data = await request.post()
        if data.get("username") == "test@example.com" and data.get("password") == "hunter2":
            resp = web.HTTPFound("/protected")
            resp.set_cookie("session", "valid", path="/")
            raise resp
        return web.Response(status=401, text="bad creds")

    async def protected(request):
        if request.cookies.get("session") != "valid":
            raise web.HTTPFound("/login")
        html = f"""<!DOCTYPE html>
<html><head><title>Protected</title></head>
<body>
<h1>Protected</h1>
<script>
fetch('http://localhost:{api_port}/v1/users', {{
  method: 'POST',
  headers: {{
    'Authorization': 'Bearer protected-token',
    'Content-Type': 'application/json'
  }},
  body: JSON.stringify({{ ok: true }})
}});
</script>
</body></html>"""
        return web.Response(text=html, content_type="text/html")

    async def unauth(request):
        html = f"""<!DOCTYPE html>
<html><head><title>Unauth</title></head>
<body>
<button id="go">Go</button>
<script>
document.getElementById('go').addEventListener('click', function() {{
  fetch('http://localhost:{api_port}/v1/secret');
}});
document.getElementById('go').click();
</script>
</body></html>"""
        return web.Response(text=html, content_type="text/html")

    async def idp_trigger(request):
        html = f"""<!DOCTYPE html>
<html><head><title>IdP</title></head>
<body>
<script>
fetch('http://localhost:{api_port}/v1/oauth-redirect').catch(function() {{}});
</script>
</body></html>"""
        return web.Response(text=html, content_type="text/html")

    app = web.Application()
    app.router.add_get("/", home)
    app.router.add_get("/page1", page1)
    app.router.add_get("/page2", page2)
    app.router.add_get("/logout", logout)
    app.router.add_get("/login", login_get)
    app.router.add_post("/login", login_post)
    app.router.add_get("/protected", protected)
    app.router.add_get("/unauth", unauth)
    app.router.add_get("/idp-trigger", idp_trigger)
    return app


def create_api_app() -> web.Application:
    """Create the fake external API app."""

    @web.middleware
    async def cors_middleware(request, handler):
        if request.method == "OPTIONS":
            return web.Response(headers=CORS_HEADERS)
        response = await handler(request)
        response.headers.update(CORS_HEADERS)
        return response

    async def users(request):
        return web.json_response({"status": "ok", "users": []})

    async def data(request):
        return web.json_response({"status": "ok", "data": []})

    async def secret(request):
        return web.Response(
            status=401,
            headers={**CORS_HEADERS, "WWW-Authenticate": 'Bearer realm="api"'},
            text="unauthorized",
        )

    async def oauth_redirect(request):
        return web.Response(
            status=302,
            headers={
                **CORS_HEADERS,
                "Location": "https://tenant.auth0.com/authorize?client_id=x",
            },
        )

    app = web.Application(middlewares=[cors_middleware])
    app.router.add_post("/v1/users", users)
    app.router.add_get("/v1/data", data)
    app.router.add_get("/v1/secret", secret)
    app.router.add_get("/v1/oauth-redirect", oauth_redirect)
    app.router.add_route("OPTIONS", "/v1/users", users)
    app.router.add_route("OPTIONS", "/v1/data", data)
    app.router.add_route("OPTIONS", "/v1/secret", secret)
    app.router.add_route("OPTIONS", "/v1/oauth-redirect", oauth_redirect)
    return app
