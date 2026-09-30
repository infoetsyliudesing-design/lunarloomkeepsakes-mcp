import os
import base64
import hashlib
import secrets
from urllib.parse import urlencode

import httpx
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, JSONResponse


ETSY_API_BASE = "https://api.etsy.com/v3/application"
ETSY_TOKEN_URL = "https://api.etsy.com/v3/public/oauth/token"
ETSY_AUTH_URL = "https://www.etsy.com/oauth/connect"

ETSY_API_KEY = os.environ["ETSY_API_KEY"]
ETSY_SHARED_SECRET = os.environ["ETSY_SHARED_SECRET"]

REDIRECT_URI = os.environ.get("ETSY_REDIRECT_URI", "")

RENDER_HOST = "lunarloomkeepsakes-mcp.onrender.com"

# Security settings for the public Render hostname.
transport_security = TransportSecuritySettings(
    allowed_hosts=[
        RENDER_HOST,
        f"{RENDER_HOST}:*",
    ],
    allowed_origins=[
        f"https://{RENDER_HOST}",
    ],
)

mcp = FastMCP(
    "Lunar Loom Keepsakes Etsy MCP",
    stateless_http=True,
)

oauth_sessions = {}

# Automatically discovered Etsy Shop ID.
_cached_shop_id = None


def create_pkce_pair():
    verifier = (
        base64.urlsafe_b64encode(secrets.token_bytes(32))
        .rstrip(b"=")
        .decode("ascii")
    )

    challenge = (
        base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()
        )
        .rstrip(b"=")
        .decode("ascii")
    )

    return verifier, challenge


@mcp.custom_route("/health", methods=["GET"])
async def health(request: Request):
    return JSONResponse({"status": "ok"})


@mcp.custom_route("/oauth/start", methods=["GET"])
async def oauth_start(request: Request):
    if not REDIRECT_URI:
        return HTMLResponse(
            "<h2>ETSY_REDIRECT_URI is not configured.</h2>",
            status_code=500,
        )

    state = secrets.token_urlsafe(32)
    verifier, challenge = create_pkce_pair()

    oauth_sessions[state] = verifier

    params = {
        "response_type": "code",
        "client_id": ETSY_API_KEY,
        "redirect_uri": REDIRECT_URI,
        "scope": "listings_r shops_r",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }

    authorization_url = (
        f"{ETSY_AUTH_URL}?{urlencode(params)}"
    )

    return RedirectResponse(authorization_url)


@mcp.custom_route("/oauth/callback", methods=["GET"])
async def oauth_callback(request: Request):
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")

    if error:
        description = request.query_params.get(
            "error_description",
            "Etsy authorization was not completed.",
        )

        return HTMLResponse(
            f"<h2>Etsy authorization failed</h2>"
            f"<p>{description}</p>",
            status_code=400,
        )

    if not code or not state:
        return HTMLResponse(
            "<h2>Missing OAuth code or state.</h2>",
            status_code=400,
        )

    verifier = oauth_sessions.pop(state, None)

    if not verifier:
        return HTMLResponse(
            "<h2>Invalid or expired OAuth state.</h2>",
            status_code=400,
        )

    data = {
        "grant_type": "authorization_code",
        "client_id": ETSY_API_KEY,
        "redirect_uri": REDIRECT_URI,
        "code": code,
        "code_verifier": verifier,
    }

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            ETSY_TOKEN_URL,
            data=data,
            headers=headers,
        )

    if response.status_code >= 400:
        return HTMLResponse(
            "<h2>Etsy token exchange failed</h2>"
            f"<pre>{response.text}</pre>",
            status_code=400,
        )

    token_data = response.json()
    refresh_token = token_data.get("refresh_token")

    if not refresh_token:
        return HTMLResponse(
            "<h2>Etsy did not return a refresh token.</h2>",
            status_code=400,
        )

    masked = (
        refresh_token[:12]
        + "..."
        + refresh_token[-6:]
        if len(refresh_token) > 20
        else "***"
    )

    return HTMLResponse(
        f"""
        <html>
        <body>
            <h2>Etsy authorization successful</h2>

            <p>Your Etsy account has authorized this MCP.</p>

            <p>
                Refresh token received:
                <strong>{masked}</strong>
            </p>

            <p>
                The refresh token is stored securely in Render.
            </p>

            <p>You may close this window.</p>
        </body>
        </html>
        """
    )


async def get_access_token():
    refresh_token = os.environ["ETSY_REFRESH_TOKEN"]

    data = {
        "grant_type": "refresh_token",
        "client_id": ETSY_API_KEY,
        "refresh_token": refresh_token,
    }

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            ETSY_TOKEN_URL,
            data=data,
            headers=headers,
        )

    response.raise_for_status()

    token_data = response.json()

    return token_data["access_token"]


async def etsy_get(path, params=None):
    access_token = await get_access_token()

    headers = {
        "x-api-key": f"{ETSY_API_KEY}:{ETSY_SHARED_SECRET}",
        "Authorization": f"Bearer {access_token}",
    }

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.get(
            f"{ETSY_API_BASE}{path}",
            headers=headers,
            params=params,
        )

    response.raise_for_status()

    return response.json()


async def get_shop_id():
    """
    Automatically discover the Etsy shop associated
    with the authorized Etsy account.
    """

    global _cached_shop_id

    if _cached_shop_id is not None:
        return _cached_shop_id

    access_token = await get_access_token()

    try:
        user_id = int(access_token.split(".", 1)[0])
    except (ValueError, IndexError):
        raise RuntimeError(
            "Unable to determine Etsy user ID from the access token."
        )

    data = await etsy_get(
        f"/users/{user_id}/shops"
    )

    shops = data.get("results", [])

    if not shops:
        raise RuntimeError(
            "No Etsy shop was found for the authorized account."
        )

    _cached_shop_id = shops[0]["shop_id"]

    return _cached_shop_id


@mcp.tool()
async def get_shop() -> dict:
    """Read information about the connected Etsy shop."""

    shop_id = await get_shop_id()

    return await etsy_get(
        f"/shops/{shop_id}"
    )


@mcp.tool()
async def get_active_listings(limit: int = 100) -> dict:
    """Read active listings from the connected Etsy shop."""

    shop_id = await get_shop_id()

    return await etsy_get(
        f"/shops/{shop_id}/listings/active",
        params={
            "limit": min(limit, 100),
        },
    )


@mcp.tool()
async def get_listing(listing_id: int) -> dict:
    """Read one Etsy listing by listing ID."""

    return await etsy_get(
        f"/listings/{listing_id}"
    )


@mcp.tool()
async def search_listings(
    query: str,
    limit: int = 100,
) -> list:
    """Search active Etsy listings by title, description, or tags."""

    shop_id = await get_shop_id()

    data = await etsy_get(
        f"/shops/{shop_id}/listings/active",
        params={
            "limit": min(limit, 100),
        },
    )

    query_lower = query.lower()
    matches = []

    for listing in data.get("results", []):
        title = listing.get("title", "")
        description = listing.get("description", "")
        tags = " ".join(listing.get("tags", []))

        searchable = (
            f"{title} {description} {tags}"
        ).lower()

        if query_lower in searchable:
            matches.append(listing)

    return matches


if __name__ == "__main__":
    port = int(
        os.environ.get("PORT", "8000")
    )

    mcp.settings.host = "0.0.0.0"
    mcp.settings.port = port

    mcp.run(
        transport="streamable-http",
        transport_security=transport_security,
    )
