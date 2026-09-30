import os
import base64
import hashlib
import secrets
import time
import asyncio
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


# ---------------------------------------------------------
# Render / MCP security
# ---------------------------------------------------------

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
    transport_security=transport_security,
)


# ---------------------------------------------------------
# OAuth state
# ---------------------------------------------------------

oauth_sessions = {}


# ---------------------------------------------------------
# Etsy cache
# ---------------------------------------------------------

_cached_shop_id = None

# Current Etsy access token.
_access_token = None

# Unix timestamp when the access token expires.
_access_token_expires_at = 0

# Always use the newest refresh token received from Etsy.
_current_refresh_token = os.environ["ETSY_REFRESH_TOKEN"]

# Prevent two requests from refreshing OAuth simultaneously.
_token_lock = asyncio.Lock()


# ---------------------------------------------------------
# PKCE
# ---------------------------------------------------------

def create_pkce_pair():
    verifier = (
        base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        )
        .rstrip(b"=")
        .decode("ascii")
    )

    challenge = (
        base64.urlsafe_b64encode(
            hashlib.sha256(
                verifier.encode("ascii")
            ).digest()
        )
        .rstrip(b"=")
        .decode("ascii")
    )

    return verifier, challenge


# ---------------------------------------------------------
# Health check
# ---------------------------------------------------------

@mcp.custom_route("/health", methods=["GET"])
async def health(request: Request):
    return JSONResponse(
        {
            "status": "ok"
        }
    )


# ---------------------------------------------------------
# Etsy OAuth start
# ---------------------------------------------------------

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

    return RedirectResponse(
        authorization_url
    )


# ---------------------------------------------------------
# Etsy OAuth callback
# ---------------------------------------------------------

@mcp.custom_route("/oauth/callback", methods=["GET"])
async def oauth_callback(request: Request):

    global _current_refresh_token
    global _access_token
    global _access_token_expires_at
    global _cached_shop_id

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

    verifier = oauth_sessions.pop(
        state,
        None,
    )

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

    async with httpx.AsyncClient(
        timeout=30
    ) as client:

        response = await client.post(
            ETSY_TOKEN_URL,
            data=data,
            headers=headers,
        )

    if response.status_code >= 400:

        print(
            "Etsy OAuth authorization-code exchange failed: "
            f"{response.status_code} - {response.text}"
        )

        return HTMLResponse(
            "<h2>Etsy token exchange failed</h2>"
            f"<pre>{response.text}</pre>",
            status_code=400,
        )

    token_data = response.json()

    new_access_token = token_data.get(
        "access_token"
    )

    new_refresh_token = token_data.get(
        "refresh_token"
    )

    expires_in = token_data.get(
        "expires_in",
        3600,
    )

    if not new_access_token:
        return HTMLResponse(
            "<h2>Etsy did not return an access token.</h2>",
            status_code=400,
        )

    if not new_refresh_token:
        return HTMLResponse(
            "<h2>Etsy did not return a refresh token.</h2>",
            status_code=400,
        )

    # Store the newest tokens in memory.
    _access_token = new_access_token

    _access_token_expires_at = (
        time.time()
        + int(expires_in)
    )

    _current_refresh_token = new_refresh_token

    # The shop ID may have changed if a different Etsy
    # account was authorized.
    _cached_shop_id = None

    masked = (
        new_refresh_token[:12]
        + "..."
        + new_refresh_token[-6:]
        if len(new_refresh_token) > 20
        else "***"
    )

    print(
        "Etsy OAuth authorization successful."
    )

    print(
        "New refresh token received: "
        f"{masked}"
    )

    return HTMLResponse(
        f"""
        <html>
        <body>
            <h2>Etsy authorization successful</h2>

            <p>
                Your Etsy account has authorized this MCP.
            </p>

            <p>
                New refresh token received:
                <strong>{masked}</strong>
            </p>

            <p>
                The new refresh token is currently active
                in this server session.
            </p>

            <p>
                You may close this window.
            </p>
        </body>
        </html>
        """
    )


# ---------------------------------------------------------
# Etsy access token
# ---------------------------------------------------------

async def get_access_token():

    global _access_token
    global _access_token_expires_at
    global _current_refresh_token

    # Fast path:
    # Reuse the current access token if it is still valid.
    if (
        _access_token
        and time.time()
        < _access_token_expires_at - 60
    ):
        return _access_token

    # Prevent simultaneous OAuth refreshes.
    async with _token_lock:

        # Another request may have refreshed the token
        # while this request was waiting for the lock.
        if (
            _access_token
            and time.time()
            < _access_token_expires_at - 60
        ):
            return _access_token

        data = {
            "grant_type": "refresh_token",
            "client_id": ETSY_API_KEY,
            "refresh_token": _current_refresh_token,
        }

        headers = {
            "Content-Type":
                "application/x-www-form-urlencoded",
        }

        async with httpx.AsyncClient(
            timeout=30
        ) as client:

            response = await client.post(
                ETSY_TOKEN_URL,
                data=data,
                headers=headers,
            )

        # Log Etsy's actual response when OAuth fails.
        if response.status_code >= 400:

            print(
                "Etsy OAuth refresh failed: "
                f"{response.status_code} - "
                f"{response.text}"
            )

            response.raise_for_status()

        token_data = response.json()

        new_access_token = token_data.get(
            "access_token"
        )

        new_refresh_token = token_data.get(
            "refresh_token"
        )

        expires_in = token_data.get(
            "expires_in",
            3600,
        )

        if not new_access_token:

            raise RuntimeError(
                "Etsy did not return an access_token."
            )

        # Cache access token.
        _access_token = new_access_token

        # Etsy normally returns 3600 seconds.
        _access_token_expires_at = (
            time.time()
            + int(expires_in)
        )

        # Etsy may rotate the refresh token.
        if new_refresh_token:

            _current_refresh_token = (
                new_refresh_token
            )

            masked = (
                new_refresh_token[:12]
                + "..."
                + new_refresh_token[-6:]
                if len(new_refresh_token) > 20
                else "***"
            )

            print(
                "Etsy OAuth refresh successful."
            )

            print(
                "New refresh token received: "
                f"{masked}"
            )

        return _access_token


# ---------------------------------------------------------
# Etsy API GET
# ---------------------------------------------------------

async def etsy_get(
    path,
    params=None,
):

    access_token = await get_access_token()

    headers = {
        "x-api-key":
            f"{ETSY_API_KEY}:{ETSY_SHARED_SECRET}",

        "Authorization":
            f"Bearer {access_token}",
    }

    async with httpx.AsyncClient(
        timeout=30
    ) as client:

        response = await client.get(
            f"{ETSY_API_BASE}{path}",
            headers=headers,
            params=params,
        )

    # If Etsy says the access token is invalid,
    # clear the cached access token so the next
    # request will perform a fresh OAuth refresh.
    if response.status_code == 401:

        global _access_token
        global _access_token_expires_at

        _access_token = None
        _access_token_expires_at = 0

        response.raise_for_status()

    response.raise_for_status()

    return response.json()


# ---------------------------------------------------------
# Etsy shop discovery
# ---------------------------------------------------------

async def get_shop_id():

    global _cached_shop_id

    if _cached_shop_id is not None:
        return _cached_shop_id

    access_token = await get_access_token()

    try:

        user_id = int(
            access_token.split(
                ".",
                1
            )[0]
        )

    except (
        ValueError,
        IndexError,
    ):

        raise RuntimeError(
            "Unable to determine Etsy user ID "
            "from the access token."
        )

    data = await etsy_get(
        f"/users/{user_id}/shops"
    )

    shops = data.get(
        "results",
        []
    )

    if not shops:

        raise RuntimeError(
            "No Etsy shop was found "
            "for the authorized account."
        )

    _cached_shop_id = shops[0][
        "shop_id"
    ]

    return _cached_shop_id


# ---------------------------------------------------------
# MCP: Get shop
# ---------------------------------------------------------

@mcp.tool()
async def get_shop() -> dict:
    """Read information about the connected Etsy shop."""

    shop_id = await get_shop_id()

    return await etsy_get(
        f"/shops/{shop_id}"
    )


# ---------------------------------------------------------
# MCP: Active listings
# ---------------------------------------------------------

@mcp.tool()
async def get_active_listings(
    limit: int = 100
) -> dict:
    """Read active listings from the connected Etsy shop."""

    shop_id = await get_shop_id()

    return await etsy_get(
        f"/shops/{shop_id}/listings/active",
        params={
            "limit": min(
                limit,
                100
            ),
        },
    )


# ---------------------------------------------------------
# MCP: Get listing
# ---------------------------------------------------------

@mcp.tool()
async def get_listing(
    listing_id: int
) -> dict:
    """Read one Etsy listing by listing ID."""

    return await etsy_get(
        f"/listings/{listing_id}"
    )


# ---------------------------------------------------------
# MCP: Search listings
# ---------------------------------------------------------

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
            "limit": min(
                limit,
                100
            ),
        },
    )

    query_lower = query.lower()

    matches = []

    for listing in data.get(
        "results",
        []
    ):

        title = listing.get(
            "title",
            ""
        )

        description = listing.get(
            "description",
            ""
        )

        tags = " ".join(
            listing.get(
                "tags",
                []
            )
        )

        searchable = (
            f"{title} "
            f"{description} "
            f"{tags}"
        ).lower()

        if query_lower in searchable:

            matches.append(
                listing
            )

    return matches


# ---------------------------------------------------------
# Server startup
# ---------------------------------------------------------

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            "8000"
        )
    )

    mcp.settings.host = "0.0.0.0"

    mcp.settings.port = port

    mcp.run(
        transport="streamable-http",
    )
