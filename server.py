import os
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

ETSY_API_BASE = "https://api.etsy.com/v3/application"
ETSY_TOKEN_URL = "https://api.etsy.com/v3/public/oauth/token"

mcp = FastMCP(
    "Lunar Loom Keepsakes Etsy MCP",
    stateless_http=True,
)


async def get_access_token() -> str:
    refresh_token = os.environ["ETSY_REFRESH_TOKEN"]
    api_key = os.environ["ETSY_API_KEY"]

    async with httpx.AsyncClient() as client:
        response = await client.post(
            ETSY_TOKEN_URL,
            data={
                "grant_type": "refresh_token",
                "client_id": api_key,
                "refresh_token": refresh_token,
            },
        )
        response.raise_for_status()
        return response.json()["access_token"]


async def etsy_get(path: str, params: dict[str, Any] | None = None):
    api_key = os.environ["ETSY_API_KEY"]
    shared_secret = os.environ["ETSY_SHARED_SECRET"]

    access_token = await get_access_token()

    headers = {
        "x-api-key": f"{api_key}:{shared_secret}",
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


@mcp.tool()
async def get_shop() -> dict:
    """Get information about the connected Etsy shop."""
    shop_id = os.environ["ETSY_SHOP_ID"]
    return await etsy_get(f"/shops/{shop_id}")


@mcp.tool()
async def get_active_listings(limit: int = 100) -> dict:
    """Get active listings from the connected Etsy shop."""
    shop_id = os.environ["ETSY_SHOP_ID"]

    return await etsy_get(
        f"/shops/{shop_id}/listings/active",
        params={
            "limit": min(limit, 100),
            "includes": "Images,Shop",
        },
    )


@mcp.tool()
async def get_listing(listing_id: int) -> dict:
    """Get one Etsy listing by listing ID."""
    return await etsy_get(
        f"/listings/{listing_id}",
        params={
            "includes": "Images,Shop",
        },
    )


@mcp.tool()
async def search_listings(query: str, limit: int = 100) -> list[dict]:
    """Search the connected shop's active listings by title, description, or tags."""
    shop_id = os.environ["ETSY_SHOP_ID"]

    data = await etsy_get(
        f"/shops/{shop_id}/listings/active",
        params={
            "limit": min(limit, 100),
            "includes": "Images,Shop",
        },
    )

    query_lower = query.lower()
    matches = []

    for listing in data.get("results", []):
        title = listing.get("title", "")
        description = listing.get("description", "")
        tags = " ".join(listing.get("tags", []))

        searchable_text = (
            f"{title} {description} {tags}"
        ).lower()

        if query_lower in searchable_text:
            matches.append(listing)

    return matches


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))

    mcp.settings.host = "0.0.0.0"
    mcp.settings.port = port

    mcp.run(transport="streamable-http")
