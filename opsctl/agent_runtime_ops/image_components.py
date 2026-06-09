from __future__ import annotations


IMAGE_COMPONENTS = {
    "ghcr.io/epicevent/hermes-jitech": "hermes-agent",
    "ghcr.io/epicevent/hermes-workspace": "hermes-workspace",
    "ghcr.io/epicevent/openclaw-nas-agent": "combined-runtime",
    "ghcr.io/epicevent/openclaw-jitech": "openclaw-control",
    "ghcr.io/epicevent/agent-runtime-hermes": "hermes-wrapper",
    "ghcr.io/epicevent/agent-runtime-openclaw": "openclaw-wrapper",
}


def image_repo(image_ref: object) -> str:
    if not isinstance(image_ref, str):
        return ""
    text = image_ref.strip()
    if "@" in text:
        return text.split("@", 1)[0]
    last_slash = text.rfind("/")
    last_colon = text.rfind(":")
    if last_colon > last_slash:
        return text[:last_colon]
    return text


def image_component_name(image_ref: object) -> str:
    repo = image_repo(image_ref)
    return IMAGE_COMPONENTS.get(repo, repo.rsplit("/", 1)[-1] if repo else "unknown")


def release_product_component(release_data: dict) -> str:
    components = release_data.get("components")
    if isinstance(components, dict):
        product_component = components.get("product_component")
        if product_component:
            return str(product_component)
    return image_component_name(release_data.get("product_image"))
