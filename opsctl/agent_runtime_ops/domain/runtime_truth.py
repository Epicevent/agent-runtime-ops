from __future__ import annotations

from ..canonical_recipes import load_canonical_recipe


def local_canonical_recipe_check_from_truth(truth: dict[str, str]) -> tuple[bool, str, str | None]:
    name = truth.get("canonical_recipe_name") or ""
    digest = truth.get("canonical_recipe_digest") or ""
    check_name = "truth_canonical_recipe_digest_matches_local"
    if not name or not digest:
        return False, check_name, "missing"
    try:
        recipe = load_canonical_recipe(name)
    except Exception as exc:
        return False, check_name, str(exc)
    return recipe.digest == digest, check_name, f"image={digest} local={recipe.digest}"
