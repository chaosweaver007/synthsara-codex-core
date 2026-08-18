#!/usr/bin/env python3
"""Validate the Sonic Codex registry, node schema, and constellation invariants."""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

try:
    from jsonschema import Draft202012Validator
except ImportError as exc:  # pragma: no cover - developer setup failure
    raise SystemExit(
        "Missing validation dependency. Run: python -m pip install -r requirements-dev.txt"
    ) from exc


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "sonic" / "schema" / "sonic-codex-node-v0.1.schema.json"
MANIFEST_PATH = REPO_ROOT / "sonic" / "registry-v0.1.json"
CONSTELLATION_DIR = REPO_ROOT / "sonic" / "constellations" / "after-the-hum"
NODE_ID_RE = re.compile(r"^SC-[0-9]{3}$")
ANCHOR_RE = re.compile(r"^(?:UDS|FIRST_LAW)\.[A-Z0-9_]+$")
TARGET_RE = re.compile(r"^(?:Genesis|NodeZero)\.[A-Za-z0-9_.]+$")
EXPECTED_FIRST_NINE = [f"SC-{index:03d}" for index in range(10)]


def load_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError as exc:
        raise ValueError(f"Missing required file: {path.relative_to(REPO_ROOT)}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Malformed JSON in {path.relative_to(REPO_ROOT)}: line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc


def format_schema_error(node_id: str, error: Any) -> str:
    location = ".".join(str(part) for part in error.absolute_path) or "<root>"
    return f"{node_id}: schema violation at {location}: {error.message}"


def validate_registry() -> list[str]:
    errors: list[str] = []

    try:
        schema = load_json(SCHEMA_PATH)
        manifest = load_json(MANIFEST_PATH)
    except ValueError as exc:
        return [str(exc)]

    try:
        Draft202012Validator.check_schema(schema)
    except Exception as exc:  # jsonschema raises SchemaError; keep output stable for CLI use
        return [f"Invalid JSON Schema: {exc}"]

    validator = Draft202012Validator(schema)

    if manifest.get("registry_id") != "SONIC-CODEX":
        errors.append("Manifest registry_id must equal SONIC-CODEX.")

    if manifest.get("constellation") != "AFTER_THE_HUM_FIRST_NINE":
        errors.append("Manifest constellation must equal AFTER_THE_HUM_FIRST_NINE.")

    manifest_version = manifest.get("version")
    if not isinstance(manifest_version, str) or not manifest_version.strip():
        errors.append("Manifest version must be a non-empty string.")

    manifest_nodes = manifest.get("nodes")
    if not isinstance(manifest_nodes, list):
        return errors + ["Manifest nodes must be an array."]

    if manifest_nodes != EXPECTED_FIRST_NINE:
        errors.append(
            "Manifest nodes must contain SC-000 through SC-009 exactly once and in canonical order."
        )

    if len(manifest_nodes) != len(set(manifest_nodes)):
        errors.append("Manifest contains duplicate node IDs.")

    for node_id in manifest_nodes:
        if not isinstance(node_id, str) or not NODE_ID_RE.fullmatch(node_id):
            errors.append(f"Manifest contains invalid node ID: {node_id!r}")

    node_files = sorted(CONSTELLATION_DIR.glob("SC-*.json")) if CONSTELLATION_DIR.exists() else []
    file_node_ids = [path.stem for path in node_files]

    missing_files = sorted(set(manifest_nodes) - set(file_node_ids))
    extra_files = sorted(set(file_node_ids) - set(manifest_nodes))
    if missing_files:
        errors.append(f"Manifest nodes missing files: {', '.join(missing_files)}")
    if extra_files:
        errors.append(f"Constellation contains unregistered node files: {', '.join(extra_files)}")

    nodes: dict[str, dict[str, Any]] = {}
    global_reason_codes: dict[str, list[str]] = defaultdict(list)

    for path in node_files:
        try:
            node = load_json(path)
        except ValueError as exc:
            errors.append(str(exc))
            continue

        if not isinstance(node, dict):
            errors.append(f"{path.name}: node document must be a JSON object.")
            continue

        node_id = node.get("node_id", path.stem)
        schema_errors = sorted(validator.iter_errors(node), key=lambda error: list(error.absolute_path))
        errors.extend(format_schema_error(str(node_id), error) for error in schema_errors)

        if node_id != path.stem:
            errors.append(f"{path.name}: node_id {node_id!r} must match filename stem {path.stem!r}.")

        if node_id in nodes:
            errors.append(f"Duplicate node document for {node_id}.")
            continue
        if isinstance(node_id, str):
            nodes[node_id] = node

        if node.get("registry_version") != manifest_version:
            errors.append(
                f"{node_id}: registry_version {node.get('registry_version')!r} does not match manifest version {manifest_version!r}."
            )

        uds_mapping = node.get("uds_mapping", {})
        if uds_mapping.get("authority") != "INTERPRETIVE_ONLY":
            errors.append(f"{node_id}: First Nine authority must remain INTERPRETIVE_ONLY.")
        if uds_mapping.get("sovereignty_exit_preserved") is not True:
            errors.append(f"{node_id}: sovereignty_exit_preserved must be true.")

        anchors = uds_mapping.get("anchors", [])
        if not anchors:
            errors.append(f"{node_id}: at least one UDS/First Law anchor is required.")
        for anchor in anchors:
            if not isinstance(anchor, str) or not ANCHOR_RE.fullmatch(anchor):
                errors.append(f"{node_id}: invalid constitutional anchor {anchor!r}.")

        recognition = node.get("recognition", {})
        themes = recognition.get("themes", [])
        reason_codes = recognition.get("reason_codes", [])
        if not themes:
            errors.append(f"{node_id}: recognition.themes must not be empty.")
        if not reason_codes:
            errors.append(f"{node_id}: recognition.reason_codes must not be empty.")
        if len(themes) != len(set(themes)):
            errors.append(f"{node_id}: recognition.themes contains duplicates.")
        if len(reason_codes) != len(set(reason_codes)):
            errors.append(f"{node_id}: recognition.reason_codes contains duplicates.")
        for reason_code in reason_codes:
            global_reason_codes[str(reason_code)].append(str(node_id))

        claims = node.get("claims", [])
        if not claims:
            errors.append(f"{node_id}: claims must not be empty.")
        for index, claim in enumerate(claims):
            if claim.get("classification") == "EMPIRICAL_EVIDENCE" and not claim.get("evidence_refs"):
                errors.append(
                    f"{node_id}: claims[{index}] classified EMPIRICAL_EVIDENCE must include evidence_refs."
                )

        technical_targets = node.get("technical_targets", [])
        if not technical_targets:
            errors.append(f"{node_id}: technical_targets must not be empty.")
        for target in technical_targets:
            if not isinstance(target, str) or not TARGET_RE.fullmatch(target):
                errors.append(f"{node_id}: invalid technical target {target!r}.")

        related_nodes = node.get("related_nodes", [])
        if len(related_nodes) != len(set(related_nodes)):
            errors.append(f"{node_id}: related_nodes contains duplicates.")
        if node_id in related_nodes:
            errors.append(f"{node_id}: related_nodes may not contain the node itself.")

    for reason_code, owners in sorted(global_reason_codes.items()):
        if len(owners) > 1:
            errors.append(
                f"Reason code {reason_code!r} is ambiguous across nodes: {', '.join(sorted(owners))}."
            )

    known_node_ids = set(nodes)
    for node_id, node in sorted(nodes.items()):
        for related_id in node.get("related_nodes", []):
            if related_id not in known_node_ids:
                errors.append(f"{node_id}: related node {related_id!r} does not exist in the registry.")
                continue
            reverse_links = nodes[related_id].get("related_nodes", [])
            if node_id not in reverse_links:
                errors.append(
                    f"{node_id}: relation to {related_id} is not reciprocal; add {node_id} to {related_id}.related_nodes."
                )

    return errors


def main() -> int:
    errors = validate_registry()
    if errors:
        print(f"[FAIL] Sonic Codex registry validation found {len(errors)} issue(s):")
        for error in errors:
            print(f"  - {error}")
        return 1

    print(
        "[PASS] SONIC-CODEX v0.1.0 validated: Draft 2020-12 schema, "
        "SC-000..SC-009 manifest integrity, reciprocal relations, epistemic boundaries, "
        "and sovereignty constraints are clean."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
