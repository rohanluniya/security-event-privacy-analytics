"""Generate a CycloneDX 1.5 JSON Software Bill of Materials (SBOM) from the installed locked environment."""

from __future__ import annotations

import importlib.metadata as md
import json
import time
import uuid
from pathlib import Path
from typing import Any


def main() -> int:
    components: list[dict[str, Any]] = []
    for dist in sorted(md.distributions(), key=lambda d: (d.metadata.get("Name") or "").lower()):
        name = dist.metadata.get("Name") or "unknown"
        version = dist.version
        lic = dist.metadata.get("License-Expression") or dist.metadata.get("License") or "UNKNOWN"
        lic_clean = lic.strip().splitlines()[0][:80] if lic else "UNKNOWN"
        components.append(
            {
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name.lower()}@{version}",
                "licenses": [{"license": {"name": lic_clean}}],
            }
        )

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "component": {
                "type": "application",
                "name": "security-event-privacy-analytics",
                "version": "1.0.0",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            },
        },
        "components": components,
    }

    out_path = Path("results/sbom/cyclonedx_sbom.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(sbom, indent=2, sort_keys=True), encoding="utf-8")
    print(f"[generate_sbom] Generated CycloneDX 1.5 SBOM with {len(components)} components -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
