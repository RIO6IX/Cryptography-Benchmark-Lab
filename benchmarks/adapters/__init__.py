"""
Algorithm adapters for the common benchmark (benchmarks/benchmark_all.py).

Each adapter is a thin wrapper around one group member's module in src/.
build_adapters() creates the requested adapters, runs their self-checks and
skips (with a clear warning) any that are unavailable - e.g. RSA before the RSA
module exists - so the rest of the pipeline still runs.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from benchmarks.adapters.aes_adapter import AESAdapter
from benchmarks.adapters.hybrid_adapter import HybridAdapter
from benchmarks.adapters.rsa_adapter import RSAAdapter
from benchmarks.adapters.sha256_adapter import SHA256Adapter
from benchmarks.framework import AlgorithmAdapter

ADAPTER_NAMES = ("aes", "sha256", "rsa", "hybrid")
REQUIRED = ("aes", "sha256")        # implemented in main; a failing self-check aborts the run


@dataclass
class AdapterSet:
    adapters: list[AlgorithmAdapter] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)      # name -> reason
    checks: dict[str, str] = field(default_factory=dict)       # name -> self-check result
    fatal: list[str] = field(default_factory=list)             # required adapters whose self-check failed

    @property
    def warnings(self) -> list[str]:
        return [f"WARNING: {name} skipped - {reason}" for name, reason in self.skipped.items()]


def build_adapters(names, rsa: RSAAdapter | None = None) -> AdapterSet:
    """Create adapters in the order given. `rsa` can be injected (tests, or a custom RSA module)."""
    result = AdapterSet()
    if rsa is None and {"rsa", "hybrid"} & set(names):
        rsa = RSAAdapter()
    if rsa is not None and rsa.available:
        try:
            result.checks["rsa"] = rsa.self_check()
        except Exception as e:
            rsa.unavailable_reason = f"{rsa.module_name} failed the adapter self-check: {type(e).__name__}: {e}"

    for name in names:
        if name == "aes":
            adapter = AESAdapter()
        elif name == "sha256":
            adapter = SHA256Adapter()
        elif name == "rsa":
            adapter = rsa
        elif name == "hybrid":
            adapter = HybridAdapter(rsa)
        else:
            raise ValueError(f"unknown algorithm {name!r}; choose from {ADAPTER_NAMES}")
        if not adapter.available:
            result.skipped[name] = adapter.unavailable_reason
            continue
        if name not in result.checks:
            try:
                result.checks[name] = adapter.self_check()
            except Exception as e:
                result.skipped[name] = f"self-check failed: {type(e).__name__}: {e}"
                if name in REQUIRED:
                    result.fatal.append(name)
                continue
        result.adapters.append(adapter)
    return result


__all__ = ["ADAPTER_NAMES", "AdapterSet", "AESAdapter", "HybridAdapter", "RSAAdapter", "SHA256Adapter",
           "build_adapters"]
