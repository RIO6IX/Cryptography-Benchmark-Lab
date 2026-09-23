"""
Measurement helpers used by the AES benchmark.

Time, CPU and memory are measured in *separate* calls so that the overhead of
one measurement (e.g. tracemalloc hooks) does not distort another.
"""
from __future__ import annotations

import gc
import platform
import statistics
import subprocess
import sys
import time
import tracemalloc

import psutil

MIB = 1024**2
PROC = psutil.Process()


def timed(fn):
    """Wall-clock duration of one call, in seconds.

    Like the standard `timeit` module, garbage collection is disabled during the
    call so an unrelated GC pause is not attributed to AES.
    """
    gc.collect()
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        t0 = time.perf_counter()
        result = fn()
        elapsed = time.perf_counter() - t0
    finally:
        if was_enabled:
            gc.enable()
    return result, elapsed


def peak_traced_mb(fn) -> float:
    """Peak memory allocated through Python's allocator during one call (MB).

    The output buffer of the library call is a Python bytes object, so it is
    counted; OpenSSL's small internal allocations are not.
    """
    gc.collect()
    tracemalloc.start()
    try:
        result = fn()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    del result
    return peak / MIB


# --------------------------------------------------------------- CPU utilisation
# On Windows, process CPU *time* (GetProcessTimes, used by psutil) is sampled
# on the scheduler clock tick and was observed to under-report a fully busy
# thread by 40-70 % on the test laptop (hybrid Intel CPU). Windows also keeps an
# exact per-process CPU *cycle* count (QueryProcessCycleTime), which advances at
# the constant TSC rate only while the process's threads are on a core. CPU
# utilisation is therefore cycles / (TSC rate x wall time). The TSC rate is
# calibrated once as the highest cycles-per-second seen in short busy loops.
if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32")
    _k32.GetCurrentProcess.restype = wintypes.HANDLE
    _k32.QueryProcessCycleTime.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_ulonglong)]

    def _process_cycles() -> int:
        c = ctypes.c_ulonglong()
        _k32.QueryProcessCycleTime(_k32.GetCurrentProcess(), ctypes.byref(c))
        return c.value
else:
    _process_cycles = None

_TSC_HZ: float | None = None


def tsc_hz() -> float | None:
    """Estimated cycle-counter rate (Hz) on Windows, else None. Calibrated once."""
    global _TSC_HZ
    if _process_cycles is None:
        return None
    if _TSC_HZ is None:
        best = 0.0
        for _ in range(10):
            y0, t0 = _process_cycles(), time.perf_counter()
            while time.perf_counter() - t0 < 0.05:
                pass
            best = max(best, (_process_cycles() - y0) / (time.perf_counter() - t0))
        _TSC_HZ = best
    return _TSC_HZ


def cpu_method() -> str:
    if _process_cycles is not None:
        return (f"Windows QueryProcessCycleTime / calibrated TSC rate ({tsc_hz() / 1e9:.3f} GHz); "
                "psutil process CPU time also recorded (*_os_pct columns)")
    return "psutil process CPU time (user + system) / wall time"


def cpu_percent(fn, window: float) -> tuple[float, float]:
    """CPU utilisation of this process while repeatedly calling fn, as % of ONE core.

    Returns (primary, os_time) where primary is cycle-based on Windows and equal
    to os_time elsewhere. OS CPU-time counters are too coarse for a single
    sub-millisecond call, so fn is repeated for at least `window` seconds.
    """
    hz = tsc_hz()
    y0 = _process_cycles() if hz else 0
    c0, t0 = PROC.cpu_times(), time.perf_counter()
    while True:
        fn()
        wall = time.perf_counter() - t0
        if wall >= window:
            break
    c1 = PROC.cpu_times()
    y1 = _process_cycles() if hz else 0
    os_pct = ((c1.user - c0.user) + (c1.system - c0.system)) / wall * 100
    primary = (y1 - y0) / (hz * wall) * 100 if hz else os_pct
    return primary, os_pct


def rss_mb() -> float:
    """Resident set size (Windows: working set) of the whole Python process."""
    return PROC.memory_info().rss / MIB


def summarise(values: list[float]) -> dict:
    """Mean, min, max and sample standard deviation (n - 1 denominator)."""
    return {"mean": statistics.mean(values),
            "min": min(values),
            "max": max(values),
            "std": statistics.stdev(values) if len(values) > 1 else 0.0}


# --------------------------------------------------------------- environment
def _cpu_name() -> str:
    if sys.platform == "win32":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as k:
                return winreg.QueryValueEx(k, "ProcessorNameString")[0].strip()
        except OSError:
            pass
    elif sys.platform.startswith("linux"):
        try:
            for line in open("/proc/cpuinfo"):
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
        except OSError:
            pass
    return platform.processor() or platform.machine()


def _power_state() -> str:
    parts = []
    battery = psutil.sensors_battery() if hasattr(psutil, "sensors_battery") else None
    if battery is not None:
        parts.append("AC power" if battery.power_plugged else f"battery ({battery.percent:.0f}%)")
    else:
        parts.append("no battery reported (desktop / AC)")
    if sys.platform == "win32":
        try:
            out = subprocess.run(["powercfg", "/getactivescheme"], capture_output=True,
                                 text=True, timeout=5).stdout.strip()
            if out:
                parts.append(out)
        except (OSError, subprocess.SubprocessError):
            pass
    return "; ".join(parts)


def environment_info() -> dict:
    import cryptography
    from cryptography.hazmat.backends.openssl.backend import backend
    freq = psutil.cpu_freq()
    clock = time.get_clock_info("perf_counter")
    return {
        "CPU": _cpu_name(),
        "Physical cores": psutil.cpu_count(logical=False),
        "Logical processors": psutil.cpu_count(logical=True),
        "CPU max frequency (MHz)": round(freq.max) if freq else "unknown",
        "RAM (GB)": round(psutil.virtual_memory().total / 1024**3, 2),
        "OS": f"{platform.system()} {platform.release()} (build {platform.version()})",
        "Python": f"{platform.python_implementation()} {platform.python_version()}",
        "cryptography": cryptography.__version__,
        "OpenSSL": backend.openssl_version_text(),
        "psutil": psutil.__version__,
        "perf_counter resolution (s)": clock.resolution,
        "Power": _power_state(),
        "AES-NI": "not detectable from Python - check with Sysinternals Coreinfo (see README)",
    }
