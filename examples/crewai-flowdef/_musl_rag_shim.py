"""Optional sandbox shim: let ``import crewai`` succeed on Alpine/musl.

You only need this on a **musl** host (e.g. Alpine). On a normal glibc host -
CrewAI's supported target - it is a no-op: ``install()`` returns immediately
because ``chromadb`` already imports, and you can delete this file entirely.

Why it exists: crewai's meta-package pins ``lancedb`` + ``chromadb`` (native,
no musllinux wheels) for its RAG / vector-memory subsystem. A CrewAI *Flow*
never invokes vector memory, but ``crewai/__init__.py`` eagerly imports ``Agent``
-> RAG embeddings, so the import fails on musl before any Flow code runs. This
installs a meta-path finder that synthesizes ONLY the ``chromadb``/``lancedb``
module subtree as inert, pydantic-compatible dummy types. Nothing under
``crewai.flow.*`` is touched; the Flow engine you run is the genuine code.

Call :func:`install` before importing crewai.
"""
from __future__ import annotations

import importlib
import importlib.abc
import importlib.machinery
import importlib.util
import sys
import types

STUB_ROOTS = ("chromadb", "lancedb")


def _already_importable() -> bool:
    """True when the real native deps are present (glibc) - then we do nothing."""
    return all(importlib.util.find_spec(r) is not None for r in STUB_ROOTS)


class _Any(type):
    # Stub classes must be subscriptable (``DataLoader[Loadable]``), callable
    # (``Settings()``), and usable as pydantic field annotations.
    def __getitem__(cls, _k):
        return cls

    def __call__(cls, *a, **k):
        return super().__call__()

    def __get_pydantic_core_schema__(cls, _src, _handler):
        from pydantic_core import core_schema

        return core_schema.any_schema()


def _stub_type(name: str, module: str):
    return _Any(name, (), {"__module__": module, "__stub__": True})


class _Loader(importlib.abc.Loader):
    def create_module(self, spec):
        m = types.ModuleType(spec.name)
        m.__path__ = []  # package, so deep imports recurse through us
        m.__spec__ = spec
        m.__getattr__ = lambda attr, _n=spec.name: _stub_type(attr, _n)
        return m

    def exec_module(self, module):
        pass


class _Finder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        if fullname.split(".", 1)[0] in STUB_ROOTS:
            return importlib.machinery.ModuleSpec(fullname, _Loader(), is_package=True)
        return None


_installed = False


def install() -> bool:
    """Install the stub finder if the native deps are missing. Returns True if a
    stub was installed (musl), False if the real deps are present (glibc)."""
    global _installed
    if _installed:
        return True
    if _already_importable():
        return False
    sys.meta_path.insert(0, _Finder())
    _installed = True
    return True
