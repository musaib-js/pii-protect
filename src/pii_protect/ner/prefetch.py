"""
pii_protect.ner.prefetch
=========================
Optional model-prefetch helpers.

pii_protect never downloads model weights on its own — GLiNERLayer and
PrivacyFilterLayer default to offline-safe loading and raise immediately
if weights aren't already cached. These functions exist so that whatever
provisioning step *your* application already uses (a Docker build stage,
a CI step, a one-off setup script — pii_protect has no opinion on which)
can warm that cache explicitly, once, ahead of time — only for the
optional layers you've actually chosen to enable.

Author: Musaib Altaf
"""

from __future__ import annotations

from pathlib import Path

from pii_protect.exceptions import OptionalDependencyMissingError


def prefetch_gliner(model_name: str = "gliner-community/gliner_small-v2.5") -> None:
    """
    Download and cache GLiNER model weights. Requires ``pii-shield[gliner]``.

    Call this explicitly from your own build/provisioning step before
    constructing ``NEREngine(enable_gliner=True)`` — pii_protect never
    calls it for you.
    """
    try:
        from gliner import GLiNER
    except ImportError as exc:
        raise OptionalDependencyMissingError("prefetch_gliner", "gliner", "gliner") from exc

    GLiNER.from_pretrained(model_name)


def prefetch_privacy_filter(model_name: str) -> None:
    """
    Download and cache a transformers token-classification model.
    Requires ``pii-shield[privacy-filter]``.

    Call this explicitly from your own build/provisioning step before
    constructing ``NEREngine(enable_privacy_filter=True, privacy_filter_model=...)``.
    """
    try:
        from transformers import AutoModelForTokenClassification, AutoTokenizer
    except ImportError as exc:
        raise OptionalDependencyMissingError(
            "prefetch_privacy_filter", "privacy-filter", "transformers"
        ) from exc

    AutoTokenizer.from_pretrained(model_name)
    AutoModelForTokenClassification.from_pretrained(model_name)


def export_gliner_onnx(
    out_dir: "str | Path",
    model_name: str = "gliner-community/gliner_small-v2.5",
    quantize: bool = True,
    local_files_only: bool = True,
) -> Path:
    """
    Export GLiNER to ONNX (and, by default, an int8 dynamic-quantised copy)
    for ``NEREngine(gliner_onnx_dir=...)``. Requires ``pii-protect[onnx]``.

    Run this from your own build/provisioning step, once; pii_protect never
    calls it for you. ``model_name`` must already be cached unless
    ``local_files_only=False``. Writes ``model.onnx``, ``model_quantized.onnx``
    (if ``quantize``), plus the config and tokenizer files, to ``out_dir``.
    """
    try:
        from gliner import GLiNER
        import onnxruntime  # noqa: F401
    except ImportError as exc:
        raise OptionalDependencyMissingError(
            "export_gliner_onnx", "onnx", "gliner/onnxruntime"
        ) from exc

    model = GLiNER.from_pretrained(model_name, local_files_only=local_files_only)
    result = model.export_to_onnx(out_dir, quantize=quantize)
    if quantize and not result.get("quantized_path"):
        # gliner downgrades a failed quantisation to a warning; a caller who
        # asked for int8 should not find out at load time.
        raise RuntimeError("ONNX export succeeded but int8 quantisation failed.")
    return Path(out_dir)
