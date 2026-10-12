"""Author: Musaib Altaf

ONNX GLiNER is opt-in: off unless a directory is given, and a missing file is
an error rather than a quiet fall back to PyTorch.
"""
import pytest

import pii_protect.ner.engine as engine_mod
from pii_protect.ner.engine import GLiNERLayer, NEREngine

pytest.importorskip("gliner")


def test_missing_onnx_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError, match="export_gliner_onnx"):
        GLiNERLayer(onnx_model_dir=tmp_path)


def test_missing_named_file_raises_even_if_dir_has_others(tmp_path):
    (tmp_path / "model.onnx").write_bytes(b"")
    with pytest.raises(FileNotFoundError, match="model_quantized.onnx"):
        GLiNERLayer(onnx_model_dir=tmp_path)


def _record_layer(monkeypatch):
    seen = []

    class Recorder:
        def __init__(self, **kwargs):
            seen.append(kwargs)

        def predict(self, *a, **k):
            return []

        def detect(self, text):
            return []

    monkeypatch.setattr(engine_mod, "GLiNERLayer", Recorder)
    return seen


def test_engine_defaults_to_pytorch(monkeypatch):
    seen = _record_layer(monkeypatch)
    NEREngine(enable_gliner=True)
    assert seen[0]["onnx_model_dir"] is None


def test_engine_passes_onnx_options(monkeypatch, tmp_path):
    seen = _record_layer(monkeypatch)
    NEREngine(
        enable_gliner=True,
        gliner_onnx_dir=tmp_path,
        gliner_onnx_file="model.onnx",
        gliner_onnx_threads=2,
    )
    assert seen[0]["onnx_model_dir"] == tmp_path
    assert seen[0]["onnx_model_file"] == "model.onnx"
    assert seen[0]["onnx_threads"] == 2


def test_domain_only_gliner_load_also_gets_onnx(monkeypatch, tmp_path):
    seen = _record_layer(monkeypatch)
    NEREngine(allow_detect_entities=True, gliner_onnx_dir=tmp_path)
    assert seen[0]["onnx_model_dir"] == tmp_path


class _StubModel:
    """Finds every 'Bob' in the chunk it is given, like a model would."""

    def predict_entities(self, chunk, labels, threshold):
        out, i = [], chunk.find("Bob")
        while i != -1:
            out.append(
                {"start": i, "end": i + 3, "text": "Bob", "label": "person", "score": 0.9}
            )
            i = chunk.find("Bob", i + 1)
        return out


def _layer(workers=1, chunk=50):
    layer = object.__new__(GLiNERLayer)
    layer._model = _StubModel()
    layer._threshold = 0.5
    layer._max_chars = chunk
    layer._workers = workers
    layer._pool = None
    return layer


TEXT = ". ".join(f"sentence {i} mentions Bob here" for i in range(30))


def test_chunk_offsets_map_back_to_the_original_text():
    found = _layer().predict(TEXT, ["person"])
    assert len(found) == 30
    assert all(TEXT[e["start"] : e["end"]] == "Bob" for e in found)


def test_concurrent_chunks_give_identical_results():
    assert _layer(workers=4).predict(TEXT, ["person"]) == _layer().predict(
        TEXT, ["person"]
    )


def test_chunk_size_defaults_depend_on_runtime(tmp_path, monkeypatch):
    import gliner

    monkeypatch.setattr(
        gliner.GLiNER, "from_pretrained", classmethod(lambda cls, *a, **k: _StubModel())
    )
    (tmp_path / "model_quantized.onnx").write_bytes(b"")
    assert GLiNERLayer()._max_chars == GLiNERLayer.CHUNK_CHARS
    assert GLiNERLayer(onnx_model_dir=tmp_path)._max_chars == GLiNERLayer.ONNX_CHUNK_CHARS
    assert GLiNERLayer(onnx_model_dir=tmp_path, max_chars_per_chunk=900)._max_chars == 900
