"""
AI-DTCTM | Deep File Classifier — Pure-NumPy Neural Network (v24)
═══════════════════════════════════════════════════════════════════════
ML-based malicious-file detection that works on ANY file type:
  PDFs, Office docs, ZIPs, EXEs, scripts, images, archives, etc.

ARCHITECTURE (4-layer Deep MLP)
─────────────────────────────────────────────
    Input:  32 file features (universal — work on any binary)
        ↓
    Dense + ReLU     :  64 neurons   (file-statistic combinations)
        ↓
    Dropout (0.25)   :
        ↓
    Dense + ReLU     :  32 neurons   (higher-order patterns)
        ↓
    Dropout (0.25)   :
        ↓
    Dense + ReLU     :  16 neurons   (compact malware embedding)
        ↓
    Dense + Sigmoid  :   1 neuron    (malicious probability 0..1)

THE 32 FEATURES (all extractable from raw bytes — type-agnostic)
─────────────────────────────────────────────
  Universal statistics (10)
    1. log_file_size              · file size in log10 bytes
    2. entropy_whole              · Shannon entropy whole file (0..8)
    3. entropy_head_4kb           · entropy of first 4 KB
    4. entropy_tail_4kb           · entropy of last 4 KB
    5. entropy_max_block          · highest 1 KB entropy chunk
    6. entropy_variance           · stddev across 1 KB chunks
    7. printable_ratio            · printable ASCII / total
    8. null_byte_ratio            · 0x00 / total
    9. high_byte_ratio            · bytes > 127 / total
   10. unique_byte_ratio          · distinct byte values / 256

  Byte histogram buckets (8)
   11-18. normalised count in 8 ranges of [0..255]

  Content indicators (6)
   19. url_count_per_kb
   20. ip_count_per_kb
   21. base64_long_blob_count
   22. hex_long_blob_count
   23. suspicious_keyword_count
   24. code_pattern_count

  File-format one-hot (8)
   25. is_pe (.exe/.dll)
   26. is_elf (Linux binary)
   27. is_zip_or_office
   28. is_pdf
   29. is_image
   30. is_text
   31. is_archive
   32. is_unknown
"""
from __future__ import annotations

import math
import re
import struct
from collections import Counter
from pathlib import Path
from typing import Optional

import numpy as np


# ═══════════════════════════════════════════════════════════════════
# FILE FEATURE EXTRACTOR — universal, runs on raw bytes
# ═══════════════════════════════════════════════════════════════════
_SUSPICIOUS_KEYWORDS = (
    b"eval(", b"exec(", b"system(", b"shell_exec", b"passthru",
    b"base64_decode", b"base64.b64decode", b"powershell -e",
    b"frombase64string", b"createobject", b"wscript.shell",
    b"vssadmin", b"bcdedit", b"cipher /w", b"schtasks /create",
    b"net user", b"reg add", b"meterpreter", b"cobaltstrike",
    b"mimikatz", b"sekurlsa", b"pwdump", b"lsadump",
    b"keylogger", b"backdoor", b"rootkit", b"trojan",
    b"ransomware", b"encrypt", b"decrypt_key", b"ransom",
    b".onion", b"stratum+tcp", b"xmrig", b"coinhive",
)

_CODE_PATTERNS = (
    re.compile(rb"<\?php"),
    re.compile(rb"<script\b", re.IGNORECASE),
    re.compile(rb"#!\s*/bin/(?:sh|bash|python|perl)"),
    re.compile(rb"(?:MZ|PK\x03\x04|%PDF-|\x7fELF|\xCA\xFE\xBA\xBE)"),
    re.compile(rb"\b(?:cmd|powershell|wscript|cscript)\.exe", re.IGNORECASE),
)

_URL_RE      = re.compile(rb"https?://[^\s'\"<>]{4,200}")
_IP_RE       = re.compile(rb"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_BASE64_LONG = re.compile(rb"[A-Za-z0-9+/]{60,}=?")
_HEX_LONG    = re.compile(rb"[a-fA-F0-9]{32,}")


_FILE_FORMAT_LABELS = (
    "is_pe", "is_elf", "is_zip_or_office", "is_pdf",
    "is_image", "is_text", "is_archive", "is_unknown",
)


def _shannon_entropy(b: bytes) -> float:
    if not b:
        return 0.0
    cnt = Counter(b)
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in cnt.values())


def _classify_format(raw: bytes, path: str = "") -> str:
    """Return one of the 8 format labels."""
    if not raw:
        return "is_unknown"
    head = raw[:16]
    # Magic-byte detection
    if head.startswith(b"MZ"):
        return "is_pe"
    if head.startswith(b"\x7fELF"):
        return "is_elf"
    if head.startswith(b"%PDF-"):
        return "is_pdf"
    if head.startswith(b"PK\x03\x04"):
        # ZIP — could be docx/xlsx/pptx/jar/apk OR just an archive
        suffix = Path(path).suffix.lower()
        if suffix in (".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm",
                      ".jar", ".apk"):
            return "is_zip_or_office"
        return "is_archive"
    if head.startswith((b"\x89PNG", b"\xFF\xD8\xFF", b"GIF87a", b"GIF89a",
                        b"BM", b"RIFF")):
        return "is_image"
    if head.startswith((b"\x1F\x8B\x08", b"\xFD7zXZ", b"7z\xBC\xAF",
                        b"Rar!\x1A\x07")):
        return "is_archive"
    # Statistical text detection — printable + low non-text ratio
    sample = raw[:2048]
    non_text = sum(1 for c in sample if c < 9 or (13 < c < 32) or c == 127)
    if non_text / max(1, len(sample)) < 0.05:
        return "is_text"
    return "is_unknown"


class FileFeatureExtractor:
    """
    Extract a fixed 32-dim feature vector from any raw file.
    """

    FEATURE_NAMES = (
        # 10 universal statistics
        "log_file_size", "entropy_whole", "entropy_head_4kb", "entropy_tail_4kb",
        "entropy_max_block", "entropy_variance",
        "printable_ratio", "null_byte_ratio", "high_byte_ratio", "unique_byte_ratio",
        # 8 byte histogram buckets
        "byte_hist_0_31", "byte_hist_32_47", "byte_hist_48_57", "byte_hist_58_64",
        "byte_hist_65_122", "byte_hist_123_127", "byte_hist_128_191", "byte_hist_192_255",
        # 6 content indicators
        "url_count_per_kb", "ip_count_per_kb",
        "base64_long_count", "hex_long_count",
        "suspicious_keyword_count", "code_pattern_count",
        # 8 file-format one-hot
        *_FILE_FORMAT_LABELS,
    )

    N_FEATURES = 32

    @classmethod
    def extract_from_bytes(cls, raw: bytes, path: str = "") -> np.ndarray:
        """Return a 32-dim float32 vector."""
        n = len(raw) or 1
        kb = max(1, n / 1024)

        # ── 1-10: universal stats ──
        log_size = math.log10(n)
        ent_whole = _shannon_entropy(raw)
        ent_head  = _shannon_entropy(raw[:4096]) if n >= 64 else ent_whole
        ent_tail  = _shannon_entropy(raw[-4096:]) if n >= 4096 else ent_whole

        # Chunk entropy: 1KB blocks
        chunk_entropies = []
        for i in range(0, n, 1024):
            chunk = raw[i:i + 1024]
            if len(chunk) > 64:
                chunk_entropies.append(_shannon_entropy(chunk))
        ent_max_block = max(chunk_entropies) if chunk_entropies else ent_whole
        ent_variance  = float(np.std(chunk_entropies)) if len(chunk_entropies) > 1 else 0.0

        printable_n = sum(1 for c in raw if 32 <= c < 127 or c in (9, 10, 13))
        null_n      = raw.count(0)
        high_n      = sum(1 for c in raw if c > 127)
        unique_n    = len(set(raw)) if raw else 0

        printable_ratio = printable_n / n
        null_ratio      = null_n / n
        high_ratio      = high_n / n
        unique_ratio    = unique_n / 256.0

        # ── 11-18: byte histogram (8 buckets) ──
        cnt = Counter(raw)
        buckets = [0] * 8
        for byte_val, c in cnt.items():
            if byte_val < 32:           buckets[0] += c
            elif byte_val < 48:         buckets[1] += c
            elif byte_val < 58:         buckets[2] += c
            elif byte_val < 65:         buckets[3] += c
            elif byte_val < 123:        buckets[4] += c
            elif byte_val < 128:        buckets[5] += c
            elif byte_val < 192:        buckets[6] += c
            else:                       buckets[7] += c
        buckets = [b / n for b in buckets]

        # ── 19-24: content indicators ──
        url_n     = len(_URL_RE.findall(raw[:200_000]))
        ip_n      = len(_IP_RE.findall(raw[:200_000]))
        b64_n     = len(_BASE64_LONG.findall(raw[:200_000]))
        hex_n     = len(_HEX_LONG.findall(raw[:200_000]))
        suspicious = sum(1 for kw in _SUSPICIOUS_KEYWORDS if kw in raw[:500_000])
        code_pat  = sum(1 for p in _CODE_PATTERNS if p.search(raw[:200_000]))

        # ── 25-32: file-format one-hot ──
        fmt = _classify_format(raw, path)
        one_hot = [1.0 if lbl == fmt else 0.0 for lbl in _FILE_FORMAT_LABELS]

        vec = [
            log_size, ent_whole, ent_head, ent_tail,
            ent_max_block, ent_variance,
            printable_ratio, null_ratio, high_ratio, unique_ratio,
            *buckets,
            url_n / kb, ip_n / kb, b64_n, hex_n,
            float(suspicious), float(code_pat),
            *one_hot,
        ]
        return np.array(vec, dtype=np.float32)

    @classmethod
    def extract_from_file(cls, filepath: str, max_bytes: int = 5_000_000) -> np.ndarray:
        p = Path(filepath)
        raw = p.read_bytes()[:max_bytes]
        return cls.extract_from_bytes(raw, path=str(filepath))


# ═══════════════════════════════════════════════════════════════════
# DEEP NEURAL NETWORK (same Adam + dropout backbone, smaller width)
# ═══════════════════════════════════════════════════════════════════
def _relu(x):        return np.maximum(0.0, x)
def _relu_grad(x):   return (x > 0).astype(x.dtype)
def _sigmoid(x):     return 1.0 / (1.0 + np.exp(-np.clip(x, -30, 30)))
def _bce_loss(y_true, y_pred, eps=1e-7):
    y_pred = np.clip(y_pred, eps, 1 - eps)
    return -np.mean(y_true * np.log(y_pred) + (1 - y_true) * np.log(1 - y_pred))


def _he_init(in_dim, out_dim, rng):
    return rng.normal(0.0, math.sqrt(2.0 / in_dim),
                       size=(in_dim, out_dim)).astype(np.float32)


class DeepFileClassifier:
    """4-layer MLP trained on the 32 file features."""

    N_FEATURES = FileFeatureExtractor.N_FEATURES

    def __init__(self,
                 hidden_sizes: tuple = (64, 32, 16),
                 dropout: float = 0.25,
                 l2: float = 1e-5,
                 seed: int = 42):
        self.hidden_sizes = hidden_sizes
        self.dropout      = dropout
        self.l2           = l2
        self.rng          = np.random.default_rng(seed)
        self.extractor    = FileFeatureExtractor()
        # Feature normalisation stats (filled during training)
        self.feat_mean: Optional[np.ndarray] = None
        self.feat_std:  Optional[np.ndarray] = None
        self._init_weights()
        self.m_W = [np.zeros_like(w) for w in self.weights]
        self.v_W = [np.zeros_like(w) for w in self.weights]
        self.m_b = [np.zeros_like(b) for b in self.biases]
        self.v_b = [np.zeros_like(b) for b in self.biases]
        self.t = 0
        self.history = {"train_loss": [], "val_loss": [],
                         "train_acc": [], "val_acc": []}

    def _init_weights(self):
        dims = [self.N_FEATURES, *self.hidden_sizes, 1]
        self.weights = []
        self.biases  = []
        for i in range(len(dims) - 1):
            self.weights.append(_he_init(dims[i], dims[i+1], self.rng))
            self.biases.append(np.zeros(dims[i+1], dtype=np.float32))

    def _normalise(self, X: np.ndarray) -> np.ndarray:
        if self.feat_mean is None or self.feat_std is None:
            return X
        return (X - self.feat_mean) / (self.feat_std + 1e-8)

    def _forward(self, X, training=False):
        cache = {"A": [X], "Z": [], "drop_masks": []}
        A = X
        for i in range(len(self.weights)):
            Z = A @ self.weights[i] + self.biases[i]
            cache["Z"].append(Z)
            is_last = (i == len(self.weights) - 1)
            if is_last:
                A = _sigmoid(Z)
            else:
                A = _relu(Z)
                if training and self.dropout > 0:
                    mask = (self.rng.random(A.shape) > self.dropout).astype(A.dtype)
                    A = A * mask / (1.0 - self.dropout)
                    cache["drop_masks"].append(mask)
                else:
                    cache["drop_masks"].append(None)
            cache["A"].append(A)
        return A, cache

    def _backward(self, cache, y, lr):
        m = y.shape[0]
        A_out = cache["A"][-1]
        dZ = (A_out - y.reshape(-1, 1)) / m
        for i in reversed(range(len(self.weights))):
            A_prev = cache["A"][i]
            gW = A_prev.T @ dZ + self.l2 * self.weights[i]
            gb = np.sum(dZ, axis=0)
            if i > 0:
                dA_prev = dZ @ self.weights[i].T
                if cache["drop_masks"][i-1] is not None:
                    dA_prev = dA_prev * cache["drop_masks"][i-1] / (1.0 - self.dropout)
                dZ = dA_prev * _relu_grad(cache["Z"][i-1])
            # Adam
            self.t += 1
            b1, b2, eps = 0.9, 0.999, 1e-8
            self.m_W[i] = b1 * self.m_W[i] + (1 - b1) * gW
            self.v_W[i] = b2 * self.v_W[i] + (1 - b2) * (gW ** 2)
            self.weights[i] -= lr * (self.m_W[i] / (1 - b1 ** self.t)) / (
                np.sqrt(self.v_W[i] / (1 - b2 ** self.t)) + eps)
            self.m_b[i] = b1 * self.m_b[i] + (1 - b1) * gb
            self.v_b[i] = b2 * self.v_b[i] + (1 - b2) * (gb ** 2)
            self.biases[i] -= lr * (self.m_b[i] / (1 - b1 ** self.t)) / (
                np.sqrt(self.v_b[i] / (1 - b2 ** self.t)) + eps)

    def fit(self, X_raw: np.ndarray, y: np.ndarray,
            epochs: int = 30, batch_size: int = 32, lr: float = 0.001,
            val_split: float = 0.15, verbose: bool = True) -> dict:
        # Compute normalisation stats from training subset
        self.feat_mean = X_raw.mean(axis=0).astype(np.float32)
        self.feat_std  = X_raw.std(axis=0).astype(np.float32)
        X = self._normalise(X_raw)

        n = X.shape[0]
        perm = self.rng.permutation(n)
        X, y = X[perm], y[perm]
        v = int(n * val_split)
        X_tr, X_va = X[v:], X[:v]
        y_tr, y_va = y[v:], y[:v]

        for ep in range(epochs):
            cur_lr = lr * 0.5 * (1 + math.cos(math.pi * ep / epochs))
            m = X_tr.shape[0]
            order = self.rng.permutation(m)
            tr_losses, tr_hits = [], 0
            for start in range(0, m, batch_size):
                idx = order[start:start + batch_size]
                xb, yb = X_tr[idx], y_tr[idx]
                out, cache = self._forward(xb, training=True)
                tr_losses.append(_bce_loss(yb, out.ravel()))
                tr_hits += int(((out.ravel() >= 0.5).astype(int) == yb).sum())
                self._backward(cache, yb, cur_lr)
            tr_loss = float(np.mean(tr_losses))
            tr_acc  = tr_hits / m
            out_va, _ = self._forward(X_va, training=False)
            va_loss = _bce_loss(y_va, out_va.ravel())
            va_acc  = float(((out_va.ravel() >= 0.5).astype(int) == y_va).mean())
            self.history["train_loss"].append(tr_loss)
            self.history["val_loss"].append(va_loss)
            self.history["train_acc"].append(tr_acc)
            self.history["val_acc"].append(va_acc)
            if verbose:
                print(f"  Epoch {ep+1:2d}/{epochs}  lr={cur_lr:.5f}  "
                      f"train_loss={tr_loss:.4f}  train_acc={tr_acc:.4f}  "
                      f"val_loss={va_loss:.4f}  val_acc={va_acc:.4f}")
        return {
            "final_train_acc": tr_acc, "final_val_acc": va_acc,
            "final_train_loss": tr_loss, "final_val_loss": va_loss,
        }

    def predict_file(self, filepath: str) -> dict:
        """Return malicious probability for one file path."""
        x = self.extractor.extract_from_file(filepath).reshape(1, -1)
        x = self._normalise(x)
        out, _ = self._forward(x, training=False)
        p_mal = float(out.ravel()[0])
        return {
            "p_malicious": p_mal,
            "p_benign":    1.0 - p_mal,
            "label":       "malicious" if p_mal >= 0.5 else "benign",
            "confidence":  max(p_mal, 1 - p_mal),
            "features":    {name: float(val) for name, val in
                            zip(FileFeatureExtractor.FEATURE_NAMES,
                                self.extractor.extract_from_file(filepath))},
        }

    def predict_bytes(self, raw: bytes, path: str = "") -> dict:
        x = self.extractor.extract_from_bytes(raw, path=path).reshape(1, -1)
        x_norm = self._normalise(x)
        out, _ = self._forward(x_norm, training=False)
        p_mal = float(out.ravel()[0])
        return {
            "p_malicious": p_mal,
            "p_benign":    1.0 - p_mal,
            "label":       "malicious" if p_mal >= 0.5 else "benign",
            "confidence":  max(p_mal, 1 - p_mal),
            "features":    {name: float(val) for name, val in
                            zip(FileFeatureExtractor.FEATURE_NAMES, x[0])},
        }

    def save(self, path: str | Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        state = {
            "hidden_sizes": np.array(self.hidden_sizes, dtype=np.int64),
            "dropout":      np.float32(self.dropout),
            "l2":           np.float32(self.l2),
            "feat_mean":    self.feat_mean,
            "feat_std":     self.feat_std,
        }
        for i, (W, b) in enumerate(zip(self.weights, self.biases)):
            state[f"W{i}"] = W
            state[f"b{i}"] = b
        np.savez_compressed(str(path), **state)

    def load(self, path: str | Path):
        data = np.load(str(path))
        self.hidden_sizes = tuple(int(x) for x in data["hidden_sizes"])
        self.dropout      = float(data["dropout"])
        self.l2           = float(data["l2"])
        self.feat_mean    = np.asarray(data["feat_mean"], dtype=np.float32)
        self.feat_std     = np.asarray(data["feat_std"], dtype=np.float32)
        self.weights = []
        self.biases  = []
        i = 0
        while f"W{i}" in data:
            self.weights.append(np.asarray(data[f"W{i}"], dtype=np.float32))
            self.biases.append(np.asarray(data[f"b{i}"], dtype=np.float32))
            i += 1
        return self


def get_architecture_summary(model: Optional[DeepFileClassifier] = None) -> dict:
    if model is None:
        model = DeepFileClassifier()
    dims = [model.N_FEATURES, *model.hidden_sizes, 1]
    layers = []
    for i in range(len(dims) - 1):
        is_last = (i == len(dims) - 2)
        params  = dims[i] * dims[i+1] + dims[i+1]
        layers.append({
            "type":       "Dense (output)" if is_last else "Dense",
            "in":         dims[i],
            "out":        dims[i+1],
            "activation": "Sigmoid" if is_last else "ReLU",
            "dropout":    None if is_last else model.dropout,
            "params":     params,
        })
    return {
        "framework":      "Pure NumPy (no PyTorch / TensorFlow)",
        "model_type":     "Multi-Layer Perceptron (file features)",
        "depth":          len(layers),
        "layers":         layers,
        "total_params":   sum(L["params"] for L in layers),
        "input_features": "32 universal file features (type-agnostic)",
        "optimizer":      "Adam (β1=0.9, β2=0.999)",
        "loss":           "Binary Cross-Entropy",
        "regularisation": f"Dropout {model.dropout}, L2 {model.l2}",
    }
