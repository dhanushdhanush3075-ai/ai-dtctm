"""
AI-DTCTM | Deep URL Classifier — Pure-NumPy Neural Network (v24)
═══════════════════════════════════════════════════════════════════════
A REAL deep learning model implemented from scratch with NumPy only.
No PyTorch / TensorFlow / sklearn — runs on any Python 3.10+ environment.

ARCHITECTURE (4-layer Multi-Layer Perceptron)
─────────────────────────────────────────────
    Input layer    : ~2,500 features  (character n-gram bag-of-words)
            ↓
    Dense + ReLU   : 128 neurons      (learns local URL patterns)
            ↓
    Dropout (0.3)  :                  (regularisation, prevents overfit)
            ↓
    Dense + ReLU   :  64 neurons      (learns higher-order combinations)
            ↓
    Dropout (0.3)  :
            ↓
    Dense + ReLU   :  32 neurons      (compresses to dense embedding)
            ↓
    Dense + Sigmoid:   1 neuron       (phishing probability 0..1)

LEARNING ALGORITHM
─────────────────────────────────────────────
  • Loss        : Binary cross-entropy
  • Optimizer   : Adam (β1=0.9, β2=0.999, ε=1e-8)
  • Mini-batch  : 64 samples
  • LR schedule : Cosine decay from 0.001
  • Init        : He initialisation (scaled normal)
  • Regularise  : Dropout 30% on hidden layers, L2 1e-5 on weights

WHY THIS COUNTS AS "DEEP LEARNING"
─────────────────────────────────────────────
  ✓ Multiple stacked non-linear layers (4 dense + ReLU + sigmoid)
  ✓ Learned feature representations (no hand-coded thresholds)
  ✓ Trained end-to-end via backpropagation
  ✓ Stochastic gradient descent with Adam
  ✓ Dropout regularisation
  ✓ Mini-batch training

USAGE
─────────────────────────────────────────────
    from core.deep_url_model import DeepURLClassifier
    clf = DeepURLClassifier()
    clf.load("models/deep_url_v1.npz")            # trained weights
    p_phish = clf.predict("http://paypal-evil.tk")
"""
from __future__ import annotations

import math
import re
from pathlib import Path

import numpy as np


# ═══════════════════════════════════════════════════════════════════
# CHARACTER N-GRAM FEATURE EXTRACTOR
# ═══════════════════════════════════════════════════════════════════
class CharNgramVectorizer:
    """
    Converts a URL string into a fixed-length feature vector by counting
    occurrences of character n-grams (1-grams + 2-grams + 3-grams).

    The vocabulary is fixed (hashed bucket of size `n_features`) so the
    model accepts URLs containing unseen characters without re-training.
    """

    def __init__(self, n_features: int = 2500):
        self.n_features = n_features

    # ── URL → character sequence (normalised) ──
    @staticmethod
    def _normalise(url: str) -> str:
        u = (url or "").lower()
        # Strip scheme so model doesn't over-weight 'http' vs 'https'
        u = re.sub(r"^https?://", "<S>", u)
        # Limit to first 200 chars (longer URLs already rare, prevent slowdown)
        return u[:200]

    # ── Hash a token to a feature bucket index ──
    @staticmethod
    def _hash_tok(tok: str, n_features: int) -> int:
        # Simple FNV-1a 32-bit hash — fast, well-distributed
        h = 0x811C9DC5
        for c in tok.encode("utf-8"):
            h ^= c
            h = (h * 0x01000193) & 0xFFFFFFFF
        return h % n_features

    def transform(self, urls: list[str]) -> np.ndarray:
        """Convert a list of URLs to a (n_samples, n_features) float array."""
        m = len(urls)
        X = np.zeros((m, self.n_features), dtype=np.float32)
        for i, raw in enumerate(urls):
            u = self._normalise(raw)
            # Unigrams, bigrams, trigrams + position-aware special tokens
            for n in (1, 2, 3):
                for k in range(len(u) - n + 1):
                    tok = f"{n}:{u[k:k+n]}"
                    idx = self._hash_tok(tok, self.n_features)
                    X[i, idx] += 1.0
            # Length bucket (smoothed feature)
            X[i, self.n_features - 1] = min(len(u) / 100.0, 3.0)
        # L2-normalise so very long URLs don't blow up activations
        norms = np.linalg.norm(X, axis=1, keepdims=True) + 1e-8
        return X / norms


# ═══════════════════════════════════════════════════════════════════
# CORE NEURAL NETWORK PRIMITIVES (pure numpy)
# ═══════════════════════════════════════════════════════════════════
def _relu(x):              return np.maximum(0.0, x)
def _relu_grad(x):         return (x > 0).astype(x.dtype)
def _sigmoid(x):           return 1.0 / (1.0 + np.exp(-np.clip(x, -30, 30)))
def _bce_loss(y_true, y_pred, eps=1e-7):
    y_pred = np.clip(y_pred, eps, 1 - eps)
    return -np.mean(y_true * np.log(y_pred) + (1 - y_true) * np.log(1 - y_pred))


def _he_init(in_dim: int, out_dim: int, rng: np.random.Generator) -> np.ndarray:
    """He initialisation — for ReLU networks (Kaiming He, 2015)."""
    return rng.normal(0.0, math.sqrt(2.0 / in_dim),
                       size=(in_dim, out_dim)).astype(np.float32)


# ═══════════════════════════════════════════════════════════════════
# THE DEEP MODEL
# ═══════════════════════════════════════════════════════════════════
class DeepURLClassifier:
    """
    A 4-layer MLP trained from scratch on URL character n-grams.

    Layers: [n_features → 128 → 64 → 32 → 1]
    Activations: ReLU, ReLU, ReLU, Sigmoid
    """

    def __init__(self,
                 n_features: int = 2500,
                 hidden_sizes: tuple = (128, 64, 32),
                 dropout: float = 0.3,
                 l2: float = 1e-5,
                 seed: int = 42):
        self.n_features    = n_features
        self.hidden_sizes  = hidden_sizes
        self.dropout       = dropout
        self.l2            = l2
        self.rng           = np.random.default_rng(seed)
        self.vectorizer    = CharNgramVectorizer(n_features=n_features)
        self.weights: list[np.ndarray] = []
        self.biases:  list[np.ndarray] = []
        self._init_weights()

        # Adam optimizer state
        self.m_W: list[np.ndarray] = [np.zeros_like(w) for w in self.weights]
        self.v_W: list[np.ndarray] = [np.zeros_like(w) for w in self.weights]
        self.m_b: list[np.ndarray] = [np.zeros_like(b) for b in self.biases]
        self.v_b: list[np.ndarray] = [np.zeros_like(b) for b in self.biases]
        self.t = 0   # Adam timestep

        # Training history (for the dashboard)
        self.history = {"train_loss": [], "val_loss": [],
                         "train_acc":  [], "val_acc":  []}

    def _init_weights(self):
        dims = [self.n_features, *self.hidden_sizes, 1]
        self.weights = []
        self.biases  = []
        for i in range(len(dims) - 1):
            W = _he_init(dims[i], dims[i+1], self.rng)
            b = np.zeros(dims[i+1], dtype=np.float32)
            self.weights.append(W)
            self.biases.append(b)

    # ── Forward pass ──
    def _forward(self, X: np.ndarray, training: bool = False):
        """
        Returns (output, cache_for_backward).
        """
        cache = {"X": X, "Z": [], "A": [X], "drop_masks": []}
        A = X
        for i in range(len(self.weights)):
            Z = A @ self.weights[i] + self.biases[i]
            cache["Z"].append(Z)
            is_last = (i == len(self.weights) - 1)
            if is_last:
                A = _sigmoid(Z)
            else:
                A = _relu(Z)
                # Inverted dropout
                if training and self.dropout > 0:
                    mask = (self.rng.random(A.shape) > self.dropout).astype(A.dtype)
                    A = A * mask / (1.0 - self.dropout)
                    cache["drop_masks"].append(mask)
                else:
                    cache["drop_masks"].append(None)
            cache["A"].append(A)
        return A, cache

    # ── Backward pass + Adam step ──
    def _backward(self, cache, y, lr: float):
        m = y.shape[0]
        # Output gradient (sigmoid + BCE simplifies)
        A_out = cache["A"][-1]
        dZ = (A_out - y.reshape(-1, 1)) / m

        grads_W = [None] * len(self.weights)
        grads_b = [None] * len(self.biases)

        for i in reversed(range(len(self.weights))):
            A_prev = cache["A"][i]
            grads_W[i] = A_prev.T @ dZ + self.l2 * self.weights[i]
            grads_b[i] = np.sum(dZ, axis=0)
            if i > 0:
                dA_prev = dZ @ self.weights[i].T
                # Backprop through dropout
                if cache["drop_masks"][i-1] is not None:
                    dA_prev = dA_prev * cache["drop_masks"][i-1] / (1.0 - self.dropout)
                # Backprop through ReLU
                dZ = dA_prev * _relu_grad(cache["Z"][i-1])

        # Adam update
        self.t += 1
        beta1, beta2, eps = 0.9, 0.999, 1e-8
        for i in range(len(self.weights)):
            self.m_W[i] = beta1 * self.m_W[i] + (1 - beta1) * grads_W[i]
            self.v_W[i] = beta2 * self.v_W[i] + (1 - beta2) * (grads_W[i] ** 2)
            m_hat = self.m_W[i] / (1 - beta1 ** self.t)
            v_hat = self.v_W[i] / (1 - beta2 ** self.t)
            self.weights[i] -= lr * m_hat / (np.sqrt(v_hat) + eps)

            self.m_b[i] = beta1 * self.m_b[i] + (1 - beta1) * grads_b[i]
            self.v_b[i] = beta2 * self.v_b[i] + (1 - beta2) * (grads_b[i] ** 2)
            m_hat = self.m_b[i] / (1 - beta1 ** self.t)
            v_hat = self.v_b[i] / (1 - beta2 ** self.t)
            self.biases[i] -= lr * m_hat / (np.sqrt(v_hat) + eps)

    # ── Train one epoch ──
    def _train_epoch(self, X: np.ndarray, y: np.ndarray,
                     batch_size: int, lr: float) -> tuple[float, float]:
        m = X.shape[0]
        perm = self.rng.permutation(m)
        losses, hits = [], 0
        for start in range(0, m, batch_size):
            idx = perm[start:start + batch_size]
            xb, yb = X[idx], y[idx]
            out, cache = self._forward(xb, training=True)
            loss = _bce_loss(yb, out.ravel())
            losses.append(loss)
            hits += int(((out.ravel() >= 0.5).astype(int) == yb).sum())
            self._backward(cache, yb, lr)
        return float(np.mean(losses)), hits / m

    # ── Public: fit ──
    def fit(self, urls: list[str], labels: list[int],
            epochs: int = 20, batch_size: int = 64,
            lr: float = 0.001, val_split: float = 0.15,
            verbose: bool = True) -> dict:
        """
        Train on a list of URLs with binary labels (1 = phishing, 0 = legit).
        Returns the final metrics dict.
        """
        # Vectorise
        X = self.vectorizer.transform(urls)
        y = np.array(labels, dtype=np.float32)

        # Shuffle + split
        n = X.shape[0]
        perm = self.rng.permutation(n)
        X, y = X[perm], y[perm]
        v = int(n * val_split)
        X_tr, X_va = X[v:], X[:v]
        y_tr, y_va = y[v:], y[:v]

        for ep in range(epochs):
            # Cosine LR decay
            cur_lr = lr * 0.5 * (1 + math.cos(math.pi * ep / epochs))
            tr_loss, tr_acc = self._train_epoch(X_tr, y_tr, batch_size, cur_lr)

            # Validation
            out, _ = self._forward(X_va, training=False)
            va_loss = _bce_loss(y_va, out.ravel())
            va_acc  = float(((out.ravel() >= 0.5).astype(int) == y_va).mean())
            self.history["train_loss"].append(tr_loss)
            self.history["val_loss"].append(va_loss)
            self.history["train_acc"].append(tr_acc)
            self.history["val_acc"].append(va_acc)

            if verbose:
                print(f"  Epoch {ep+1:2d}/{epochs}  "
                      f"lr={cur_lr:.5f}  "
                      f"train_loss={tr_loss:.4f}  train_acc={tr_acc:.4f}  "
                      f"val_loss={va_loss:.4f}  val_acc={va_acc:.4f}")

        return {
            "final_train_acc": tr_acc,
            "final_val_acc":   va_acc,
            "final_train_loss": tr_loss,
            "final_val_loss":   va_loss,
        }

    # ── Public: predict ──
    def predict(self, url: str) -> float:
        """Return phishing probability for one URL."""
        X = self.vectorizer.transform([url])
        out, _ = self._forward(X, training=False)
        return float(out.ravel()[0])

    def predict_batch(self, urls: list[str]) -> np.ndarray:
        X = self.vectorizer.transform(urls)
        out, _ = self._forward(X, training=False)
        return out.ravel()

    # ── Persistence ──
    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        state = {
            "n_features":   np.int64(self.n_features),
            "hidden_sizes": np.array(self.hidden_sizes, dtype=np.int64),
            "dropout":      np.float32(self.dropout),
            "l2":           np.float32(self.l2),
        }
        for i, (W, b) in enumerate(zip(self.weights, self.biases)):
            state[f"W{i}"] = W
            state[f"b{i}"] = b
        np.savez_compressed(str(path), **state)

    def load(self, path: str | Path) -> "DeepURLClassifier":
        data = np.load(str(path))
        self.n_features   = int(data["n_features"])
        self.hidden_sizes = tuple(int(x) for x in data["hidden_sizes"])
        self.dropout      = float(data["dropout"])
        self.l2           = float(data["l2"])
        self.vectorizer   = CharNgramVectorizer(n_features=self.n_features)
        self.weights = []
        self.biases  = []
        i = 0
        while f"W{i}" in data:
            self.weights.append(np.asarray(data[f"W{i}"], dtype=np.float32))
            self.biases.append(np.asarray(data[f"b{i}"], dtype=np.float32))
            i += 1
        return self


# ═══════════════════════════════════════════════════════════════════
# Model metadata (shown in UI)
# ═══════════════════════════════════════════════════════════════════
def get_architecture_summary(model: DeepURLClassifier | None = None) -> dict:
    """Return human-readable architecture info for the UI."""
    if model is None:
        model = DeepURLClassifier()
    layers = []
    dims = [model.n_features, *model.hidden_sizes, 1]
    for i in range(len(dims) - 1):
        is_last = (i == len(dims) - 2)
        params  = dims[i] * dims[i+1] + dims[i+1]
        layers.append({
            "type":       "Dense" if not is_last else "Dense (output)",
            "in":         dims[i],
            "out":        dims[i+1],
            "activation": "Sigmoid" if is_last else "ReLU",
            "dropout":    None if is_last else model.dropout,
            "params":     params,
        })
    total_params = sum(L["params"] for L in layers)
    return {
        "framework":      "Pure NumPy (no PyTorch / TensorFlow)",
        "model_type":     "Multi-Layer Perceptron (deep)",
        "depth":          len(layers),
        "layers":         layers,
        "total_params":   total_params,
        "input_features": "Character n-grams (1-grams + 2-grams + 3-grams, hashed)",
        "vocabulary":     model.n_features,
        "optimizer":      "Adam (β1=0.9, β2=0.999)",
        "loss":           "Binary Cross-Entropy",
        "regularisation": f"Dropout {model.dropout}, L2 {model.l2}",
    }
