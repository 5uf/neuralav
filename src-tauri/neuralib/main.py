import binascii
import os
from functools import lru_cache

import numpy as np
import onnxruntime as ort
from transformers import AutoTokenizer

LABELS = ["Virus", "Worm", "Trojan", "CryptoJacker", "Spyware", "Ransomware", "Adware", "Botnet", "Rootkit"]
MAX_BYTES = 2048


def hexdump(file):
    with open(file, 'rb') as f:
        data = f.read(MAX_BYTES)
    return binascii.hexlify(data).decode('utf-16')


@lru_cache(maxsize=None)
def _load(name):
    path = os.path.join(os.environ.get("NEURALAV_MODELS", "models"), name)
    sess = ort.InferenceSession(os.path.join(path, "model.onnx"), providers=["CPUExecutionProvider"])
    return sess, AutoTokenizer.from_pretrained(path)


def _logits(file, name):
    sess, tokenizer = _load(name)
    tokens = tokenizer(hexdump(file), return_tensors='np', truncation=True, max_length=512)
    wanted = {i.name for i in sess.get_inputs()}
    feed = {k: v for k, v in tokens.items() if k in wanted}
    return sess.run(None, feed)[0][0]


def identify(file):
    logits = _logits(file, "Identifier")
    # ponytail: label order (index 1 = Malicious) is unverified against the trained model
    return "Malicious" if int(np.argmax(logits)) == 1 else "Harmless"


def classify(file):
    logits = _logits(file, "Classifier")
    e = np.exp(logits - np.max(logits))
    probs = e / e.sum()
    i = int(np.argmax(probs))
    # "label,accuracy,text" as parsed by Dashboard.jsx; no field contains a comma
    return "%s,%.2f,%s" % (LABELS[i], probs[i] * 100, "Detected as %s" % LABELS[i])
