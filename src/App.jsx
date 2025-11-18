
// src/App.jsx
import React, { useState } from "react";

// ==================== GLOBAL HELPERS & CONFIG ====================

const API_BASE = "http://localhost:8080/api";
const SESSION_ID_KEY = "rsa_demo_session_id";

function getSessionId() {
  if (typeof window === "undefined") return "rsa-demo-static-session";
  let sid = window.localStorage.getItem(SESSION_ID_KEY);
  if (!sid) {
    if (window.crypto && window.crypto.randomUUID) {
      sid = window.crypto.randomUUID();
    } else {
      sid = "rsa-" + Math.random().toString(36).slice(2) + Date.now();
    }
    window.localStorage.setItem(SESSION_ID_KEY, sid);
  }
  return sid;
}

async function apiPost(path, body) {
  const session_id = getSessionId();
  const payload = { ...body, session_id };

  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  const text = await res.text();
  let data = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = {};
  }

  if (!res.ok || data.error) {
    const msg =
      (data && data.error) || `HTTP ${res.status}` || "Unknown server error";
    throw new Error(msg);
  }
  return data;
}

function quickHash(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = (h * 31 + str.charCodeAt(i)) | 0;
  }
  return h;
}

function shortStatus(err) {
  if (!err) return "";
  if (typeof err === "string") return err;
  if (err.message) return err.message;
  return String(err);
}

function downloadJson(filename, obj) {
  const blob = new Blob([JSON.stringify(obj, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// ==================== AES PANEL (CLASSMATE STYLE) ====================

function AESPanel() {
  const [key, setKey] = useState("");
  const [keySize, setKeySize] = useState(128);
  const [mode, setMode] = useState("encrypt"); // "encrypt" | "decrypt"
  const [input, setInput] = useState("");
  const [output, setOutput] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleProcess() {
    setError("");
    setOutput("");

    if (!input.trim()) {
      setError("Please enter text to process.");
      return;
    }

    if (!key.trim()) {
      setError("Please enter an AES key.");
      return;
    }

    setLoading(true);
    try {
      // TODO: replace this placeholder with real AES Flask calls.
      // Example:
      // const resp = await fetch(`${API_BASE}/aes-${mode}`, { ... });
      // const data = await resp.json();
      // setOutput(data.output);

      setOutput(
        `AES ${mode.toUpperCase()} placeholder.\n` +
          "UI is ready; connect this to your Flask AES endpoint."
      );
    } catch (err) {
      setError(
        `Error: ${err.message}. Make sure the Flask API is running on port 8080.`
      );
    } finally {
      setLoading(false);
    }
  }

  function handleClear() {
    setInput("");
    setOutput("");
    setError("");
  }

  return (
    <div
      style={{
        maxWidth: "900px",
        margin: "0 auto",
        border: "1px solid #ddd",
        borderRadius: "6px",
        backgroundColor: "#ffffff",
        boxShadow: "0 2px 6px rgba(0,0,0,0.08)",
        fontFamily: "Segoe UI, system-ui, -apple-system, BlinkMacSystemFont",
        padding: "1rem",
      }}
    >
      <h2 style={{ marginTop: 0, marginBottom: "0.25rem" }}>
        AES Cryptography Demo (Classmate)
      </h2>
      <p style={{ marginTop: 0, fontSize: "0.85rem", color: "#555" }}>
        Encrypt and decrypt using AES with a custom key (same style as your
        classmate&apos;s UI).
      </p>

      {/* Key size */}
      <div style={{ marginBottom: "0.6rem" }}>
        <label
          style={{ display: "block", fontSize: "0.9rem", marginBottom: "0.25rem" }}
        >
          Key Size
        </label>
        <select
          value={keySize}
          onChange={(e) => setKeySize(parseInt(e.target.value, 10))}
          style={{
            width: "100%",
            maxWidth: "260px",
            padding: "0.35rem 0.5rem",
            fontSize: "0.9rem",
            borderRadius: "4px",
            border: "1px solid #ccc",
          }}
        >
          <option value={128}>AES-128 (16 bytes)</option>
          <option value={192}>AES-192 (24 bytes)</option>
          <option value={256}>AES-256 (32 bytes)</option>
        </select>
      </div>

      {/* Key */}
      <div style={{ marginBottom: "0.6rem" }}>
        <label
          style={{ display: "block", fontSize: "0.9rem", marginBottom: "0.25rem" }}
        >
          Key
        </label>
        <textarea
          rows={1}
          value={key}
          onChange={(e) => setKey(e.target.value)}
          placeholder="Enter encryption key"
          style={{
            width: "100%",
            padding: "0.35rem 0.5rem",
            fontSize: "0.9rem",
            fontFamily: "Consolas, monospace",
            borderRadius: "4px",
            border: "1px solid #ccc",
            resize: "none",
          }}
        />
      </div>

      {/* Mode buttons */}
      <div style={{ marginBottom: "0.6rem" }}>
        <span style={{ fontSize: "0.9rem", marginRight: "0.5rem" }}>Mode:</span>
        <button
          onClick={() => setMode("encrypt")}
          style={{
            padding: "0.3rem 0.9rem",
            marginRight: "0.4rem",
            borderRadius: "4px",
            border: mode === "encrypt" ? "2px solid #0d6efd" : "1px solid #ccc",
            backgroundColor: mode === "encrypt" ? "#ffe7e7ff" : "#f8f9fa",
            cursor: "pointer",
            fontSize: "0.85rem",
          }}
        >
          Encrypt
        </button>
        <button
          onClick={() => setMode("decrypt")}
          style={{
            padding: "0.3rem 0.9rem",
            borderRadius: "4px",
            border: mode === "decrypt" ? "2px solid #0d6efd" : "1px solid #ccc",
            backgroundColor: mode === "decrypt" ? "#e7f1ff" : "#f8f9fa",
            cursor: "pointer",
            fontSize: "0.85rem",
          }}
        >
          Decrypt
        </button>
      </div>

      {/* Input */}
      <div style={{ marginBottom: "0.6rem" }}>
        <label
          style={{ display: "block", fontSize: "0.9rem", marginBottom: "0.25rem" }}
        >
          {mode === "encrypt" ? "Plaintext" : "Ciphertext"}
        </label>
        <textarea
          rows={4}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={
            mode === "encrypt"
              ? "Enter text to encrypt"
              : "Enter ciphertext to decrypt"
          }
          style={{
            width: "100%",
            padding: "0.4rem 0.5rem",
            fontSize: "0.9rem",
            borderRadius: "4px",
            border: "1px solid #ccc",
            resize: "none",
          }}
        />
      </div>

      {/* Buttons */}
      <div style={{ display: "flex", gap: "0.5rem", marginBottom: "0.6rem" }}>
        <button
          onClick={handleProcess}
          disabled={loading}
          style={{
            flex: 1,
            padding: "0.4rem 1rem",
            backgroundColor: "#0d6efd",
            color: "#fff",
            border: "none",
            borderRadius: "4px",
            fontWeight: "bold",
            cursor: "pointer",
            opacity: loading ? 0.7 : 1,
          }}
        >
          {loading
            ? "Processing..."
            : mode === "encrypt"
            ? "Encrypt"
            : "Decrypt"}
        </button>
        <button
          onClick={handleClear}
          disabled={loading}
          style={{
            padding: "0.4rem 1rem",
            backgroundColor: "#6c757d",
            color: "#fff",
            border: "none",
            borderRadius: "4px",
            fontWeight: "bold",
            cursor: "pointer",
            opacity: loading ? 0.7 : 1,
          }}
        >
          Clear
        </button>
      </div>

      {/* Output */}
      {output && (
        <div style={{ marginBottom: "0.4rem" }}>
          <label
            style={{
              display: "block",
              fontSize: "0.9rem",
              marginBottom: "0.25rem",
            }}
          >
            {mode === "encrypt"
              ? "Encrypted (ciphertext)"
              : "Decrypted (plaintext)"}
          </label>
          <div
            style={{
              backgroundColor: "#f8f9fa",
              borderRadius: "4px",
              border: "1px solid #ddd",
              padding: "0.5rem",
              fontFamily: "Consolas, monospace",
              fontSize: "0.85rem",
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
            }}
          >
            {output}
          </div>
        </div>
      )}

      {error && (
        <div
          style={{
            marginTop: "0.3rem",
            fontSize: "0.82rem",
            color: "#b02a37",
            backgroundColor: "#d8f8d7ff",
            borderRadius: "4px",
            padding: "0.4rem 0.5rem",
            border: "1px solid #f5c2c7",
          }}
        >
          {error}
        </div>
      )}
    </div>
  );
}

// ==================== RSA PANEL (TKINTER STYLE) ====================

function RSAPanel() {
  // Key management
  const [bitLength, setBitLength] = useState("1024");
  const [publicExponent, setPublicExponent] = useState("65537");
  const [keyText, setKeyText] = useState(
    "Click 'Generate Keys' or load keys from JSON (buttons below).\n"
  );
  const [fingerprint, setFingerprint] = useState("—");
  const [generatedKey, setGeneratedKey] = useState(null);
  const [keysStatus, setKeysStatus] = useState("Ready.");

  // Encrypt / Decrypt
  const [encMode, setEncMode] = useState("text");
  const [encE, setEncE] = useState("");
  const [encN, setEncN] = useState("");
  const [decD, setDecD] = useState("");
  const [decN, setDecN] = useState("");
  const [plaintext, setPlaintext] = useState("");
  const [ciphertext, setCiphertext] = useState("");
  const [decryptedOutput, setDecryptedOutput] = useState("");
  const [encStatus, setEncStatus] = useState("");
  const [lastPlainHash, setLastPlainHash] = useState(null);

  // Sign / Verify
  const [sigMode, setSigMode] = useState("text");
  const [sigSD, setSigSD] = useState("");
  const [sigSN, setSigSN] = useState("");
  const [sigVE, setSigVE] = useState("");
  const [sigVN, setSigVN] = useState("");
  const [sigMessage, setSigMessage] = useState("");
  const [sigHex, setSigHex] = useState("");
  const [sigStatus, setSigStatus] = useState("");

  const [activeTab, setActiveTab] = useState("keys");

  // -------- KEY MANAGEMENT --------
  async function handleGenerateKeys() {
    try {
      setKeysStatus("Generating keys...");
      const bits = parseInt(bitLength, 10);
      const eInt = parseInt(publicExponent, 10);
      if (!bits || bits <= 0) throw new Error("Invalid bit length.");
      if (!eInt || eInt <= 1 || eInt % 2 === 0)
        throw new Error("Public exponent e must be an odd integer > 1.");

      const data = await apiPost("/generate-keys", {
        bits,
        e: String(eInt),
      });

      let p = data.p;
      let q = data.q;
      let n = data.n;
      let e = data.e;
      let d = data.d;

      if ((!n || !e) && data.public_key) {
        n = data.public_key.n || data.public_key.modulus;
        e = data.public_key.e || data.public_key.exponent;
      }
      if (!d && data.private_key) d = data.private_key.d;
      if (!p && data.private_key) p = data.private_key.p;
      if (!q && data.private_key) q = data.private_key.q;

      if (!n || !e || !d) {
        console.error("Unexpected keygen response:", data);
        throw new Error(
          "Key generation response missing n/e/d fields. Check backend format."
        );
      }

      const mergedKey = {
        ...(generatedKey || {}),
        p,
        q,
        n,
        e,
        d,
        phi: data.phi,
      };
      setGeneratedKey(mergedKey);

      const lines = [];
      if (p) lines.push(`p = ${p}`);
      if (q) lines.push(`q = ${q}`);
      lines.push(`n = ${n}`);
      if (data.phi) lines.push(`φ(n) = ${data.phi}`);
      lines.push(`e = ${e}`);
      lines.push(`d = ${d}`);
      setKeyText(lines.join("\n") + "\n");
      setFingerprint(data.fingerprint || data.fp || "—");
      setKeysStatus("Keys generated.");
    } catch (err) {
      const msg = shortStatus(err);
      setKeysStatus("Key generation failed: " + msg);
      alert("Key generation error: " + msg);
    }
  }

  function handleClearKeysView() {
    setKeyText("Key view cleared. Generate or load keys to proceed.\n");
    setGeneratedKey(null);
    setFingerprint("—");
    setKeysStatus("Cleared key view.");
  }

  function useGeneratedPublicForEncrypt() {
    if (!generatedKey || !generatedKey.n || !generatedKey.e) {
      setEncStatus("No generated/loaded public key.");
      alert("No generated/loaded public key.");
      return;
    }
    setEncE(String(generatedKey.e));
    setEncN(String(generatedKey.n));
    setEncStatus("Public key filled from generated key.");
  }

  function useGeneratedPrivateForDecrypt() {
    if (!generatedKey || !generatedKey.n || !generatedKey.d) {
      setEncStatus("No generated/loaded private key.");
      alert("No generated/loaded private key.");
      return;
    }
    setDecD(String(generatedKey.d));
    setDecN(String(generatedKey.n));
    setEncStatus("Private key filled from generated key.");
  }

  function useGeneratedPublicForVerify() {
    if (!generatedKey || !generatedKey.n || !generatedKey.e) {
      setSigStatus("No generated/loaded public key.");
      alert("No generated/loaded public key.");
      return;
    }
    setSigVE(String(generatedKey.e));
    setSigVN(String(generatedKey.n));
    setSigStatus("Public key filled from generated key.");
  }

  function useGeneratedPrivateForSign() {
    if (!generatedKey || !generatedKey.n || !generatedKey.d) {
      setSigStatus("No generated/loaded private key.");
      alert("No generated/loaded private key.");
      return;
    }
    setSigSD(String(generatedKey.d));
    setSigSN(String(generatedKey.n));
    setSigStatus("Private key filled from generated key.");
  }

  function handleDownloadPublic() {
    if (!generatedKey || !generatedKey.n || !generatedKey.e) {
      alert("No public key to save. Generate or load keys first.");
      return;
    }
    downloadJson("rsa_public_key.json", {
      n: String(generatedKey.n),
      e: String(generatedKey.e),
    });
  }

  function handleDownloadPrivate() {
    if (!generatedKey || !generatedKey.n || !generatedKey.d) {
      alert("No private key to save. Generate or load keys first.");
      return;
    }
    downloadJson("rsa_private_key.json", {
      n: String(generatedKey.n),
      d: String(generatedKey.d),
    });
  }

  function handleLoadPublicFile(ev) {
    const file = ev.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const data = JSON.parse(reader.result);
        if (!data.n || !data.e) throw new Error("JSON must contain 'n' and 'e'.");
        const merged = { ...(generatedKey || {}), n: data.n, e: data.e };
        setGeneratedKey(merged);
        setKeyText((prev) => `${prev}\n[Loaded Public]\nn = ${data.n}\ne = ${data.e}\n`);
        setKeysStatus("Public key loaded from file.");
      } catch (err) {
        alert("Load public key error: " + shortStatus(err));
      }
    };
    reader.readAsText(file);
    ev.target.value = "";
  }

  function handleLoadPrivateFile(ev) {
    const file = ev.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const data = JSON.parse(reader.result);
        if (!data.n || !data.d) throw new Error("JSON must contain 'n' and 'd'.");
        const merged = { ...(generatedKey || {}), n: data.n, d: data.d };
        setGeneratedKey(merged);
        setKeyText((prev) => `${prev}\n[Loaded Private]\nn = ${data.n}\nd = ${data.d}\n`);
        setKeysStatus("Private key loaded from file.");
      } catch (err) {
        alert("Load private key error: " + shortStatus(err));
      }
    };
    reader.readAsText(file);
    ev.target.value = "";
  }

  // -------- ENCRYPT / DECRYPT --------
  async function handleEncrypt() {
    try {
      const e = encE.trim();
      const n = encN.trim();
      if (!e || !n) {
        throw new Error(
          "Public key (e, n) is required. Generate keys, click 'Use Generated', or paste your own key."
        );
      }
      if (!plaintext.trim()) throw new Error("Plaintext is empty.");

      setLastPlainHash(quickHash(plaintext));

      const data = await apiPost("/encrypt", {
        message: plaintext,
        e,
        n,
        mode: encMode,
      });

      setCiphertext(data.ciphertext_hex || data.ciphertext || "");
      setEncStatus("Encrypted successfully.");
    } catch (err) {
      const msg = shortStatus(err);
      setEncStatus(msg);
      alert("Encrypt error: " + msg);
    }
  }

  async function handleDecrypt() {
    try {
      const d = decD.trim();
      const n = decN.trim();
      if (!d || !n) {
        throw new Error(
          "Private key (d, n) is required. Generate keys, click 'Use Generated', or paste your own key."
        );
      }
      if (!ciphertext.trim()) throw new Error("Ciphertext is empty.");

      const ct = ciphertext.trim();
      const data = await apiPost("/decrypt", {
        ciphertext: ct,
        ciphertext_hex: ct,
        d,
        n,
        mode: encMode,
      });

      const pt = data.plaintext || "";
      setDecryptedOutput(pt);

      if (lastPlainHash && quickHash(pt) === lastPlainHash) {
        setEncStatus("Decrypted successfully (round-trip match).");
      } else {
        setEncStatus("Decrypted successfully.");
      }
    } catch (err) {
      const msg = shortStatus(err);
      setEncStatus(msg);
      alert("Decrypt error: " + msg);
    }
  }

  function handleClearEnc() {
    setPlaintext("");
    setCiphertext("");
    setDecryptedOutput("");
    setEncStatus("");
  }

  // -------- SIGN / VERIFY --------
  async function handleSign() {
    try {
      const d = sigSD.trim();
      const n = sigSN.trim();
      if (!d || !n) {
        throw new Error(
          "Private key (d, n) is required for signing. Generate keys, click 'Use Generated', or paste your own key."
        );
      }
      if (!sigMessage.trim()) throw new Error("Message is empty.");

      const data = await apiPost("/sign", {
        message: sigMessage,
        d,
        n,
        mode: sigMode,
      });

      setSigHex(data.signature_hex || data.signature || "");
      setSigStatus("Signed successfully.");
    } catch (err) {
      const msg = shortStatus(err);
      setSigStatus(msg);
      alert("Sign error: " + msg);
    }
  }

  async function handleVerify() {
    try {
      const e = sigVE.trim();
      const n = sigVN.trim();
      if (!e || !n) {
        throw new Error(
          "Public key (e, n) is required for verification. Generate keys, click 'Use Generated', or paste your own key."
        );
      }
      if (!sigMessage.trim()) throw new Error("Message is empty.");
      if (!sigHex.trim()) throw new Error("Signature is empty.");

      const sigValue = sigHex.trim();

      const data = await apiPost("/verify", {
        message: sigMessage,
        signature_hex: sigValue,
        signature: sigValue, // both names, so backend won't say "signature is required"
        e,
        n,
        mode: sigMode,
      });

      const ok = !!data.valid;
      setSigStatus(ok ? "Signature VALID." : "Signature INVALID.");
      alert(ok ? "Signature VALID" : "Signature INVALID");
    } catch (err) {
      const msg = shortStatus(err);
      setSigStatus(msg);
      alert("Verify error: " + msg);
    }
  }

  function handleClearSig() {
    setSigMessage("");
    setSigHex("");
    setSigStatus("");
  }

  // -------- Tabs UI --------
  const tabBtn = (id, label) => (
    <button
      key={id}
      onClick={() => setActiveTab(id)}
      style={{
        padding: "0.4rem 0.9rem",
        marginRight: "0.3rem",
        border: "none",
        borderBottom: activeTab === id ? "3px solid #fd0d7dff" : "1px solid #ccc",
        backgroundColor: activeTab === id ? "#0d6efd" : "#f0f0f0",
        color: activeTab === id ? "#fff" : "#333",
        fontWeight: "bold",
        cursor: "pointer",
        fontSize: "0.9rem",
      }}
    >
      {label}
    </button>
  );

  return (
    <div
      style={{
        maxWidth: "1000px",
        margin: "0 auto",
        border: "2px solid #c78b8bff",
        borderRadius: "6px",
        backgroundColor: "#f8f9fa",
        boxShadow: "0 2px 6px rgba(196, 7, 7, 0.08)",
        fontFamily: "Segoe UI, system-ui, -apple-system, BlinkMacSystemFont",
      }}
    >
      <div
        style={{
          padding: "0.6rem 1rem",
          borderBottom: "1px solid #ddd",
          backgroundColor: "#0d4216ff",
          color: "#fff",
          fontSize: "20px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
        }}
      >
        <div>
          <strong>RSA Cryptography Demo – Robust (Educational)</strong>
        </div>
        <div style={{ fontSize: "0.8rem" }}>Mode: RSA</div>
      </div>

      {/* Tab headers */}
      <div style={{ padding: "0.4rem 1rem", borderBottom: "1px solid #ce8282ff" }}>
        {tabBtn("keys", "Key Generation & Management")}
        {tabBtn("enc", "Encrypt / Decrypt")}
        {tabBtn("sig", "Sign / Verify")}
        {tabBtn("help", "Help / Notes")}
      </div>

      <div style={{ padding: "0.8rem 1rem 1rem" }}>
        {/* KEY TAB */}
        {activeTab === "keys" && (
          <>
            <div
              style={{
                display: "flex",
                flexWrap: "wrap",
                gap: "0.6rem",
                marginBottom: "0.6rem",
                alignItems: "center",
              }}
            >
              <label>
                Bit length:&nbsp;
                <select
                  value={bitLength}
                  onChange={(e) => setBitLength(e.target.value)}
                >
                  <option value={256}>256-bit (Fast, Testing Only)</option>
                  <option value={512}>512-bit (Fast, Demo)</option>
                  <option value={1024}>1024-bit (Medium)</option>
                  <option value={2048}>2048-bit (Secure)</option>
                </select>
              </label>
              <label>
                &nbsp;&nbsp;Public exponent e:&nbsp;
                <input
                  type="text"
                  value={publicExponent}
                  onChange={(e) => setPublicExponent(e.target.value)}
                  style={{ width: "90px" }}
                />
              </label>
              <button
                onClick={handleGenerateKeys}
                style={{
                  padding: "0.3rem 0.9rem",
                  backgroundColor: "#0d6efd",
                  color: "#fff",
                  border: "none",
                  borderRadius: "3px",
                  fontWeight: "bold",
                  cursor: "pointer",
                }}
              >
                Generate Keys
              </button>
              <button
                onClick={handleClearKeysView}
                style={{
                  padding: "0.3rem 0.9rem",
                  backgroundColor: "#6c757d",
                  color: "#fff",
                  border: "none",
                  borderRadius: "3px",
                  fontWeight: "bold",
                  cursor: "pointer",
                }}
              >
                Clear
              </button>
              <div style={{ marginLeft: "auto", fontSize: "0.8rem" }}>
                Fingerprint: <strong>{fingerprint}</strong>
              </div>
            </div>

            <textarea
              value={keyText}
              onChange={(e) => setKeyText(e.target.value)}
              style={{
                width: "100%",
                height: "260px",
                fontFamily: "Consolas, monospace",
                fontSize: "0.85rem",
                padding: "0.5rem",
                boxSizing: "border-box",
              }}
            />

            <div
              style={{
                marginTop: "0.5rem",
                display: "flex",
                flexWrap: "wrap",
                gap: "0.6rem",
              }}
            >
              <button
                onClick={handleDownloadPublic}
                style={{
                  padding: "0.3rem 0.8rem",
                  backgroundColor: "#6c757d",
                  color: "#fff",
                  border: "none",
                  borderRadius: "3px",
                  cursor: "pointer",
                  fontSize: "0.85rem",
                }}
              >
                Save Public Key (JSON)
              </button>
              <button
                onClick={handleDownloadPrivate}
                style={{
                  padding: "0.3rem 0.8rem",
                  backgroundColor: "#6c757d",
                  color: "#fff",
                  border: "none",
                  borderRadius: "3px",
                  cursor: "pointer",
                  fontSize: "0.85rem",
                }}
              >
                Save Private Key (JSON)
              </button>

              <label
                style={{
                  padding: "0.3rem 0.8rem",
                  backgroundColor: "#0d6efd",
                  color: "#fff",
                  borderRadius: "3px",
                  cursor: "pointer",
                  fontSize: "0.85rem",
                }}
              >
                Load Public Key
                <input
                  type="file"
                  accept=".json,application/json"
                  style={{ display: "none" }}
                  onChange={handleLoadPublicFile}
                />
              </label>

              <label
                style={{
                  padding: "0.3rem 0.8rem",
                  backgroundColor: "#0d6efd",
                  color: "#fff",
                  borderRadius: "3px",
                  cursor: "pointer",
                  fontSize: "0.85rem",
                }}
              >
                Load Private Key
                <input
                  type="file"
                  accept=".json,application/json"
                  style={{ display: "none" }}
                  onChange={handleLoadPrivateFile}
                />
              </label>
            </div>

            <div
              style={{
                marginTop: "0.4rem",
                fontSize: "0.8rem",
                color: "#555",
              }}
            >
              Status: {keysStatus}
            </div>
          </>
        )}

        {/* ENC TAB */}
        {activeTab === "enc" && (
          <>
            <div style={{ marginBottom: "0.6rem", fontSize: "0.9rem" }}>
              <div
                style={{
                  display: "flex",
                  gap: "0.5rem",
                  marginBottom: "0.3rem",
                  alignItems: "center",
                }}
              >
                <span>Public key e:</span>
                <input
                  type="text"
                  value={encE}
                  onChange={(e) => setEncE(e.target.value)}
                  style={{ width: "120px" }}
                />
                <span>n:</span>
                <input
                  type="text"
                  value={encN}
                  onChange={(e) => setEncN(e.target.value)}
                  style={{ flex: 1 }}
                />
                <button
                  onClick={useGeneratedPublicForEncrypt}
                  style={{
                    padding: "0.25rem 0.6rem",
                    backgroundColor: "#35414bff",
                    color: "#fff",
                    border: "none",
                    borderRadius: "3px",
                    cursor: "pointer",
                  }}
                >
                  Use Generated
                </button>
                <button
                  onClick={() => {
                    setEncE("");
                    setEncN("");
                  }}
                  style={{
                    padding: "0.25rem 0.6rem",
                    backgroundColor: "#8294a7ff",
                    color: "#fff",
                    border: "none",
                    borderRadius: "3px",
                    cursor: "pointer",
                  }}
                >
                  Clear Pub
                </button>
              </div>

              <div
                style={{
                  display: "flex",
                  gap: "0.5rem",
                  marginBottom: "0.4rem",
                  alignItems: "center",
                }}
              >
                <span>Private key d:</span>
                <input
                  type="text"
                  value={decD}
                  onChange={(e) => setDecD(e.target.value)}
                  style={{ width: "120px" }}
                />
                <span>n:</span>
                <input
                  type="text"
                  value={decN}
                  onChange={(e) => setDecN(e.target.value)}
                  style={{ flex: 1 }}
                />
                <button
                  onClick={useGeneratedPrivateForDecrypt}
                  style={{
                    padding: "0.25rem 0.6rem",
                    backgroundColor: "#35414bff",
                    color: "#fff",
                    border: "none",
                    borderRadius: "3px",
                    cursor: "pointer",
                  }}
                >
                  Use Generated
                </button>
                <button
                  onClick={() => {
                    setDecD("");
                    setDecN("");
                  }}
                  style={{
                    padding: "0.25rem 0.6rem",
                    backgroundColor: "#8294a7ff",
                    color: "#fff",
                    border: "none",
                    borderRadius: "3px",
                    cursor: "pointer",
                  }}
                >
                  Clear Priv
                </button>
              </div>

              <div style={{ marginBottom: "0.4rem" }}>
                Message input mode:&nbsp;
                <label>
                  <input
                    type="radio"
                    name="encMode"
                    value="text"
                    checked={encMode === "text"}
                    onChange={() => setEncMode("text")}
                  />{" "}
                  Text (UTF-8)
                </label>
                &nbsp;&nbsp;
                <label>
                  <input
                    type="radio"
                    name="encMode"
                    value="hex"
                    checked={encMode === "hex"}
                    onChange={() => setEncMode("hex")}
                  />{" "}
                  Hex
                </label>
              </div>
            </div>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: "0.6rem",
                marginBottom: "0.6rem",
              }}
            >
              <div>
                <div
                  style={{
                    fontWeight: "bold",
                    marginBottom: "0.2rem",
                    fontSize: "0.9rem",
                  }}
                >
                  Plaintext
                </div>
                <textarea
                  value={plaintext}
                  onChange={(e) => setPlaintext(e.target.value)}
                  style={{
                    width: "100%",
                    height: "150px",
                    weight: "600px",
                    fontFamily: "Consolas, monospace",
                    fontSize: "0.9rem",
                    padding: "0.4rem",
                    boxSizing: "border-box",
                  }}
                />
              </div>
              <div>
                <div
                  style={{
                    fontWeight: "bold",
                    marginBottom: "0.2rem",
                    fontSize: "0.9rem",
                  }}
                >
                  Ciphertext (hex)
                </div>
                <textarea
                  value={ciphertext}
                  onChange={(e) => setCiphertext(e.target.value)}
                  style={{
                    width: "100%",
                    height: "150px",
                    fontFamily: "Consolas, monospace",
                    fontSize: "0.9rem",
                    padding: "0.4rem",
                    boxSizing: "border-box",
                  }}
                />
              </div>
            </div>

            <div style={{ marginBottom: "0.6rem" }}>
              <div
                style={{
                  fontWeight: "bold",
                  marginBottom: "0.2rem",
                  fontSize: "0.9rem",
                }}
              >
                Decrypted Output
              </div>
              <textarea
                value={decryptedOutput}
                readOnly
                style={{
                  width: "100%",
                  height: "120px",
                  fontFamily: "Consolas, monospace",
                  fontSize: "0.9rem",
                  padding: "0.4rem",
                  boxSizing: "border-box",
                  backgroundColor: "#fff",
                }}
              />
            </div>

            <div
              style={{
                display: "flex",
                gap: "0.5rem",
                marginBottom: "0.4rem",
              }}
            >
              <button
                onClick={handleEncrypt}
                style={{
                  padding: "0.35rem 1rem",
                  backgroundColor: "#0d6efd",
                  color: "#fff",
                  border: "none",
                  borderRadius: "3px",
                  fontWeight: "bold",
                  cursor: "pointer",
                }}
              >
                Encrypt →
              </button>
              <button
                onClick={handleDecrypt}
                style={{
                  padding: "0.35rem 1rem",
                  backgroundColor: "#198754",
                  color: "#fff",
                  border: "none",
                  borderRadius: "3px",
                  fontWeight: "bold",
                  cursor: "pointer",
                }}
              >
                ← Decrypt
              </button>
              <button
                onClick={handleClearEnc}
                style={{
                  padding: "0.35rem 1rem",
                  backgroundColor: "#6c757d",
                  color: "#fff",
                  border: "none",
                  borderRadius: "3px",
                  fontWeight: "bold",
                  cursor: "pointer",
                }}
              >
                Clear All
              </button>
            </div>

            <div
              style={{
                fontSize: "0.8rem",
                color: "#555",
                marginBottom: "0.2rem",
              }}
            >
              Tips: Paste custom e,n or d,n pairs. Text encodes UTF-8; Hex
              interprets raw bytes. Raw RSA has no padding (demo only). If you see
              "m &lt; n" error, shorten message or use a larger key.
            </div>
            <div style={{ fontSize: "0.8rem", color: "#555555ff" }}>
              Status: {encStatus}
            </div>
          </>
        )}

        {/* SIGN / VERIFY TAB */}
        {activeTab === "sig" && (
          <>
            <div style={{ marginBottom: "0.6rem", fontSize: "0.9rem" }}>
              <div
                style={{
                  display: "flex",
                  gap: "0.5rem",
                  marginBottom: "0.3rem",
                  alignItems: "center",
                }}
              >
                <span>Public key e:</span>
                <input
                  type="text"
                  value={sigVE}
                  onChange={(e) => setSigVE(e.target.value)}
                  style={{ width: "120px" }}
                />
                <span>n:</span>
                <input
                  type="text"
                  value={sigVN}
                  onChange={(e) => setSigVN(e.target.value)}
                  style={{ flex: 1 }}
                />
                <button
                  onClick={useGeneratedPublicForVerify}
                  style={{
                    padding: "0.25rem 0.6rem",
                    backgroundColor: "#35414bff",
                    color: "#fff",
                    border: "none",
                    borderRadius: "3px",
                    cursor: "pointer",
                  }}
                >
                  Use Generated
                </button>
                <button
                  onClick={() => {
                    setSigVE("");
                    setSigVN("");
                  }}
                  style={{
                    padding: "0.25rem 0.6rem",
                    backgroundColor: "#8294a7ff",
                    color: "#fff",
                    border: "none",
                    borderRadius: "3px",
                    cursor: "pointer",
                  }}
                >
                  Clear Pub
                </button>
              </div>

              <div
                style={{
                  display: "flex",
                  gap: "0.5rem",
                  marginBottom: "0.4rem",
                  alignItems: "center",
                }}
              >
                <span>Private key d:</span>
                <input
                  type="text"
                  value={sigSD}
                  onChange={(e) => setSigSD(e.target.value)}
                  style={{ width: "120px" }}
                />
                <span>n:</span>
                <input
                  type="text"
                  value={sigSN}
                  onChange={(e) => setSigSN(e.target.value)}
                  style={{ flex: 1 }}
                />
                <button
                  onClick={useGeneratedPrivateForSign}
                  style={{
                    padding: "0.25rem 0.6rem",
                    backgroundColor: "#35414bff",
                    color: "#fff",
                    border: "none",
                    borderRadius: "3px",
                    cursor: "pointer",
                  }}
                >
                  Use Generated
                </button>
                <button
                  onClick={() => {
                    setSigSD("");
                    setSigSN("");
                  }}
                  style={{
                    padding: "0.25rem 0.6rem",
                    backgroundColor: "#8294a7ff",
                    color: "#fff",
                    border: "none",
                    borderRadius: "3px",
                    cursor: "pointer",
                  }}
                >
                  Clear Priv
                </button>
              </div>

              <div style={{ marginBottom: "0.4rem" }}>
                Message mode:&nbsp;
                <label>
                  <input
                    type="radio"
                    name="sigMode"
                    value="text"
                    checked={sigMode === "text"}
                    onChange={() => setSigMode("text")}
                  />{" "}
                  Text (UTF-8)
                </label>
                &nbsp;&nbsp;
                <label>
                  <input
                    type="radio"
                    name="sigMode"
                    value="hex"
                    checked={sigMode === "hex"}
                    onChange={() => setSigMode("hex")}
                  />{" "}
                  Hex
                </label>
              </div>
            </div>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: "0.6rem",
                marginBottom: "0.6rem",
              }}
            >
              <div>
                <div
                  style={{
                    fontWeight: "bold",
                    marginBottom: "0.2rem",
                    fontSize: "0.9rem",
                  }}
                >
                  Message (Text or Hex)
                </div>
                <textarea
                  value={sigMessage}
                  onChange={(e) => setSigMessage(e.target.value)}
                  style={{
                    width: "100%",
                    height: "150px",
                    fontFamily: "Consolas, monospace",
                    fontSize: "0.9rem",
                    padding: "0.4rem",
                    boxSizing: "border-box",
                  }}
                />
              </div>
              <div>
                <div
                  style={{
                    fontWeight: "bold",
                    marginBottom: "0.2rem",
                    fontSize: "0.9rem",
                  }}
                >
                  Signature (hex)
                </div>
                <textarea
                  value={sigHex}
                  onChange={(e) => setSigHex(e.target.value)}
                  style={{
                    width: "100%",
                    height: "150px",
                    fontFamily: "Consolas, monospace",
                    fontSize: "0.9rem",
                    padding: "0.4rem",
                    boxSizing: "border-box",
                  }}
                />
              </div>
            </div>

            <div
              style={{
                display: "flex",
                gap: "0.5rem",
                marginBottom: "0.4rem",
              }}
            >
              <button
                onClick={handleSign}
                style={{
                  padding: "0.35rem 1rem",
                  backgroundColor: "#0d6efd",
                  color: "#fff",
                  border: "none",
                  borderRadius: "3px",
                  fontWeight: "bold",
                  cursor: "pointer",
                }}
              >
                Sign →
              </button>
              <button
                onClick={handleVerify}
                style={{
                  padding: "0.35rem 1rem",
                  backgroundColor: "#198754",
                  color: "#fff",
                  border: "none",
                  borderRadius: "3px",
                  fontWeight: "bold",
                  cursor: "pointer",
                }}
              >
                ← Verify
              </button>
              <button
                onClick={handleClearSig}
                style={{
                  padding: "0.35rem 1rem",
                  backgroundColor: "#6c757d",
                  color: "#fff",
                  border: "none",
                  borderRadius: "3px",
                  fontWeight: "bold",
                  cursor: "pointer",
                }}
              >
                Clear
              </button>
            </div>

            <div
              style={{
                fontSize: "0.8rem",
                color: "#555",
                marginBottom: "0.2rem",
              }}
            >
              Signs SHA-256(message). For demo only (no PKCS#1 v1.5 / PSS).
              Change any byte of the message and verification should fail.
            </div>
            <div style={{ fontSize: "0.8rem", color: "#555" }}>
              Status: {sigStatus}
            </div>
          </>
        )}

        {/* HELP TAB */}
        {activeTab === "help" && (
          <textarea
            readOnly
            value={
              "RSA DEMO – IMPORTANT NOTES (Educational Only)\n\n" +
              "• Raw RSA (no padding). For learning only.\n" +
              "• Encrypt leaves the plaintext panel unchanged; Decrypt shows the result in 'Decrypted Output'.\n" +
              "• Keys can be generated or loaded from JSON, then reused across tabs via 'Use Generated'.\n" +
              "• Text mode encodes UTF-8; Hex mode interprets raw bytes (e.g., 48656c6c6f21 for \"Hello!\").\n"
            }
            style={{
              width: "100%",
              height: "260px",
              fontFamily: "Consolas, monospace",
              fontSize: "0.9rem",
              padding: "0.5rem",
              boxSizing: "border-box",
              backgroundColor: "#fff",
            }}
          />
        )}
      </div>
    </div>
  );
}

// ==================== ROOT APP (AES / RSA SWITCH) ====================

export default function App() {
  const [mode, setMode] = useState("RSA"); // "AES" or "RSA"

  return (
    <div style={{ padding: "1rem 0" }}>
      {/* Centered AES / RSA buttons */}
      <div
        style={{
          display: "flex",
          justifyContent: "center",
          gap: "0.75rem",
          marginBottom: "1.2rem",
        }}
      >
        <button
          onClick={() => setMode("AES")}
          style={{
            padding: "0.35rem 0.9rem",
            borderRadius: "4px",
            border: mode === "AES" ? "2px solid #0d6efd" : "1px solid #b90d0dff",
            backgroundColor: mode === "AES" ? "#e7f1ff" : "#f8f9fa",
            cursor: "pointer",
            minWidth: "70px",
          }}
        >
          AES (Symmetric)
        </button>
        <button
          onClick={() => setMode("RSA")}
          style={{
            padding: "0.35rem 0.9rem",
            borderRadius: "4px",
            border: mode === "RSA" ? "2px solid #0d6efd" : "1px solid #e20909ff",
            backgroundColor: mode === "RSA" ? "#e7f1ff" : "#f8f9fa",
            cursor: "pointer",
            minWidth: "70px",
          }}
        >
          RSA (Asymmetric)
        </button>
      </div>

      {/* Content card */}
      <div style={{ padding: "0 0.5rem 1rem" }}>
        {mode === "AES" ? <AESPanel /> : <RSAPanel />}
      </div>
    </div>
  );
}

