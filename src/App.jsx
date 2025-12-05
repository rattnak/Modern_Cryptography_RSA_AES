import { useState } from "react";

const API_BASE_URL = "http://localhost:8080/api";

function App() {
  const [algorithm, setAlgorithm] = useState("aes"); // 'aes' or 'rsa'
  const [mode, setMode] = useState("encrypt");
  const [key, setKey] = useState("");
  const [keySize, setKeySize] = useState(128);
  const [rsaKeySize, setRsaKeySize] = useState(2048);
  const [input, setInput] = useState("");
  const [output, setOutput] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  // RSA-specific state
  const [sessionId] = useState(() => `session_${Date.now()}`);
  const [publicKey, setPublicKey] = useState(null);
  const [privateKey, setPrivateKey] = useState(null);
  const [hasKeys, setHasKeys] = useState(false);
  const [showKeys, setShowKeys] = useState(true);

  // Generate RSA keys
  const handleGenerateKeys = async () => {
    setError("");
    setLoading(true);

    try {
      const response = await fetch(`${API_BASE_URL}/generate-keys`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          size: rsaKeySize,
          session_id: sessionId,
        }),
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || "Failed to generate keys");
      }

      setPublicKey(data.public_key);
      setPrivateKey(data.private_key);
      setHasKeys(true);
      setError("");
      setOutput(`Keys generated successfully! (${data.size}-bit)`);
    } catch (err) {
      setError(
        `Error generating keys: ${err.message}. Make sure the Flask API is running on port 8080.`
      );
    } finally {
      setLoading(false);
    }
  };

  const handleProcess = async () => {
    setError("");
    setOutput("");

    if (algorithm === "rsa" && !hasKeys) {
      setError("Please generate RSA keys first");
      return;
    }

    if (algorithm === "aes" && !key.trim()) {
      setError("Please enter an AES key");
      return;
    }

    if (!input.trim()) {
      setError("Please enter text to process");
      return;
    }

    setLoading(true);

    try {
      if (algorithm === "aes") {
        // AES
        if (mode === "encrypt") {
          // Encrypt
          const response = await fetch(`${API_BASE_URL}/aes/encrypt`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              message: input,
              key: key,
              size: keySize,
            }),
          });

          const data = await response.json();

          if (!response.ok || !data.success) {
            throw new Error(data.error || "Encryption failed");
          }

          setOutput(data.ciphertext);
        } else {
          // Decrypt
          const response = await fetch(`${API_BASE_URL}/aes/decrypt`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              ciphertext: input,
              key: key,
              size: keySize,
            }),
          });

          const data = await response.json();

          if (!response.ok || !data.success) {
            throw new Error(data.error || "Decryption failed");
          }

          setOutput(data.plaintext);
        }
      } else {
        // RSA
        if (mode === "encrypt") {
          // Encrypt
          const response = await fetch(`${API_BASE_URL}/encrypt`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              message: input,
              session_id: sessionId,
            }),
          });

          const data = await response.json();

          if (!response.ok || !data.success) {
            throw new Error(data.error || "Encryption failed");
          }

          setOutput(data.ciphertext);
        } else {
          // Decrypt
          const response = await fetch(`${API_BASE_URL}/decrypt`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              ciphertext: input,
              session_id: sessionId,
            }),
          });

          const data = await response.json();

          if (!response.ok || !data.success) {
            throw new Error(data.error || "Decryption failed");
          }

          setOutput(data.plaintext);
        }
      }
    } catch (err) {
      setError(
        `Error: ${err.message}. Make sure the Flask API is running on port 8080.`
      );
    } finally {
      setLoading(false);
    }
  };

  const handleClear = () => {
    setKey("");
    setInput("");
    setOutput("");
    setError("");
  };

  const handleAlgorithmChange = (newAlgorithm) => {
    setAlgorithm(newAlgorithm);
    handleClear();
    setPublicKey(null);
    setPrivateKey(null);
    setHasKeys(false);
  };

  return (
    <div className="min-h-screen bg-gray-50 py-8 px-4">
      <div className="max-w-2xl mx-auto">
        <div className="mb-6">
          <h1 className="text-2xl font-semibold text-gray-900 mb-1">
            Cryptography Demo
          </h1>
          <p className="text-sm text-gray-600">
            Encrypt and decrypt text using AES or RSA
          </p>
        </div>

        {/* Algorithm Tabs */}
        <div className="mb-4">
          <div className="flex border-b border-gray-200">
            <button
              onClick={() => handleAlgorithmChange("aes")}
              className={`px-4 py-2 text-sm font-medium border-b-2 transition ${
                algorithm === "aes"
                  ? "border-gray-900 text-gray-900"
                  : "border-transparent text-gray-500 hover:text-gray-700"
              }`}
            >
              AES (Symmetric)
            </button>
            <button
              onClick={() => handleAlgorithmChange("rsa")}
              className={`px-4 py-2 text-sm font-medium border-b-2 transition ${
                algorithm === "rsa"
                  ? "border-gray-900 text-gray-900"
                  : "border-transparent text-gray-500 hover:text-gray-700"
              }`}
            >
              RSA (Asymmetric)
            </button>
          </div>
        </div>

        <div className="bg-white border border-gray-200 rounded p-6 space-y-5">
          {/* RSA Key Generation Section */}
          {algorithm === "rsa" && (
            <div className="pb-5 border-b border-gray-200">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                RSA Key Size
              </label>
              <div className="flex gap-2 mb-3">
                <select
                  value={rsaKeySize}
                  onChange={(e) => setRsaKeySize(parseInt(e.target.value))}
                  disabled={hasKeys}
                  className="flex-1 px-3 py-2 text-sm border border-gray-300 rounded focus:ring-1 focus:ring-gray-900 focus:border-gray-900 outline-none bg-white disabled:bg-gray-100 disabled:cursor-not-allowed"
                >
                  <option value={256}>256-bit (Fast, Testing Only)</option>
                  <option value={512}>512-bit (Fast, Demo)</option>
                  <option value={1024}>1024-bit (Medium)</option>
                  <option value={2048}>2048-bit (Secure)</option>
                </select>
                <button
                  onClick={handleGenerateKeys}
                  disabled={loading || hasKeys}
                  className="px-4 py-2 text-sm font-medium bg-black text-white rounded transition disabled:bg-gray-400 disabled:cursor-not-allowed"
                >
                  {hasKeys ? "Keys Generated" : "Generate Keys"}
                </button>
              </div>

              {/* Display Keys */}
              {hasKeys && publicKey && privateKey && (
                <div className="space-y-3">
                  {/* Toggle Button */}
                  <button
                    onClick={() => setShowKeys(!showKeys)}
                    className="flex items-center gap-2 text-sm text-gray-700 hover:text-gray-900 transition"
                  >
                    <svg
                      className={`w-4 h-4 transition-transform ${
                        showKeys ? "rotate-90" : ""
                      }`}
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M9 5l7 7-7 7"
                      />
                    </svg>
                    <span className="font-medium">
                      {showKeys ? "Hide" : "Show"} Generated Keys
                    </span>
                  </button>

                  {/* Collapsible Keys Display */}
                  {showKeys && (
                    <div className="space-y-3 pl-6">
                      <div>
                        <label className="block text-xs font-medium text-gray-600 mb-1">
                          Public Key (e, n)
                        </label>
                        <div className="bg-gray-50 border border-gray-200 rounded p-2">
                          <p className="font-mono text-xs break-all text-gray-800">
                            e: {publicKey.e}
                          </p>
                          <p className="font-mono text-xs break-all text-gray-800 mt-1">
                            n: {publicKey.n.substring(0, 60)}...
                          </p>
                        </div>
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-gray-600 mb-1">
                          Private Key (d, n)
                        </label>
                        <div className="bg-gray-50 border border-gray-200 rounded p-2">
                          <p className="font-mono text-xs break-all text-gray-800">
                            d: {privateKey.d.substring(0, 60)}...
                          </p>
                          <p className="font-mono text-xs break-all text-gray-800 mt-1">
                            n: {privateKey.n.substring(0, 60)}...
                          </p>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Mode Selection */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Mode
            </label>
            <div className="flex gap-2">
              <button
                onClick={() => setMode("encrypt")}
                className={`flex-1 py-2 px-4 text-sm font-medium rounded transition ${
                  mode === "encrypt"
                    ? "bg-gray-900 text-white"
                    : "bg-gray-100 text-gray-700 hover:bg-gray-200"
                }`}
              >
                Encrypt
              </button>
              <button
                onClick={() => setMode("decrypt")}
                className={`flex-1 py-2 px-4 text-sm font-medium rounded transition ${
                  mode === "decrypt"
                    ? "bg-gray-900 text-white"
                    : "bg-gray-100 text-gray-700 hover:bg-gray-200"
                }`}
              >
                Decrypt
              </button>
            </div>
          </div>

          {/* Key Size Selection - Only for AES */}
          {algorithm === "aes" && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Key Size
              </label>
              <select
                value={keySize}
                onChange={(e) => setKeySize(parseInt(e.target.value))}
                className="w-full px-3 py-2 text-sm border border-gray-300 rounded focus:ring-1 focus:ring-gray-900 focus:border-gray-900 outline-none bg-white"
              >
                <option value={128}>AES-128 (16 bytes, 10 rounds)</option>
                <option value={192}>AES-192 (24 bytes, 12 rounds)</option>
                <option value={256}>AES-256 (32 bytes, 14 rounds)</option>
              </select>
            </div>
          )}

          {/* Key Input - Only for AES */}
          {algorithm === "aes" && (
            <div>
              <label
                htmlFor="key"
                className="block text-sm font-medium text-gray-700 mb-2"
              >
                Key
              </label>
              <div className="flex gap-2">
                <textarea
                  id="key"
                  value={key}
                  onChange={(e) => setKey(e.target.value)}
                  placeholder="Enter encryption key (hex format)"
                  rows="1"
                  className="flex-1 px-3 py-2 text-sm border border-gray-300 rounded focus:ring-1 focus:ring-gray-900 focus:border-gray-900 outline-none resize-none font-mono"
                />
                <button
                  onClick={async () => {
                    setError("");
                    setLoading(true);
                    try {
                      const response = await fetch(
                        `${API_BASE_URL}/aes/generate-key`,
                        {
                          method: "POST",
                          headers: {
                            "Content-Type": "application/json",
                          },
                          body: JSON.stringify({
                            size: keySize,
                          }),
                        }
                      );
                      const data = await response.json();
                      if (!response.ok || !data.success) {
                        throw new Error(data.error || "Failed to generate key");
                      }
                      setKey(data.key);
                      setError("");
                    } catch (err) {
                      setError(
                        `Error generating key: ${err.message}. Make sure the Flask API is running on port 8080.`
                      );
                    } finally {
                      setLoading(false);
                    }
                  }}
                  disabled={loading}
                  className="px-4 py-2 text-sm font-medium bg-black text-white rounded transition hover:bg-gray-800 disabled:bg-gray-400 disabled:cursor-not-allowed whitespace-nowrap"
                >
                  Generate Key
                </button>
              </div>
            </div>
          )}

          {/* Input Text */}
          <div>
            <label
              htmlFor="input"
              className="block text-sm font-medium text-gray-700 mb-2"
            >
              {mode === "encrypt" ? "Plaintext" : "Ciphertext"}
            </label>
            <textarea
              id="input"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder={
                mode === "encrypt"
                  ? "Enter text to encrypt"
                  : "Enter text to decrypt"
              }
              rows="4"
              className="w-full px-3 py-2 text-sm border border-gray-300 rounded focus:ring-1 focus:ring-gray-900 focus:border-gray-900 outline-none resize-none"
            />
          </div>

          {/* Action Buttons */}
          <div className="flex gap-2">
            <button
              onClick={handleProcess}
              disabled={loading || (algorithm === "rsa" && !hasKeys)}
              className="flex-1 bg-gray-900 text-white py-2 px-4 text-sm font-medium rounded hover:bg-gray-800 transition disabled:bg-gray-400 disabled:cursor-not-allowed"
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
              className="px-4 py-2 text-sm font-medium bg-gray-100 text-gray-700 rounded hover:bg-gray-200 transition disabled:bg-gray-50 disabled:cursor-not-allowed"
            >
              Clear
            </button>
          </div>

          {/* Error Message */}
          {error && (
            <div className="p-3 bg-red-50 border border-red-200 rounded">
              <p className="text-sm text-red-700">{error}</p>
            </div>
          )}

          {/* Output */}
          {output && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                {mode === "encrypt" ? "Encrypted" : "Decrypted"}
              </label>
              <div className="bg-gray-50 border border-gray-200 rounded p-3">
                <p className="font-mono text-xs break-all text-gray-800">
                  {output}
                </p>
              </div>
              <button
                onClick={() => navigator.clipboard.writeText(output)}
                className="mt-2 text-xs text-gray-600 hover:text-gray-900 underline"
              >
                Copy to clipboard
              </button>
            </div>
          )}

          {/* Info */}
          <div className="pt-4 border-t border-gray-200">
            <p className="text-xs text-gray-500 mb-2">
              {algorithm === "aes" ? "AES Details:" : "RSA Details:"}
            </p>
            {algorithm === "aes" ? (
              <ul className="text-xs text-gray-600 space-y-1">
                <li>AES-128/192/256 symmetric encryption</li>
                <li>Custom Python implementation via Flask API</li>
                <li>SubBytes, ShiftRows, MixColumns transformations</li>
                <li>PKCS7 padding, variable rounds (10/12/14)</li>
                <li>Key sizes: 16/24/32 bytes for 128/192/256-bit</li>
              </ul>
            ) : (
              <ul className="text-xs text-gray-600 space-y-1">
                <li>RSA asymmetric encryption (public/private key pair)</li>
                <li>Custom Python implementation via Flask API</li>
                <li>Encrypt with public key, decrypt with private key</li>
                <li>Key sizes: 256/512/1024/2048-bit</li>
                <li>Based on prime factorization difficulty</li>
              </ul>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
