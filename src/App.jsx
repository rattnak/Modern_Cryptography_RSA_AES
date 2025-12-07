import { useState } from "react";

const API_BASE_URL = "http://localhost:8080/api";

function App() {
  const [algorithm, setAlgorithm] = useState("aes"); // 'aes', 'rsa', or 'signature'
  const [mode, setMode] = useState("encrypt"); // 'encrypt', 'decrypt', 'sign', 'verify'
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

  // Digital signature state
  const [signature, setSignature] = useState("");
  const [messageHash, setMessageHash] = useState("");

  // Mode-specific input cache
  const [modeInputCache, setModeInputCache] = useState({
    encrypt: "",
    decrypt: "",
    sign: "",
    verify: "",
  });

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

    if ((algorithm === "rsa" || algorithm === "signature") && !hasKeys) {
      setError("Please generate RSA keys first");
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
        setError("AES backend not yet implemented.");
      } else if (algorithm === "rsa") {
        // RSA Encryption/Decryption
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
        } else if (mode === "decrypt") {
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
      } else if (algorithm === "signature") {
        // Digital Signatures
        if (mode === "sign") {
          // Sign message
          const response = await fetch(`${API_BASE_URL}/sign`, {
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
            throw new Error(data.error || "Signing failed");
          }

          setSignature(data.signature);
          setMessageHash(data.message_hash);
          setOutput(
            `Message signed successfully!\n\nSignature created with private key.`
          );
        } else if (mode === "verify") {
          // Verify signature
          if (!signature.trim() || !messageHash.trim()) {
            setError("Please provide both signature and message hash");
            return;
          }

          const response = await fetch(`${API_BASE_URL}/verify`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              message: input,
              signature: signature,
              message_hash: messageHash,
              session_id: sessionId,
            }),
          });

          const data = await response.json();

          if (!response.ok || !data.success) {
            throw new Error(data.error || "Verification failed");
          }

          setOutput(
            data.valid
              ? "✓ Signature is VALID\n\nThe signature was created by the private key holder and the message has not been modified."
              : "✗ Signature is INVALID\n\nThe signature does not match the message or was not created by the corresponding private key."
          );
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

  const handleResetKeys = () => {
    setPublicKey(null);
    setPrivateKey(null);
    setHasKeys(false);
  };

  // Generate AES key (calls backend AES endpoint and populates `key` textarea)
  const handleGenerateAESKey = async () => {
    setError("");
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL}/aes/generate-key`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ size: keySize }),
      });
      const data = await response.json();
      if (!response.ok || !data.success) {
        throw new Error(data.error || "Failed to generate AES key");
      }
      // API returns hex key string
      setKey(data.key);
      setOutput(`AES-${data.size} key generated and populated.`);
    } catch (err) {
      setError(
        `Error generating AES key: ${err.message}. Make sure the Flask API is running on port 8080.`
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
    setSignature("");
    setMessageHash("");
  };

  const handleModeChange = (newMode) => {
    // Save current input to cache before switching
    setModeInputCache((prev) => ({
      ...prev,
      [mode]: input,
    }));

    // Switch to new mode
    setMode(newMode);

    // Restore cached input for the new mode
    setInput(modeInputCache[newMode] || "");

    // Clear output and errors when switching modes
    setOutput("");
    setError("");
  };

  const handleAlgorithmChange = (newAlgorithm) => {
    setAlgorithm(newAlgorithm);
    handleClear();

    // Reset input cache when switching algorithms
    setModeInputCache({
      encrypt: "",
      decrypt: "",
      sign: "",
      verify: "",
    });

    // Set default mode based on algorithm
    if (newAlgorithm === "signature") {
      setMode("sign");
    } else {
      setMode("encrypt");
    }

    // Only reset keys when switching away from RSA/signature
    if (newAlgorithm === "aes") {
      setPublicKey(null);
      setPrivateKey(null);
      setHasKeys(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 py-8 px-4">
      <div className="max-w-2xl mx-auto">
        <div className="mb-6">
          <h1 className="text-2xl font-semibold text-gray-900 mb-1">
            Modern Cryptography: RSA and AES
          </h1>
          <p className="text-sm text-gray-600">
            Encrypt, decrypt, sign, and verify using AES or RSA
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
            <button
              onClick={() => handleAlgorithmChange("signature")}
              className={`px-4 py-2 text-sm font-medium border-b-2 transition ${
                algorithm === "signature"
                  ? "border-gray-900 text-gray-900"
                  : "border-transparent text-gray-500 hover:text-gray-700"
              }`}
            >
              Digital Signature
            </button>
          </div>
        </div>

        <div className="bg-white border border-gray-200 rounded p-6 space-y-5">
          {/* RSA Key Generation Section */}
          {(algorithm === "rsa" || algorithm === "signature") && (
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
                {hasKeys && (
                  <button
                    onClick={handleResetKeys}
                    disabled={loading}
                    className="px-4 py-2 text-sm font-medium bg-gray-600 text-white rounded hover:bg-gray-700 transition disabled:bg-gray-400 disabled:cursor-not-allowed"
                  >
                    Reset Keys
                  </button>
                )}
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
            {algorithm === "signature" ? (
              // Signature modes: Sign, Verify
              <div className="flex gap-2">
                <button
                  onClick={() => handleModeChange("sign")}
                  className={`flex-1 py-2 px-4 text-sm font-medium rounded transition ${
                    mode === "sign"
                      ? "bg-gray-900 text-white"
                      : "bg-gray-100 text-gray-700 hover:bg-gray-200"
                  }`}
                >
                  Sign
                </button>
                <button
                  onClick={() => handleModeChange("verify")}
                  className={`flex-1 py-2 px-4 text-sm font-medium rounded transition ${
                    mode === "verify"
                      ? "bg-gray-900 text-white"
                      : "bg-gray-100 text-gray-700 hover:bg-gray-200"
                  }`}
                >
                  Verify
                </button>
              </div>
            ) : (
              // AES/RSA modes: Encrypt, Decrypt only
              <div className="flex gap-2">
                <button
                  onClick={() => handleModeChange("encrypt")}
                  className={`flex-1 py-2 px-4 text-sm font-medium rounded transition ${
                    mode === "encrypt"
                      ? "bg-gray-900 text-white"
                      : "bg-gray-100 text-gray-700 hover:bg-gray-200"
                  }`}
                >
                  Encrypt
                </button>
                <button
                  onClick={() => handleModeChange("decrypt")}
                  className={`flex-1 py-2 px-4 text-sm font-medium rounded transition ${
                    mode === "decrypt"
                      ? "bg-gray-900 text-white"
                      : "bg-gray-100 text-gray-700 hover:bg-gray-200"
                  }`}
                >
                  Decrypt
                </button>
              </div>
            )}
          </div>

          {/* Key Size Selection - Only for AES */}
          {algorithm === "aes" && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Key Size
              </label>
              <div className="flex gap-2">
                <select
                  value={keySize}
                  onChange={(e) => setKeySize(parseInt(e.target.value))}
                  className="flex-1 px-3 py-2 text-sm border border-gray-300 rounded focus:ring-1 focus:ring-gray-900 focus:border-gray-900 outline-none bg-white"
                >
                  <option value={128}>AES-128 (16 bytes, 10 rounds)</option>
                  <option value={192}>AES-192 (24 bytes, 12 rounds)</option>
                  <option value={256}>AES-256 (32 bytes, 14 rounds)</option>
                </select>
                <button
                  onClick={handleGenerateAESKey}
                  disabled={loading}
                  className="px-4 py-2 text-sm font-medium bg-black text-white rounded transition disabled:bg-gray-400 disabled:cursor-not-allowed"
                >
                  Generate Key
                </button>
              </div>
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
              <textarea
                id="key"
                value={key}
                onChange={(e) => setKey(e.target.value)}
                placeholder="Enter encryption key"
                rows="1"
                className="w-full px-3 py-2 text-sm border border-gray-300 rounded focus:ring-1 focus:ring-gray-900 focus:border-gray-900 outline-none resize-none font-mono"
              />
            </div>
          )}

          {/* Signature and Hash inputs for Verify mode */}
          {algorithm === "signature" && mode === "verify" && (
            <>
              <div>
                <label
                  htmlFor="signature"
                  className="block text-sm font-medium text-gray-700 mb-2"
                >
                  Digital Signature
                </label>
                <textarea
                  id="signature"
                  value={signature}
                  onChange={(e) => setSignature(e.target.value)}
                  placeholder="Enter signature to verify"
                  rows="2"
                  className="w-full px-3 py-2 text-sm border border-gray-300 rounded focus:ring-1 focus:ring-gray-900 focus:border-gray-900 outline-none resize-y font-mono"
                />
              </div>
              <div>
                <label
                  htmlFor="messageHash"
                  className="block text-sm font-medium text-gray-700 mb-2"
                >
                  Message Hash
                </label>
                <textarea
                  id="messageHash"
                  value={messageHash}
                  onChange={(e) => setMessageHash(e.target.value)}
                  placeholder="Enter message hash"
                  rows="2"
                  className="w-full px-3 py-2 text-sm border border-gray-300 rounded focus:ring-1 focus:ring-gray-900 focus:border-gray-900 outline-none resize-y font-mono"
                />
              </div>
            </>
          )}

          {/* Input Text */}
          <div>
            <label
              htmlFor="input"
              className="block text-sm font-medium text-gray-700 mb-2"
            >
              {mode === "encrypt"
                ? "Plaintext"
                : mode === "decrypt"
                ? "Ciphertext"
                : mode === "sign"
                ? "Message to Sign"
                : "Original Message"}
            </label>
            <textarea
              id="input"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder={
                mode === "encrypt"
                  ? "Enter text to encrypt"
                  : mode === "decrypt"
                  ? "Enter text to decrypt"
                  : mode === "sign"
                  ? "Enter message to sign"
                  : "Enter original message to verify"
              }
              rows="4"
              className="w-full px-3 py-2 text-sm border border-gray-300 rounded focus:ring-1 focus:ring-gray-900 focus:border-gray-900 outline-none resize-y"
            />
          </div>

          {/* Action Buttons */}
          <div className="flex gap-2">
            <button
              onClick={handleProcess}
              disabled={
                loading ||
                ((algorithm === "rsa" || algorithm === "signature") && !hasKeys)
              }
              className="flex-1 bg-gray-900 text-white py-2 px-4 text-sm font-medium rounded hover:bg-gray-800 transition disabled:bg-gray-400 disabled:cursor-not-allowed"
            >
              {loading
                ? "Processing..."
                : mode === "encrypt"
                ? "Encrypt"
                : mode === "decrypt"
                ? "Decrypt"
                : mode === "sign"
                ? "Sign Message"
                : "Verify Signature"}
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
                {mode === "encrypt"
                  ? "Encrypted"
                  : mode === "decrypt"
                  ? "Decrypted"
                  : mode === "sign"
                  ? "Signature Result"
                  : "Verification Result"}
              </label>
              <div className="bg-gray-50 border border-gray-200 rounded p-3">
                <p className="font-mono text-xs break-all text-gray-800 whitespace-pre-wrap">
                  {output}
                </p>
              </div>
              {mode !== "sign" && mode !== "verify" && (
                <button
                  onClick={() => navigator.clipboard.writeText(output)}
                  className="mt-2 text-xs text-gray-600 hover:text-gray-900 underline"
                >
                  Copy to clipboard
                </button>
              )}
            </div>
          )}

          {/* Signature Output (for Sign mode) */}
          {algorithm === "signature" &&
            mode === "sign" &&
            signature &&
            messageHash && (
              <div className="space-y-3">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Digital Signature
                  </label>
                  <div className="bg-gray-50 border border-gray-200 rounded p-3">
                    <p className="font-mono text-xs break-all text-gray-800">
                      {signature}
                    </p>
                  </div>
                  <button
                    onClick={() => navigator.clipboard.writeText(signature)}
                    className="mt-2 text-xs text-gray-600 hover:text-gray-900 underline"
                  >
                    Copy signature
                  </button>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Message Hash (SHA-256)
                  </label>
                  <div className="bg-gray-50 border border-gray-200 rounded p-3">
                    <p className="font-mono text-xs break-all text-gray-800">
                      {messageHash}
                    </p>
                  </div>
                  <button
                    onClick={() => navigator.clipboard.writeText(messageHash)}
                    className="mt-2 text-xs text-gray-600 hover:text-gray-900 underline"
                  >
                    Copy hash
                  </button>
                </div>
                <div className="bg-blue-50 border border-blue-200 rounded p-3">
                  <p className="text-xs text-blue-800">
                    <strong>Tip:</strong> Copy these values to verify the
                    signature later using the "Verify" mode.
                  </p>
                </div>
              </div>
            )}

          {/* Info */}
          <div className="pt-4 border-t border-gray-200">
            <p className="text-xs text-gray-500 mb-2">
              {algorithm === "aes"
                ? "AES Details:"
                : algorithm === "rsa"
                ? "RSA Details:"
                : "Digital Signature Details:"}
            </p>
            {algorithm === "aes" ? (
              <ul className="text-xs text-gray-600 space-y-1">
                <li>AES-128/192/256 symmetric encryption</li>
                <li>Custom Python implementation via Flask API</li>
                <li>SubBytes, ShiftRows, MixColumns transformations</li>
                <li>PKCS7 padding, variable rounds (10/12/14)</li>
                <li>Key sizes: 16/24/32 bytes for 128/192/256-bit</li>
              </ul>
            ) : algorithm === "rsa" ? (
              <ul className="text-xs text-gray-600 space-y-1">
                <li>RSA asymmetric encryption (public/private key pair)</li>
                <li>Custom Python implementation via Flask API</li>
                <li>Encrypt with public key, decrypt with private key</li>
                <li>Key sizes: 256/512/1024/2048-bit</li>
                <li>Based on prime factorization difficulty</li>
              </ul>
            ) : (
              <ul className="text-xs text-gray-600 space-y-1">
                <li>RSA-based digital signatures with SHA-256 hashing</li>
                <li>Custom Python implementation via Flask API</li>
                <li>Sign with private key, verify with public key</li>
                <li>Ensures message authenticity and integrity</li>
                <li>Non-repudiation: only private key holder can sign</li>
                <li>Key sizes: 256/512/1024/2048-bit</li>
              </ul>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
