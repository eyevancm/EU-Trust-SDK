/**
 * Sovereign Trust SDK Widget
 * reCAPTCHA replacement using Privacy Pass RSAPBSSA tokens.
 *
 * Usage:
 *   <script src="/widget/widget.js"></script>
 *   <div id="attestation" data-sitekey="sk_test_sovereign"></div>
 *   <script>
 *     TrustWidget.render('#attestation', { onSuccess: (token) => { ... } });
 *   </script>
 *
 * Implements the client side of the 3-step protocol:
 *   1. GET /challenge  → receive challenge parameters + server public key
 *   2. Solve HashCash (CPU-bound) + Argon2 (memory-bound) + environment probes
 *   3. POST /verify with blinded message → receive blind signature
 *   4. Unblind to get final token, pass to onSuccess callback
 */

(function (global) {
  'use strict';

  // --- Configuration ---
  const API_BASE = ''; // relative to the page's origin; set to absolute URL if cross-origin
  const SITEKEY = 'sk_test_sovereign';

  // --- BigInt RSA helpers ---
  // Native BigInt (all modern browsers since 2018).

  function bytesToBigInt(bytes) {
    let hex = '';
    for (const b of bytes) hex += b.toString(16).padStart(2, '0');
    return BigInt('0x' + hex);
  }

  function bigIntToBytes(n, length) {
    let hex = n.toString(16);
    if (hex.length % 2 !== 0) hex = '0' + hex;
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    if (length !== undefined && bytes.length < length) {
      const padded = new Uint8Array(length);
      padded.set(bytes, length - bytes.length);
      return padded;
    }
    return bytes;
  }

  function modPow(base, exp, mod) {
    // Square-and-multiply for BigInt modular exponentiation.
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
      if (exp % 2n === 1n) result = result * base % mod;
      exp >>= 1n;
      base = base * base % mod;
    }
    return result;
  }

  function modInverse(a, m) {
    // Extended Euclidean algorithm
    let [old_r, r] = [a, m];
    let [old_s, s] = [1n, 0n];
    while (r !== 0n) {
      const q = old_r / r;
      [old_r, r] = [r, old_r - q * r];
      [old_s, s] = [s, old_s - q * s];
    }
    if (old_r !== 1n) throw new Error('no modular inverse');
    return ((old_s % m) + m) % m;
  }

  // --- SHA-256 via Web Crypto ---
  async function sha256(data) {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
  }

  // --- SHA-384 via Web Crypto ---
  async function sha384(data) {
    return new Uint8Array(await crypto.subtle.digest('SHA-384', data));
  }

  // --- Encoding helpers ---
  function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function base64ToBytes(b64) {
    const bin = atob(b64);
    return Uint8Array.from(bin, c => c.charCodeAt(0));
  }

  function bytesToBase64(bytes) {
    return btoa(String.fromCharCode(...bytes));
  }

  function concatBytes(...arrays) {
    const total = arrays.reduce((s, a) => s + a.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const a of arrays) { out.set(a, offset); offset += a.length; }
    return out;
  }

  function uint32BE(n) {
    const buf = new Uint8Array(4);
    new DataView(buf.buffer).setUint32(0, n, false);
    return buf;
  }

  function uint64BE(n) {
    const buf = new Uint8Array(8);
    const view = new DataView(buf.buffer);
    const lo = Number(BigInt(n) & 0xFFFFFFFFn);
    const hi = Number((BigInt(n) >> 32n) & 0xFFFFFFFFn);
    view.setUint32(0, hi, false);
    view.setUint32(4, lo, false);
    return buf;
  }

  // --- HashCash solver ---
  // Finds counter such that SHA-256(nonceBytes || uint64BE(counter)) has diffBits leading zeros.
  async function solveHashCash(nonceHex, diffBits) {
    const nonceBytes = hexToBytes(nonceHex);
    let counter = 0n;
    while (true) {
      const data = concatBytes(nonceBytes, uint64BE(counter));
      const digest = await sha256(data);
      if (countLeadingZeroBits(digest) >= diffBits) {
        return bytesToHex(uint64BE(counter));
      }
      counter++;
      // Yield to event loop occasionally to avoid blocking
      if (counter % 10000n === 0n) {
        await new Promise(resolve => setTimeout(resolve, 0));
      }
    }
  }

  function countLeadingZeroBits(bytes) {
    let count = 0;
    for (const byte of bytes) {
      if (byte === 0) { count += 8; continue; }
      for (let mask = 0x80; mask !== 0; mask >>= 1) {
        if (byte & mask) return count;
        count++;
      }
      return count;
    }
    return count;
  }

  // --- Argon2 via WASM (hash-wasm) ---
  let argon2Module = null;

  const ARGON2_SRI = 'sha384-tP0Wy54CKmng7i9EoTlPySD0hBx6Octj0VS6MfwlnUu111MPa+JLm0CCbep6XJ1W';

  async function loadArgon2() {
    if (argon2Module) return argon2Module;
    await new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = 'vendor/argon2.umd.min.js';
      script.integrity = ARGON2_SRI;
      script.crossOrigin = 'anonymous';
      script.onload = resolve;
      script.onerror = reject;
      document.head.appendChild(script);
    });
    argon2Module = window.hashwasm;
    return argon2Module;
  }

  async function solveArgon2(challenge) {
    const lib = await loadArgon2();
    const nonceBytes = hexToBytes(challenge.nonce);
    const result = await lib.argon2id({
      password: 'sovereign-trust-challenge',
      salt: nonceBytes,
      iterations: challenge.iterations,
      parallelism: challenge.parallelism,
      memorySize: challenge.memory,
      hashLength: challenge.key_length,
      outputType: 'hex',
    });
    return result;
  }

  // --- Environment probes ---
  async function runProbes(probeNames) {
    const results = {};
    for (const name of probeNames) {
      try {
        results[name] = await runProbe(name);
      } catch (e) {
        results[name] = '0';
      }
    }
    return results;
  }

  async function runProbe(name) {
    switch (name) {
      case 'webcrypto_timing': {
        const start = performance.now();
        await crypto.subtle.generateKey(
          { name: 'ECDSA', namedCurve: 'P-256' },
          false, ['sign', 'verify']
        );
        return String((performance.now() - start).toFixed(3));
      }
      case 'dom_computation': {
        const start = performance.now();
        const el = document.createElement('div');
        el.style.cssText = 'position:absolute;transform:rotate(45deg) scale(1.5);width:100px;height:100px;';
        document.body.appendChild(el);
        const rect = el.getBoundingClientRect();
        void rect.width;
        document.body.removeChild(el);
        return String((performance.now() - start).toFixed(3));
      }
      case 'memory_allocation': {
        const start = performance.now();
        const buf = new ArrayBuffer(1024 * 1024);
        const view = new Uint8Array(buf);
        for (let i = 0; i < view.length; i += 1024) view[i] = i & 0xFF;
        return String((performance.now() - start).toFixed(3));
      }
      case 'canvas_timing': {
        const start = performance.now();
        const canvas = new OffscreenCanvas(64, 64);
        const ctx = canvas.getContext('2d');
        ctx.fillStyle = '#f0a';
        ctx.fillRect(0, 0, 64, 64);
        ctx.font = '14px serif';
        ctx.fillText('probe', 10, 32);
        canvas.convertToBlob();
        return String((performance.now() - start).toFixed(3));
      }
      case 'audio_latency': {
        try {
          const ac = new AudioContext();
          const latency = ac.baseLatency;
          ac.close();
          return String(latency >= 0 ? latency * 1000 : -1);
        } catch (e) {
          return '-1';
        }
      }
      case 'font_measurement': {
        const start = performance.now();
        const span = document.createElement('span');
        span.style.cssText = 'position:absolute;visibility:hidden;font-size:72px;';
        span.textContent = 'Wmgj|';
        document.body.appendChild(span);
        span.style.fontFamily = 'monospace';
        const w1 = span.offsetWidth;
        span.style.fontFamily = 'serif';
        const w2 = span.offsetWidth;
        document.body.removeChild(span);
        void (w1 + w2);
        return String((performance.now() - start).toFixed(3));
      }
      case 'animation_frame': {
        const t0 = await new Promise(r => requestAnimationFrame(r));
        const t1 = await new Promise(r => requestAnimationFrame(r));
        const t2 = await new Promise(r => requestAnimationFrame(r));
        return String((t2 - t0).toFixed(3));
      }
      case 'intersection_observer': {
        const el = document.createElement('div');
        el.style.cssText = 'position:absolute;width:1px;height:1px;top:0;left:0;';
        document.body.appendChild(el);
        const start = performance.now();
        await new Promise(resolve => {
          const obs = new IntersectionObserver(entries => {
            obs.disconnect();
            resolve();
          });
          obs.observe(el);
        });
        document.body.removeChild(el);
        return String((performance.now() - start).toFixed(3));
      }
      case 'webgl_query': {
        const start = performance.now();
        try {
          const c = document.createElement('canvas');
          const gl = c.getContext('webgl');
          if (gl) {
            const ext = gl.getExtension('WEBGL_debug_renderer_info');
            if (ext) void gl.getParameter(ext.UNMASKED_RENDERER_WEBGL);
          }
        } catch (e) { /* no WebGL */ }
        return String((performance.now() - start).toFixed(3));
      }
      case 'performance_heap': {
        if (performance.memory && performance.memory.usedJSHeapSize) {
          return String(performance.memory.usedJSHeapSize);
        }
        return '-1';
      }
      default:
        return '0';
    }
  }

  // --- MGF1 with SHA-384 ---
  async function mgf1SHA384(seed, length) {
    const out = new Uint8Array(length);
    let done = 0;
    let counter = 0;
    while (done < length) {
      const input = concatBytes(seed, uint32BE(counter));
      const chunk = await sha384(input);
      const n = Math.min(chunk.length, length - done);
      out.set(chunk.subarray(0, n), done);
      done += n;
      counter++;
    }
    return out;
  }

  // --- EMSA-PSS-ENCODE (SHA-384, MGF1-SHA384, sLen=48) ---
  const HASH_LEN = 48;
  const SALT_LEN = 48;

  async function pssEncode(msgPrime, emBits, salt) {
    const emLen = Math.ceil(emBits / 8);
    const mHash = await sha384(msgPrime);

    // M' = 0x00^8 || mHash || salt
    const mPrime = concatBytes(new Uint8Array(8), mHash, salt);
    const H = await sha384(mPrime);

    const dbLen = emLen - HASH_LEN - 1;
    const psLen = dbLen - SALT_LEN - 1;
    const db = new Uint8Array(dbLen);
    db[psLen] = 0x01;
    db.set(salt, psLen + 1);

    const dbMask = await mgf1SHA384(H, dbLen);
    for (let i = 0; i < dbLen; i++) db[i] ^= dbMask[i];

    const topBits = 8 * emLen - emBits;
    db[0] &= 0xFF >> topBits;

    const em = concatBytes(db, H, new Uint8Array([0xbc]));
    return em;
  }

  // --- RSAPBSSA Blind ---
  // Follows draft-amjad-cfrg-partially-blind-rsa-01 Section 4.2.
  async function rsapbssaBlind(serverPK, msg, info) {
    const N = bytesToBigInt(base64ToBytes(serverPK.n));
    const E = BigInt(serverPK.e);
    const modulusLen = base64ToBytes(serverPK.n).length;
    const emBits = modulusLen * 8 - 1;

    // msg' = "msg" || I2OSP(len(info), 4) || info || msg
    const infoBytes = info instanceof Uint8Array ? info : new TextEncoder().encode(info);
    const msgBytes = msg instanceof Uint8Array ? msg : new TextEncoder().encode(msg);
    const msgPrime = concatBytes(
      new TextEncoder().encode('msg'),
      uint32BE(infoBytes.length),
      infoBytes,
      msgBytes
    );

    // Generate random PSS salt
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));

    // PSS encode
    const em = await pssEncode(msgPrime, emBits, salt);
    const m = bytesToBigInt(em);

    // Derive e' = DerivePublicKey(pk, info) — must match server's HKDF derivation
    const ePrime = await derivePublicExponent(N, E, modulusLen, infoBytes);

    // Generate random blinding factor r
    const rBytes = crypto.getRandomValues(new Uint8Array(modulusLen));
    const r = bytesToBigInt(rBytes) % N;
    if (r === 0n) throw new Error('bad random r');

    const rInv = modInverse(r, N);

    // x = r^e' mod N, z = m * x mod N
    const x = modPow(r, ePrime, N);
    const z = m * x % N;

    const blindedMsg = bigIntToBytes(z, modulusLen);
    return { blindedMsg, rInv, N, modulusLen };
  }

  // Derives e' via HKDF-SHA384 — must match server's DerivePublicKey.
  // Section 4.6 of draft-amjad-cfrg-partially-blind-rsa-01.
  async function derivePublicExponent(N, E, modulusLen, infoBytes) {
    const lambdaLen = Math.floor(modulusLen / 2);
    const hkdfLen = lambdaLen + 16;

    // IKM = "key" || info || 0x00
    const ikm = concatBytes(
      new TextEncoder().encode('key'),
      infoBytes,
      new Uint8Array([0x00])
    );

    // Salt = I2OSP(N, modulusLen)
    const saltBytes = bigIntToBytes(N, modulusLen);

    // HKDF-SHA384: Extract then Expand with label "PBRSA"
    const label = new TextEncoder().encode('PBRSA');
    const prk = await hkdfExtract(ikm, saltBytes);
    const expanded = await hkdfExpand(prk, label, hkdfLen);

    expanded[0] &= 0x3F;
    expanded[lambdaLen - 1] |= 0x01;

    return bytesToBigInt(expanded.subarray(0, lambdaLen));
  }

  // HKDF-Extract: PRK = HMAC-SHA384(salt, IKM)
  async function hkdfExtract(ikm, salt) {
    const key = await crypto.subtle.importKey('raw', salt, { name: 'HMAC', hash: 'SHA-384' }, false, ['sign']);
    const prk = await crypto.subtle.sign('HMAC', key, ikm);
    return new Uint8Array(prk);
  }

  // HKDF-Expand: OKM = T(1) || T(2) || ...
  async function hkdfExpand(prk, info, length) {
    const key = await crypto.subtle.importKey('raw', prk, { name: 'HMAC', hash: 'SHA-384' }, false, ['sign']);
    const out = new Uint8Array(length);
    let t = new Uint8Array(0);
    let done = 0;
    let counter = 1;
    while (done < length) {
      const input = concatBytes(t, info, new Uint8Array([counter]));
      t = new Uint8Array(await crypto.subtle.sign('HMAC', key, input));
      const n = Math.min(t.length, length - done);
      out.set(t.subarray(0, n), done);
      done += n;
      counter++;
    }
    return out;
  }

  // Unblind: sig = blindSig * rInv mod N
  function unblind(blindSigBytes, rInv, N, modulusLen) {
    const z = bytesToBigInt(blindSigBytes);
    const s = z * rInv % N;
    return bigIntToBytes(s, modulusLen);
  }

  // Assemble token: base64( sig || metadataBytes || nonce )
  function buildToken(sig, metadataBytes, nonce) {
    return bytesToBase64(concatBytes(sig, metadataBytes, nonce));
  }

  // --- Widget renderer ---

  const TrustWidget = {
    async render(selector, options) {
      const container = document.querySelector(selector);
      if (!container) throw new Error('TrustWidget: element not found: ' + selector);

      const sitekey = container.dataset.sitekey || SITEKEY;
      const onSuccess = options.onSuccess || function () {};

      container.innerHTML = '<div class="trust-widget-inner" style="font-family:sans-serif;font-size:13px;color:#444;padding:8px 12px;border:1px solid #ddd;border-radius:4px;display:inline-block;min-width:200px;">Verifying...</div>';
      const inner = container.querySelector('.trust-widget-inner');

      try {
        // Step 1: Fetch challenge
        const ua = navigator.userAgent;
        const resp = await fetch(`${API_BASE}/challenge?sitekey=${encodeURIComponent(sitekey)}&ua=${encodeURIComponent(ua)}`);
        if (!resp.ok) throw new Error('challenge fetch failed');
        const challengeData = await resp.json();

        inner.textContent = 'Solving challenge...';

        // Step 2a: Solve HashCash
        const hashcashSolution = challengeData.hashcash
          ? await solveHashCash(challengeData.hashcash.nonce, challengeData.hashcash.difficulty_bits)
          : null;

        // Step 2b: Solve Argon2 (lazy-loads WASM)
        let argon2Result = null;
        if (challengeData.argon2) {
          inner.textContent = 'Memory-hard proof of work...';
          argon2Result = await solveArgon2(challengeData.argon2);
        }

        // Step 2c: Environment probes
        const probeResults = await runProbes(challengeData.probes || []);

        inner.textContent = 'Obtaining token...';

        // Step 3: Blind the nonce with predicted metadata as RSAPBSSA info
        const nonce = crypto.getRandomValues(new Uint8Array(8));
        const predictedMeta = base64ToBytes(challengeData.predicted_metadata);
        const { blindedMsg, rInv, N, modulusLen } = await rsapbssaBlind(
          challengeData.server_public_key,
          nonce,
          predictedMeta
        );

        const isMobile = /Mobi|Android/i.test(navigator.userAgent);

        // POST /verify
        const verifyBody = {
          challenge_id: challengeData.challenge_id,
          hashcash_solution: hashcashSolution,
          argon2_result: argon2Result,
          probe_results: probeResults,
          blinded_message: bytesToBase64(blindedMsg),
          device_class: isMobile ? 2 : 1,
        };

        const verifyResp = await fetch(`${API_BASE}/verify?sitekey=${encodeURIComponent(sitekey)}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(verifyBody),
        });
        if (!verifyResp.ok) throw new Error('verify failed: ' + await verifyResp.text());
        const verifyData = await verifyResp.json();

        // Step 4: Unblind
        const blindSigBytes = base64ToBytes(verifyData.blind_signature);
        const sig = unblind(blindSigBytes, rInv, N, modulusLen);

        // Use the actual metadata the server signed with
        const metadataBytes = base64ToBytes(verifyData.metadata);
        const token = buildToken(sig, metadataBytes, nonce);

        inner.innerHTML = '&#10003; Verified';
        inner.style.color = '#2e7d32';
        inner.style.borderColor = '#4caf50';

        onSuccess(token);
      } catch (err) {
        inner.textContent = 'Verification failed. Please reload.';
        inner.style.color = '#c62828';
        console.error('TrustWidget error:', err);
      }
    }
  };

  global.TrustWidget = TrustWidget;
})(window);
