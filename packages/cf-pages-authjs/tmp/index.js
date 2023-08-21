var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// ../../node_modules/@auth/core/lib/cookie.js
function defaultCookies(useSecureCookies) {
  const cookiePrefix = useSecureCookies ? "__Secure-" : "";
  return {
    sessionToken: {
      name: `${cookiePrefix}next-auth.session-token`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies
      }
    },
    callbackUrl: {
      name: `${cookiePrefix}next-auth.callback-url`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies
      }
    },
    csrfToken: {
      name: `${useSecureCookies ? "__Host-" : ""}next-auth.csrf-token`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies
      }
    },
    pkceCodeVerifier: {
      name: `${cookiePrefix}next-auth.pkce.code_verifier`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies,
        maxAge: 60 * 15
      }
    },
    state: {
      name: `${cookiePrefix}next-auth.state`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies,
        maxAge: 60 * 15
      }
    },
    nonce: {
      name: `${cookiePrefix}next-auth.nonce`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies
      }
    }
  };
}
var __classPrivateFieldSet, __classPrivateFieldGet, _SessionStore_instances, _SessionStore_chunks, _SessionStore_option, _SessionStore_logger, _SessionStore_chunk, _SessionStore_clean, ALLOWED_COOKIE_SIZE, ESTIMATED_EMPTY_COOKIE_SIZE, CHUNK_SIZE, SessionStore;
var init_cookie = __esm({
  "../../node_modules/@auth/core/lib/cookie.js"() {
    init_functionsRoutes_0_9412289658568613();
    __classPrivateFieldSet = function(receiver, state2, value, kind, f3) {
      if (kind === "m")
        throw new TypeError("Private method is not writable");
      if (kind === "a" && !f3)
        throw new TypeError("Private accessor was defined without a setter");
      if (typeof state2 === "function" ? receiver !== state2 || !f3 : !state2.has(receiver))
        throw new TypeError("Cannot write private member to an object whose class did not declare it");
      return kind === "a" ? f3.call(receiver, value) : f3 ? f3.value = value : state2.set(receiver, value), value;
    };
    __classPrivateFieldGet = function(receiver, state2, kind, f3) {
      if (kind === "a" && !f3)
        throw new TypeError("Private accessor was defined without a getter");
      if (typeof state2 === "function" ? receiver !== state2 || !f3 : !state2.has(receiver))
        throw new TypeError("Cannot read private member from an object whose class did not declare it");
      return kind === "m" ? f3 : kind === "a" ? f3.call(receiver) : f3 ? f3.value : state2.get(receiver);
    };
    ALLOWED_COOKIE_SIZE = 4096;
    ESTIMATED_EMPTY_COOKIE_SIZE = 163;
    CHUNK_SIZE = ALLOWED_COOKIE_SIZE - ESTIMATED_EMPTY_COOKIE_SIZE;
    SessionStore = class {
      constructor(option, req, logger2) {
        _SessionStore_instances.add(this);
        _SessionStore_chunks.set(this, {});
        _SessionStore_option.set(this, void 0);
        _SessionStore_logger.set(this, void 0);
        __classPrivateFieldSet(this, _SessionStore_logger, logger2, "f");
        __classPrivateFieldSet(this, _SessionStore_option, option, "f");
        const { cookies } = req;
        const { name: cookieName } = option;
        if (typeof cookies?.getAll === "function") {
          for (const { name, value } of cookies.getAll()) {
            if (name.startsWith(cookieName)) {
              __classPrivateFieldGet(this, _SessionStore_chunks, "f")[name] = value;
            }
          }
        } else if (cookies instanceof Map) {
          for (const name of cookies.keys()) {
            if (name.startsWith(cookieName))
              __classPrivateFieldGet(this, _SessionStore_chunks, "f")[name] = cookies.get(name);
          }
        } else {
          for (const name in cookies) {
            if (name.startsWith(cookieName))
              __classPrivateFieldGet(this, _SessionStore_chunks, "f")[name] = cookies[name];
          }
        }
      }
      get value() {
        const sortedKeys = Object.keys(__classPrivateFieldGet(this, _SessionStore_chunks, "f")).sort((a3, b3) => {
          const aSuffix = parseInt(a3.split(".")[1] || "0");
          const bSuffix = parseInt(b3.split(".")[1] || "0");
          return aSuffix - bSuffix;
        });
        return sortedKeys.map((key) => __classPrivateFieldGet(this, _SessionStore_chunks, "f")[key]).join("");
      }
      chunk(value, options) {
        const cookies = __classPrivateFieldGet(this, _SessionStore_instances, "m", _SessionStore_clean).call(this);
        const chunked = __classPrivateFieldGet(this, _SessionStore_instances, "m", _SessionStore_chunk).call(this, {
          name: __classPrivateFieldGet(this, _SessionStore_option, "f").name,
          value,
          options: { ...__classPrivateFieldGet(this, _SessionStore_option, "f").options, ...options }
        });
        for (const chunk of chunked) {
          cookies[chunk.name] = chunk;
        }
        return Object.values(cookies);
      }
      clean() {
        return Object.values(__classPrivateFieldGet(this, _SessionStore_instances, "m", _SessionStore_clean).call(this));
      }
    };
    _SessionStore_chunks = /* @__PURE__ */ new WeakMap(), _SessionStore_option = /* @__PURE__ */ new WeakMap(), _SessionStore_logger = /* @__PURE__ */ new WeakMap(), _SessionStore_instances = /* @__PURE__ */ new WeakSet(), _SessionStore_chunk = function _SessionStore_chunk2(cookie) {
      const chunkCount = Math.ceil(cookie.value.length / CHUNK_SIZE);
      if (chunkCount === 1) {
        __classPrivateFieldGet(this, _SessionStore_chunks, "f")[cookie.name] = cookie.value;
        return [cookie];
      }
      const cookies = [];
      for (let i3 = 0; i3 < chunkCount; i3++) {
        const name = `${cookie.name}.${i3}`;
        const value = cookie.value.substr(i3 * CHUNK_SIZE, CHUNK_SIZE);
        cookies.push({ ...cookie, name, value });
        __classPrivateFieldGet(this, _SessionStore_chunks, "f")[name] = value;
      }
      __classPrivateFieldGet(this, _SessionStore_logger, "f").debug("CHUNKING_SESSION_COOKIE", {
        message: `Session cookie exceeds allowed ${ALLOWED_COOKIE_SIZE} bytes.`,
        emptyCookieSize: ESTIMATED_EMPTY_COOKIE_SIZE,
        valueSize: cookie.value.length,
        chunks: cookies.map((c3) => c3.value.length + ESTIMATED_EMPTY_COOKIE_SIZE)
      });
      return cookies;
    }, _SessionStore_clean = function _SessionStore_clean2() {
      const cleanedChunks = {};
      for (const name in __classPrivateFieldGet(this, _SessionStore_chunks, "f")) {
        delete __classPrivateFieldGet(this, _SessionStore_chunks, "f")?.[name];
        cleanedChunks[name] = {
          name,
          value: "",
          options: { ...__classPrivateFieldGet(this, _SessionStore_option, "f").options, maxAge: 0 }
        };
      }
      return cleanedChunks;
    };
  }
});

// ../../node_modules/@auth/core/errors.js
var AuthError, AdapterError, AuthorizedCallbackError, CallbackRouteError, ErrorPageLoop, EventError, InvalidCallbackUrl, InvalidEndpoints, InvalidCheck, JWTSessionError, MissingAdapter, MissingAdapterMethods, MissingAuthorize, MissingSecret, OAuthAccountNotLinked, OAuthCallbackError, OAuthProfileParseError, SessionTokenError, SignInError, SignOutError, UnknownAction, UnsupportedStrategy, UntrustedHost, Verification;
var init_errors = __esm({
  "../../node_modules/@auth/core/errors.js"() {
    init_functionsRoutes_0_9412289658568613();
    AuthError = class extends Error {
      constructor(message2, cause) {
        if (message2 instanceof Error) {
          super(void 0, {
            cause: { err: message2, ...message2.cause, ...cause }
          });
        } else if (typeof message2 === "string") {
          if (cause instanceof Error) {
            cause = { err: cause, ...cause.cause };
          }
          super(message2, cause);
        } else {
          super(void 0, message2);
        }
        Error.captureStackTrace?.(this, this.constructor);
        this.name = message2 instanceof AuthError ? message2.name : this.constructor.name;
      }
    };
    AdapterError = class extends AuthError {
    };
    AuthorizedCallbackError = class extends AuthError {
    };
    CallbackRouteError = class extends AuthError {
    };
    ErrorPageLoop = class extends AuthError {
    };
    EventError = class extends AuthError {
    };
    InvalidCallbackUrl = class extends AuthError {
    };
    InvalidEndpoints = class extends AuthError {
    };
    InvalidCheck = class extends AuthError {
    };
    JWTSessionError = class extends AuthError {
    };
    MissingAdapter = class extends AuthError {
    };
    MissingAdapterMethods = class extends AuthError {
    };
    MissingAuthorize = class extends AuthError {
    };
    MissingSecret = class extends AuthError {
    };
    OAuthAccountNotLinked = class extends AuthError {
    };
    OAuthCallbackError = class extends AuthError {
    };
    OAuthProfileParseError = class extends AuthError {
    };
    SessionTokenError = class extends AuthError {
    };
    SignInError = class extends AuthError {
    };
    SignOutError = class extends AuthError {
    };
    UnknownAction = class extends AuthError {
    };
    UnsupportedStrategy = class extends AuthError {
    };
    UntrustedHost = class extends AuthError {
    };
    Verification = class extends AuthError {
    };
  }
});

// ../../node_modules/@auth/core/lib/assert.js
function isValidHttpUrl(url, baseUrl) {
  try {
    return /^https?:/.test(new URL(url, url.startsWith("/") ? baseUrl : void 0).protocol);
  } catch {
    return false;
  }
}
function assertConfig(request, options) {
  const { url } = request;
  const warnings = [];
  if (!warned && options.debug)
    warnings.push("debug-enabled");
  if (!options.trustHost) {
    return new UntrustedHost(`Host must be trusted. URL was: ${request.url}`);
  }
  if (!options.secret) {
    return new MissingSecret("Please define a `secret`.");
  }
  const callbackUrlParam = request.query?.callbackUrl;
  if (callbackUrlParam && !isValidHttpUrl(callbackUrlParam, url.origin)) {
    return new InvalidCallbackUrl(`Invalid callback URL. Received: ${callbackUrlParam}`);
  }
  const { callbackUrl: defaultCallbackUrl } = defaultCookies(options.useSecureCookies ?? url.protocol === "https://");
  const callbackUrlCookie = request.cookies?.[options.cookies?.callbackUrl?.name ?? defaultCallbackUrl.name];
  if (callbackUrlCookie && !isValidHttpUrl(callbackUrlCookie, url.origin)) {
    return new InvalidCallbackUrl(`Invalid callback URL. Received: ${callbackUrlCookie}`);
  }
  for (const p3 of options.providers) {
    const provider = typeof p3 === "function" ? p3() : p3;
    if ((provider.type === "oauth" || provider.type === "oidc") && !(provider.issuer ?? provider.options?.issuer)) {
      const { authorization: a3, token: t2, userinfo: u3 } = provider;
      let key;
      if (typeof a3 !== "string" && !a3?.url)
        key = "authorization";
      else if (typeof t2 !== "string" && !t2?.url)
        key = "token";
      else if (typeof u3 !== "string" && !u3?.url)
        key = "userinfo";
      if (key) {
        return new InvalidEndpoints(`Provider "${provider.id}" is missing both \`issuer\` and \`${key}\` endpoint config. At least one of them is required.`);
      }
    }
    if (provider.type === "credentials")
      hasCredentials = true;
    else if (provider.type === "email")
      hasEmail = true;
  }
  if (hasCredentials) {
    const dbStrategy = options.session?.strategy === "database";
    const onlyCredentials = !options.providers.some((p3) => (typeof p3 === "function" ? p3() : p3).type !== "credentials");
    if (dbStrategy && onlyCredentials) {
      return new UnsupportedStrategy("Signin in with credentials only supported if JWT strategy is enabled");
    }
    const credentialsNoAuthorize = options.providers.some((p3) => {
      const provider = typeof p3 === "function" ? p3() : p3;
      return provider.type === "credentials" && !provider.authorize;
    });
    if (credentialsNoAuthorize) {
      return new MissingAuthorize("Must define an authorize() handler to use credentials authentication provider");
    }
  }
  const { adapter, session: session2 } = options;
  if (hasEmail || session2?.strategy === "database" || !session2?.strategy && adapter) {
    let methods;
    if (hasEmail) {
      if (!adapter)
        return new MissingAdapter("Email login requires an adapter.");
      methods = emailMethods;
    } else {
      if (!adapter)
        return new MissingAdapter("Database session requires an adapter.");
      methods = sessionMethods;
    }
    const missing = methods.filter((m3) => !adapter[m3]);
    if (missing.length) {
      return new MissingAdapterMethods(`Required adapter methods were missing: ${missing.join(", ")}`);
    }
  }
  if (!warned)
    warned = true;
  return warnings;
}
var warned, hasCredentials, hasEmail, emailMethods, sessionMethods;
var init_assert = __esm({
  "../../node_modules/@auth/core/lib/assert.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_cookie();
    init_errors();
    warned = false;
    hasCredentials = false;
    hasEmail = false;
    emailMethods = [
      "createVerificationToken",
      "useVerificationToken",
      "getUserByEmail"
    ];
    sessionMethods = [
      "createUser",
      "getUser",
      "getUserByEmail",
      "getUserByAccount",
      "updateUser",
      "linkAccount",
      "createSession",
      "getSessionAndUser",
      "updateSession",
      "deleteSession"
    ];
  }
});

// ../../node_modules/@panva/hkdf/dist/web/runtime/hkdf.js
var getGlobal, hkdf_default;
var init_hkdf = __esm({
  "../../node_modules/@panva/hkdf/dist/web/runtime/hkdf.js"() {
    init_functionsRoutes_0_9412289658568613();
    getGlobal = () => {
      if (typeof globalThis !== "undefined")
        return globalThis;
      if (typeof self !== "undefined")
        return self;
      if (typeof window !== "undefined")
        return window;
      throw new Error("unable to locate global object");
    };
    hkdf_default = async (digest2, ikm, salt, info, keylen) => {
      const { crypto: { subtle } } = getGlobal();
      return new Uint8Array(await subtle.deriveBits({
        name: "HKDF",
        hash: `SHA-${digest2.substr(3)}`,
        salt,
        info
      }, await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]), keylen << 3));
    };
  }
});

// ../../node_modules/@panva/hkdf/dist/web/index.js
function normalizeDigest(digest2) {
  switch (digest2) {
    case "sha256":
    case "sha384":
    case "sha512":
    case "sha1":
      return digest2;
    default:
      throw new TypeError('unsupported "digest" value');
  }
}
function normalizeUint8Array(input, label) {
  if (typeof input === "string")
    return new TextEncoder().encode(input);
  if (!(input instanceof Uint8Array))
    throw new TypeError(`"${label}"" must be an instance of Uint8Array or a string`);
  return input;
}
function normalizeIkm(input) {
  const ikm = normalizeUint8Array(input, "ikm");
  if (!ikm.byteLength)
    throw new TypeError(`"ikm" must be at least one byte in length`);
  return ikm;
}
function normalizeInfo(input) {
  const info = normalizeUint8Array(input, "info");
  if (info.byteLength > 1024) {
    throw TypeError('"info" must not contain more than 1024 bytes');
  }
  return info;
}
function normalizeKeylen(input, digest2) {
  if (typeof input !== "number" || !Number.isInteger(input) || input < 1) {
    throw new TypeError('"keylen" must be a positive integer');
  }
  const hashlen = parseInt(digest2.substr(3), 10) >> 3 || 20;
  if (input > 255 * hashlen) {
    throw new TypeError('"keylen" too large');
  }
  return input;
}
async function hkdf(digest2, ikm, salt, info, keylen) {
  return hkdf_default(normalizeDigest(digest2), normalizeIkm(ikm), normalizeUint8Array(salt, "salt"), normalizeInfo(info), normalizeKeylen(keylen, digest2));
}
var init_web = __esm({
  "../../node_modules/@panva/hkdf/dist/web/index.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_hkdf();
  }
});

// ../../node_modules/jose/dist/browser/runtime/webcrypto.js
var webcrypto_default, isCryptoKey;
var init_webcrypto = __esm({
  "../../node_modules/jose/dist/browser/runtime/webcrypto.js"() {
    init_functionsRoutes_0_9412289658568613();
    webcrypto_default = crypto;
    isCryptoKey = (key) => key instanceof CryptoKey;
  }
});

// ../../node_modules/jose/dist/browser/runtime/digest.js
var digest, digest_default;
var init_digest = __esm({
  "../../node_modules/jose/dist/browser/runtime/digest.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_webcrypto();
    digest = async (algorithm, data) => {
      const subtleDigest = `SHA-${algorithm.slice(-3)}`;
      return new Uint8Array(await webcrypto_default.subtle.digest(subtleDigest, data));
    };
    digest_default = digest;
  }
});

// ../../node_modules/jose/dist/browser/lib/buffer_utils.js
function concat(...buffers) {
  const size = buffers.reduce((acc, { length }) => acc + length, 0);
  const buf2 = new Uint8Array(size);
  let i3 = 0;
  buffers.forEach((buffer) => {
    buf2.set(buffer, i3);
    i3 += buffer.length;
  });
  return buf2;
}
function p2s(alg, p2sInput) {
  return concat(encoder.encode(alg), new Uint8Array([0]), p2sInput);
}
function writeUInt32BE(buf2, value, offset) {
  if (value < 0 || value >= MAX_INT32) {
    throw new RangeError(`value must be >= 0 and <= ${MAX_INT32 - 1}. Received ${value}`);
  }
  buf2.set([value >>> 24, value >>> 16, value >>> 8, value & 255], offset);
}
function uint64be(value) {
  const high = Math.floor(value / MAX_INT32);
  const low = value % MAX_INT32;
  const buf2 = new Uint8Array(8);
  writeUInt32BE(buf2, high, 0);
  writeUInt32BE(buf2, low, 4);
  return buf2;
}
function uint32be(value) {
  const buf2 = new Uint8Array(4);
  writeUInt32BE(buf2, value);
  return buf2;
}
function lengthAndInput(input) {
  return concat(uint32be(input.length), input);
}
async function concatKdf(secret, bits, value) {
  const iterations = Math.ceil((bits >> 3) / 32);
  const res = new Uint8Array(iterations * 32);
  for (let iter = 0; iter < iterations; iter++) {
    const buf2 = new Uint8Array(4 + secret.length + value.length);
    buf2.set(uint32be(iter + 1));
    buf2.set(secret, 4);
    buf2.set(value, 4 + secret.length);
    res.set(await digest_default("sha256", buf2), iter * 32);
  }
  return res.slice(0, bits >> 3);
}
var encoder, decoder, MAX_INT32;
var init_buffer_utils = __esm({
  "../../node_modules/jose/dist/browser/lib/buffer_utils.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_digest();
    encoder = new TextEncoder();
    decoder = new TextDecoder();
    MAX_INT32 = 2 ** 32;
  }
});

// ../../node_modules/jose/dist/browser/runtime/base64url.js
var encodeBase64, encode, decodeBase64, decode;
var init_base64url = __esm({
  "../../node_modules/jose/dist/browser/runtime/base64url.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_buffer_utils();
    encodeBase64 = (input) => {
      let unencoded = input;
      if (typeof unencoded === "string") {
        unencoded = encoder.encode(unencoded);
      }
      const CHUNK_SIZE3 = 32768;
      const arr = [];
      for (let i3 = 0; i3 < unencoded.length; i3 += CHUNK_SIZE3) {
        arr.push(String.fromCharCode.apply(null, unencoded.subarray(i3, i3 + CHUNK_SIZE3)));
      }
      return btoa(arr.join(""));
    };
    encode = (input) => {
      return encodeBase64(input).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
    };
    decodeBase64 = (encoded) => {
      const binary = atob(encoded);
      const bytes = new Uint8Array(binary.length);
      for (let i3 = 0; i3 < binary.length; i3++) {
        bytes[i3] = binary.charCodeAt(i3);
      }
      return bytes;
    };
    decode = (input) => {
      let encoded = input;
      if (encoded instanceof Uint8Array) {
        encoded = decoder.decode(encoded);
      }
      encoded = encoded.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "");
      try {
        return decodeBase64(encoded);
      } catch (_a) {
        throw new TypeError("The input to be decoded is not correctly encoded.");
      }
    };
  }
});

// ../../node_modules/jose/dist/browser/util/errors.js
var JOSEError, JWTClaimValidationFailed, JWTExpired, JOSEAlgNotAllowed, JOSENotSupported, JWEDecryptionFailed, JWEInvalid, JWTInvalid;
var init_errors2 = __esm({
  "../../node_modules/jose/dist/browser/util/errors.js"() {
    init_functionsRoutes_0_9412289658568613();
    JOSEError = class extends Error {
      static get code() {
        return "ERR_JOSE_GENERIC";
      }
      constructor(message2) {
        var _a;
        super(message2);
        this.code = "ERR_JOSE_GENERIC";
        this.name = this.constructor.name;
        (_a = Error.captureStackTrace) === null || _a === void 0 ? void 0 : _a.call(Error, this, this.constructor);
      }
    };
    JWTClaimValidationFailed = class extends JOSEError {
      static get code() {
        return "ERR_JWT_CLAIM_VALIDATION_FAILED";
      }
      constructor(message2, claim = "unspecified", reason = "unspecified") {
        super(message2);
        this.code = "ERR_JWT_CLAIM_VALIDATION_FAILED";
        this.claim = claim;
        this.reason = reason;
      }
    };
    JWTExpired = class extends JOSEError {
      static get code() {
        return "ERR_JWT_EXPIRED";
      }
      constructor(message2, claim = "unspecified", reason = "unspecified") {
        super(message2);
        this.code = "ERR_JWT_EXPIRED";
        this.claim = claim;
        this.reason = reason;
      }
    };
    JOSEAlgNotAllowed = class extends JOSEError {
      constructor() {
        super(...arguments);
        this.code = "ERR_JOSE_ALG_NOT_ALLOWED";
      }
      static get code() {
        return "ERR_JOSE_ALG_NOT_ALLOWED";
      }
    };
    JOSENotSupported = class extends JOSEError {
      constructor() {
        super(...arguments);
        this.code = "ERR_JOSE_NOT_SUPPORTED";
      }
      static get code() {
        return "ERR_JOSE_NOT_SUPPORTED";
      }
    };
    JWEDecryptionFailed = class extends JOSEError {
      constructor() {
        super(...arguments);
        this.code = "ERR_JWE_DECRYPTION_FAILED";
        this.message = "decryption operation failed";
      }
      static get code() {
        return "ERR_JWE_DECRYPTION_FAILED";
      }
    };
    JWEInvalid = class extends JOSEError {
      constructor() {
        super(...arguments);
        this.code = "ERR_JWE_INVALID";
      }
      static get code() {
        return "ERR_JWE_INVALID";
      }
    };
    JWTInvalid = class extends JOSEError {
      constructor() {
        super(...arguments);
        this.code = "ERR_JWT_INVALID";
      }
      static get code() {
        return "ERR_JWT_INVALID";
      }
    };
  }
});

// ../../node_modules/jose/dist/browser/runtime/random.js
var random_default;
var init_random = __esm({
  "../../node_modules/jose/dist/browser/runtime/random.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_webcrypto();
    random_default = webcrypto_default.getRandomValues.bind(webcrypto_default);
  }
});

// ../../node_modules/jose/dist/browser/lib/iv.js
function bitLength(alg) {
  switch (alg) {
    case "A128GCM":
    case "A128GCMKW":
    case "A192GCM":
    case "A192GCMKW":
    case "A256GCM":
    case "A256GCMKW":
      return 96;
    case "A128CBC-HS256":
    case "A192CBC-HS384":
    case "A256CBC-HS512":
      return 128;
    default:
      throw new JOSENotSupported(`Unsupported JWE Algorithm: ${alg}`);
  }
}
var iv_default;
var init_iv = __esm({
  "../../node_modules/jose/dist/browser/lib/iv.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_errors2();
    init_random();
    iv_default = (alg) => random_default(new Uint8Array(bitLength(alg) >> 3));
  }
});

// ../../node_modules/jose/dist/browser/lib/check_iv_length.js
var checkIvLength, check_iv_length_default;
var init_check_iv_length = __esm({
  "../../node_modules/jose/dist/browser/lib/check_iv_length.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_errors2();
    init_iv();
    checkIvLength = (enc, iv) => {
      if (iv.length << 3 !== bitLength(enc)) {
        throw new JWEInvalid("Invalid Initialization Vector length");
      }
    };
    check_iv_length_default = checkIvLength;
  }
});

// ../../node_modules/jose/dist/browser/runtime/check_cek_length.js
var checkCekLength, check_cek_length_default;
var init_check_cek_length = __esm({
  "../../node_modules/jose/dist/browser/runtime/check_cek_length.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_errors2();
    checkCekLength = (cek, expected) => {
      const actual = cek.byteLength << 3;
      if (actual !== expected) {
        throw new JWEInvalid(`Invalid Content Encryption Key length. Expected ${expected} bits, got ${actual} bits`);
      }
    };
    check_cek_length_default = checkCekLength;
  }
});

// ../../node_modules/jose/dist/browser/runtime/timing_safe_equal.js
var timingSafeEqual, timing_safe_equal_default;
var init_timing_safe_equal = __esm({
  "../../node_modules/jose/dist/browser/runtime/timing_safe_equal.js"() {
    init_functionsRoutes_0_9412289658568613();
    timingSafeEqual = (a3, b3) => {
      if (!(a3 instanceof Uint8Array)) {
        throw new TypeError("First argument must be a buffer");
      }
      if (!(b3 instanceof Uint8Array)) {
        throw new TypeError("Second argument must be a buffer");
      }
      if (a3.length !== b3.length) {
        throw new TypeError("Input buffers must have the same length");
      }
      const len = a3.length;
      let out = 0;
      let i3 = -1;
      while (++i3 < len) {
        out |= a3[i3] ^ b3[i3];
      }
      return out === 0;
    };
    timing_safe_equal_default = timingSafeEqual;
  }
});

// ../../node_modules/jose/dist/browser/lib/crypto_key.js
function unusable(name, prop = "algorithm.name") {
  return new TypeError(`CryptoKey does not support this operation, its ${prop} must be ${name}`);
}
function isAlgorithm(algorithm, name) {
  return algorithm.name === name;
}
function getHashLength(hash) {
  return parseInt(hash.name.slice(4), 10);
}
function checkUsage(key, usages) {
  if (usages.length && !usages.some((expected) => key.usages.includes(expected))) {
    let msg = "CryptoKey does not support this operation, its usages must include ";
    if (usages.length > 2) {
      const last = usages.pop();
      msg += `one of ${usages.join(", ")}, or ${last}.`;
    } else if (usages.length === 2) {
      msg += `one of ${usages[0]} or ${usages[1]}.`;
    } else {
      msg += `${usages[0]}.`;
    }
    throw new TypeError(msg);
  }
}
function checkEncCryptoKey(key, alg, ...usages) {
  switch (alg) {
    case "A128GCM":
    case "A192GCM":
    case "A256GCM": {
      if (!isAlgorithm(key.algorithm, "AES-GCM"))
        throw unusable("AES-GCM");
      const expected = parseInt(alg.slice(1, 4), 10);
      const actual = key.algorithm.length;
      if (actual !== expected)
        throw unusable(expected, "algorithm.length");
      break;
    }
    case "A128KW":
    case "A192KW":
    case "A256KW": {
      if (!isAlgorithm(key.algorithm, "AES-KW"))
        throw unusable("AES-KW");
      const expected = parseInt(alg.slice(1, 4), 10);
      const actual = key.algorithm.length;
      if (actual !== expected)
        throw unusable(expected, "algorithm.length");
      break;
    }
    case "ECDH": {
      switch (key.algorithm.name) {
        case "ECDH":
        case "X25519":
        case "X448":
          break;
        default:
          throw unusable("ECDH, X25519, or X448");
      }
      break;
    }
    case "PBES2-HS256+A128KW":
    case "PBES2-HS384+A192KW":
    case "PBES2-HS512+A256KW":
      if (!isAlgorithm(key.algorithm, "PBKDF2"))
        throw unusable("PBKDF2");
      break;
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      if (!isAlgorithm(key.algorithm, "RSA-OAEP"))
        throw unusable("RSA-OAEP");
      const expected = parseInt(alg.slice(9), 10) || 1;
      const actual = getHashLength(key.algorithm.hash);
      if (actual !== expected)
        throw unusable(`SHA-${expected}`, "algorithm.hash");
      break;
    }
    default:
      throw new TypeError("CryptoKey does not support this operation");
  }
  checkUsage(key, usages);
}
var init_crypto_key = __esm({
  "../../node_modules/jose/dist/browser/lib/crypto_key.js"() {
    init_functionsRoutes_0_9412289658568613();
  }
});

// ../../node_modules/jose/dist/browser/lib/invalid_key_input.js
function message(msg, actual, ...types2) {
  if (types2.length > 2) {
    const last = types2.pop();
    msg += `one of type ${types2.join(", ")}, or ${last}.`;
  } else if (types2.length === 2) {
    msg += `one of type ${types2[0]} or ${types2[1]}.`;
  } else {
    msg += `of type ${types2[0]}.`;
  }
  if (actual == null) {
    msg += ` Received ${actual}`;
  } else if (typeof actual === "function" && actual.name) {
    msg += ` Received function ${actual.name}`;
  } else if (typeof actual === "object" && actual != null) {
    if (actual.constructor && actual.constructor.name) {
      msg += ` Received an instance of ${actual.constructor.name}`;
    }
  }
  return msg;
}
function withAlg(alg, actual, ...types2) {
  return message(`Key for the ${alg} algorithm must be `, actual, ...types2);
}
var invalid_key_input_default;
var init_invalid_key_input = __esm({
  "../../node_modules/jose/dist/browser/lib/invalid_key_input.js"() {
    init_functionsRoutes_0_9412289658568613();
    invalid_key_input_default = (actual, ...types2) => {
      return message("Key must be ", actual, ...types2);
    };
  }
});

// ../../node_modules/jose/dist/browser/runtime/is_key_like.js
var is_key_like_default, types;
var init_is_key_like = __esm({
  "../../node_modules/jose/dist/browser/runtime/is_key_like.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_webcrypto();
    is_key_like_default = (key) => {
      return isCryptoKey(key);
    };
    types = ["CryptoKey"];
  }
});

// ../../node_modules/jose/dist/browser/runtime/decrypt.js
async function cbcDecrypt(enc, cek, ciphertext, iv, tag, aad) {
  if (!(cek instanceof Uint8Array)) {
    throw new TypeError(invalid_key_input_default(cek, "Uint8Array"));
  }
  const keySize = parseInt(enc.slice(1, 4), 10);
  const encKey = await webcrypto_default.subtle.importKey("raw", cek.subarray(keySize >> 3), "AES-CBC", false, ["decrypt"]);
  const macKey = await webcrypto_default.subtle.importKey("raw", cek.subarray(0, keySize >> 3), {
    hash: `SHA-${keySize << 1}`,
    name: "HMAC"
  }, false, ["sign"]);
  const macData = concat(aad, iv, ciphertext, uint64be(aad.length << 3));
  const expectedTag = new Uint8Array((await webcrypto_default.subtle.sign("HMAC", macKey, macData)).slice(0, keySize >> 3));
  let macCheckPassed;
  try {
    macCheckPassed = timing_safe_equal_default(tag, expectedTag);
  } catch (_a) {
  }
  if (!macCheckPassed) {
    throw new JWEDecryptionFailed();
  }
  let plaintext;
  try {
    plaintext = new Uint8Array(await webcrypto_default.subtle.decrypt({ iv, name: "AES-CBC" }, encKey, ciphertext));
  } catch (_b) {
  }
  if (!plaintext) {
    throw new JWEDecryptionFailed();
  }
  return plaintext;
}
async function gcmDecrypt(enc, cek, ciphertext, iv, tag, aad) {
  let encKey;
  if (cek instanceof Uint8Array) {
    encKey = await webcrypto_default.subtle.importKey("raw", cek, "AES-GCM", false, ["decrypt"]);
  } else {
    checkEncCryptoKey(cek, enc, "decrypt");
    encKey = cek;
  }
  try {
    return new Uint8Array(await webcrypto_default.subtle.decrypt({
      additionalData: aad,
      iv,
      name: "AES-GCM",
      tagLength: 128
    }, encKey, concat(ciphertext, tag)));
  } catch (_a) {
    throw new JWEDecryptionFailed();
  }
}
var decrypt, decrypt_default;
var init_decrypt = __esm({
  "../../node_modules/jose/dist/browser/runtime/decrypt.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_buffer_utils();
    init_check_iv_length();
    init_check_cek_length();
    init_timing_safe_equal();
    init_errors2();
    init_webcrypto();
    init_crypto_key();
    init_invalid_key_input();
    init_is_key_like();
    decrypt = async (enc, cek, ciphertext, iv, tag, aad) => {
      if (!isCryptoKey(cek) && !(cek instanceof Uint8Array)) {
        throw new TypeError(invalid_key_input_default(cek, ...types, "Uint8Array"));
      }
      check_iv_length_default(enc, iv);
      switch (enc) {
        case "A128CBC-HS256":
        case "A192CBC-HS384":
        case "A256CBC-HS512":
          if (cek instanceof Uint8Array)
            check_cek_length_default(cek, parseInt(enc.slice(-3), 10));
          return cbcDecrypt(enc, cek, ciphertext, iv, tag, aad);
        case "A128GCM":
        case "A192GCM":
        case "A256GCM":
          if (cek instanceof Uint8Array)
            check_cek_length_default(cek, parseInt(enc.slice(1, 4), 10));
          return gcmDecrypt(enc, cek, ciphertext, iv, tag, aad);
        default:
          throw new JOSENotSupported("Unsupported JWE Content Encryption Algorithm");
      }
    };
    decrypt_default = decrypt;
  }
});

// ../../node_modules/jose/dist/browser/runtime/zlib.js
var inflate, deflate;
var init_zlib = __esm({
  "../../node_modules/jose/dist/browser/runtime/zlib.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_errors2();
    inflate = async () => {
      throw new JOSENotSupported('JWE "zip" (Compression Algorithm) Header Parameter is not supported by your javascript runtime. You need to use the `inflateRaw` decrypt option to provide Inflate Raw implementation.');
    };
    deflate = async () => {
      throw new JOSENotSupported('JWE "zip" (Compression Algorithm) Header Parameter is not supported by your javascript runtime. You need to use the `deflateRaw` encrypt option to provide Deflate Raw implementation.');
    };
  }
});

// ../../node_modules/jose/dist/browser/lib/is_disjoint.js
var isDisjoint, is_disjoint_default;
var init_is_disjoint = __esm({
  "../../node_modules/jose/dist/browser/lib/is_disjoint.js"() {
    init_functionsRoutes_0_9412289658568613();
    isDisjoint = (...headers) => {
      const sources = headers.filter(Boolean);
      if (sources.length === 0 || sources.length === 1) {
        return true;
      }
      let acc;
      for (const header of sources) {
        const parameters = Object.keys(header);
        if (!acc || acc.size === 0) {
          acc = new Set(parameters);
          continue;
        }
        for (const parameter of parameters) {
          if (acc.has(parameter)) {
            return false;
          }
          acc.add(parameter);
        }
      }
      return true;
    };
    is_disjoint_default = isDisjoint;
  }
});

// ../../node_modules/jose/dist/browser/lib/is_object.js
function isObjectLike(value) {
  return typeof value === "object" && value !== null;
}
function isObject(input) {
  if (!isObjectLike(input) || Object.prototype.toString.call(input) !== "[object Object]") {
    return false;
  }
  if (Object.getPrototypeOf(input) === null) {
    return true;
  }
  let proto = input;
  while (Object.getPrototypeOf(proto) !== null) {
    proto = Object.getPrototypeOf(proto);
  }
  return Object.getPrototypeOf(input) === proto;
}
var init_is_object = __esm({
  "../../node_modules/jose/dist/browser/lib/is_object.js"() {
    init_functionsRoutes_0_9412289658568613();
  }
});

// ../../node_modules/jose/dist/browser/runtime/bogus.js
var bogusWebCrypto, bogus_default;
var init_bogus = __esm({
  "../../node_modules/jose/dist/browser/runtime/bogus.js"() {
    init_functionsRoutes_0_9412289658568613();
    bogusWebCrypto = [
      { hash: "SHA-256", name: "HMAC" },
      true,
      ["sign"]
    ];
    bogus_default = bogusWebCrypto;
  }
});

// ../../node_modules/jose/dist/browser/runtime/aeskw.js
function checkKeySize(key, alg) {
  if (key.algorithm.length !== parseInt(alg.slice(1, 4), 10)) {
    throw new TypeError(`Invalid key size for alg: ${alg}`);
  }
}
function getCryptoKey(key, alg, usage) {
  if (isCryptoKey(key)) {
    checkEncCryptoKey(key, alg, usage);
    return key;
  }
  if (key instanceof Uint8Array) {
    return webcrypto_default.subtle.importKey("raw", key, "AES-KW", true, [usage]);
  }
  throw new TypeError(invalid_key_input_default(key, ...types, "Uint8Array"));
}
var wrap, unwrap;
var init_aeskw = __esm({
  "../../node_modules/jose/dist/browser/runtime/aeskw.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_bogus();
    init_webcrypto();
    init_crypto_key();
    init_invalid_key_input();
    init_is_key_like();
    wrap = async (alg, key, cek) => {
      const cryptoKey = await getCryptoKey(key, alg, "wrapKey");
      checkKeySize(cryptoKey, alg);
      const cryptoKeyCek = await webcrypto_default.subtle.importKey("raw", cek, ...bogus_default);
      return new Uint8Array(await webcrypto_default.subtle.wrapKey("raw", cryptoKeyCek, cryptoKey, "AES-KW"));
    };
    unwrap = async (alg, key, encryptedKey) => {
      const cryptoKey = await getCryptoKey(key, alg, "unwrapKey");
      checkKeySize(cryptoKey, alg);
      const cryptoKeyCek = await webcrypto_default.subtle.unwrapKey("raw", encryptedKey, cryptoKey, "AES-KW", ...bogus_default);
      return new Uint8Array(await webcrypto_default.subtle.exportKey("raw", cryptoKeyCek));
    };
  }
});

// ../../node_modules/jose/dist/browser/runtime/ecdhes.js
async function deriveKey(publicKey, privateKey, algorithm, keyLength, apu = new Uint8Array(0), apv = new Uint8Array(0)) {
  if (!isCryptoKey(publicKey)) {
    throw new TypeError(invalid_key_input_default(publicKey, ...types));
  }
  checkEncCryptoKey(publicKey, "ECDH");
  if (!isCryptoKey(privateKey)) {
    throw new TypeError(invalid_key_input_default(privateKey, ...types));
  }
  checkEncCryptoKey(privateKey, "ECDH", "deriveBits");
  const value = concat(lengthAndInput(encoder.encode(algorithm)), lengthAndInput(apu), lengthAndInput(apv), uint32be(keyLength));
  let length;
  if (publicKey.algorithm.name === "X25519") {
    length = 256;
  } else if (publicKey.algorithm.name === "X448") {
    length = 448;
  } else {
    length = Math.ceil(parseInt(publicKey.algorithm.namedCurve.substr(-3), 10) / 8) << 3;
  }
  const sharedSecret = new Uint8Array(await webcrypto_default.subtle.deriveBits({
    name: publicKey.algorithm.name,
    public: publicKey
  }, privateKey, length));
  return concatKdf(sharedSecret, keyLength, value);
}
async function generateEpk(key) {
  if (!isCryptoKey(key)) {
    throw new TypeError(invalid_key_input_default(key, ...types));
  }
  return webcrypto_default.subtle.generateKey(key.algorithm, true, ["deriveBits"]);
}
function ecdhAllowed(key) {
  if (!isCryptoKey(key)) {
    throw new TypeError(invalid_key_input_default(key, ...types));
  }
  return ["P-256", "P-384", "P-521"].includes(key.algorithm.namedCurve) || key.algorithm.name === "X25519" || key.algorithm.name === "X448";
}
var init_ecdhes = __esm({
  "../../node_modules/jose/dist/browser/runtime/ecdhes.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_buffer_utils();
    init_webcrypto();
    init_crypto_key();
    init_invalid_key_input();
    init_is_key_like();
  }
});

// ../../node_modules/jose/dist/browser/lib/check_p2s.js
function checkP2s(p2s2) {
  if (!(p2s2 instanceof Uint8Array) || p2s2.length < 8) {
    throw new JWEInvalid("PBES2 Salt Input must be 8 or more octets");
  }
}
var init_check_p2s = __esm({
  "../../node_modules/jose/dist/browser/lib/check_p2s.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_errors2();
  }
});

// ../../node_modules/jose/dist/browser/runtime/pbes2kw.js
function getCryptoKey2(key, alg) {
  if (key instanceof Uint8Array) {
    return webcrypto_default.subtle.importKey("raw", key, "PBKDF2", false, ["deriveBits"]);
  }
  if (isCryptoKey(key)) {
    checkEncCryptoKey(key, alg, "deriveBits", "deriveKey");
    return key;
  }
  throw new TypeError(invalid_key_input_default(key, ...types, "Uint8Array"));
}
async function deriveKey2(p2s2, alg, p2c, key) {
  checkP2s(p2s2);
  const salt = p2s(alg, p2s2);
  const keylen = parseInt(alg.slice(13, 16), 10);
  const subtleAlg = {
    hash: `SHA-${alg.slice(8, 11)}`,
    iterations: p2c,
    name: "PBKDF2",
    salt
  };
  const wrapAlg = {
    length: keylen,
    name: "AES-KW"
  };
  const cryptoKey = await getCryptoKey2(key, alg);
  if (cryptoKey.usages.includes("deriveBits")) {
    return new Uint8Array(await webcrypto_default.subtle.deriveBits(subtleAlg, cryptoKey, keylen));
  }
  if (cryptoKey.usages.includes("deriveKey")) {
    return webcrypto_default.subtle.deriveKey(subtleAlg, cryptoKey, wrapAlg, false, ["wrapKey", "unwrapKey"]);
  }
  throw new TypeError('PBKDF2 key "usages" must include "deriveBits" or "deriveKey"');
}
var encrypt, decrypt2;
var init_pbes2kw = __esm({
  "../../node_modules/jose/dist/browser/runtime/pbes2kw.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_random();
    init_buffer_utils();
    init_base64url();
    init_aeskw();
    init_check_p2s();
    init_webcrypto();
    init_crypto_key();
    init_invalid_key_input();
    init_is_key_like();
    encrypt = async (alg, key, cek, p2c = 2048, p2s2 = random_default(new Uint8Array(16))) => {
      const derived = await deriveKey2(p2s2, alg, p2c, key);
      const encryptedKey = await wrap(alg.slice(-6), derived, cek);
      return { encryptedKey, p2c, p2s: encode(p2s2) };
    };
    decrypt2 = async (alg, key, encryptedKey, p2c, p2s2) => {
      const derived = await deriveKey2(p2s2, alg, p2c, key);
      return unwrap(alg.slice(-6), derived, encryptedKey);
    };
  }
});

// ../../node_modules/jose/dist/browser/runtime/subtle_rsaes.js
function subtleRsaEs(alg) {
  switch (alg) {
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512":
      return "RSA-OAEP";
    default:
      throw new JOSENotSupported(`alg ${alg} is not supported either by JOSE or your javascript runtime`);
  }
}
var init_subtle_rsaes = __esm({
  "../../node_modules/jose/dist/browser/runtime/subtle_rsaes.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_errors2();
  }
});

// ../../node_modules/jose/dist/browser/runtime/check_key_length.js
var check_key_length_default;
var init_check_key_length = __esm({
  "../../node_modules/jose/dist/browser/runtime/check_key_length.js"() {
    init_functionsRoutes_0_9412289658568613();
    check_key_length_default = (alg, key) => {
      if (alg.startsWith("RS") || alg.startsWith("PS")) {
        const { modulusLength } = key.algorithm;
        if (typeof modulusLength !== "number" || modulusLength < 2048) {
          throw new TypeError(`${alg} requires key modulusLength to be 2048 bits or larger`);
        }
      }
    };
  }
});

// ../../node_modules/jose/dist/browser/runtime/rsaes.js
var encrypt2, decrypt3;
var init_rsaes = __esm({
  "../../node_modules/jose/dist/browser/runtime/rsaes.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_subtle_rsaes();
    init_bogus();
    init_webcrypto();
    init_crypto_key();
    init_check_key_length();
    init_invalid_key_input();
    init_is_key_like();
    encrypt2 = async (alg, key, cek) => {
      if (!isCryptoKey(key)) {
        throw new TypeError(invalid_key_input_default(key, ...types));
      }
      checkEncCryptoKey(key, alg, "encrypt", "wrapKey");
      check_key_length_default(alg, key);
      if (key.usages.includes("encrypt")) {
        return new Uint8Array(await webcrypto_default.subtle.encrypt(subtleRsaEs(alg), key, cek));
      }
      if (key.usages.includes("wrapKey")) {
        const cryptoKeyCek = await webcrypto_default.subtle.importKey("raw", cek, ...bogus_default);
        return new Uint8Array(await webcrypto_default.subtle.wrapKey("raw", cryptoKeyCek, key, subtleRsaEs(alg)));
      }
      throw new TypeError('RSA-OAEP key "usages" must include "encrypt" or "wrapKey" for this operation');
    };
    decrypt3 = async (alg, key, encryptedKey) => {
      if (!isCryptoKey(key)) {
        throw new TypeError(invalid_key_input_default(key, ...types));
      }
      checkEncCryptoKey(key, alg, "decrypt", "unwrapKey");
      check_key_length_default(alg, key);
      if (key.usages.includes("decrypt")) {
        return new Uint8Array(await webcrypto_default.subtle.decrypt(subtleRsaEs(alg), key, encryptedKey));
      }
      if (key.usages.includes("unwrapKey")) {
        const cryptoKeyCek = await webcrypto_default.subtle.unwrapKey("raw", encryptedKey, key, subtleRsaEs(alg), ...bogus_default);
        return new Uint8Array(await webcrypto_default.subtle.exportKey("raw", cryptoKeyCek));
      }
      throw new TypeError('RSA-OAEP key "usages" must include "decrypt" or "unwrapKey" for this operation');
    };
  }
});

// ../../node_modules/jose/dist/browser/lib/cek.js
function bitLength2(alg) {
  switch (alg) {
    case "A128GCM":
      return 128;
    case "A192GCM":
      return 192;
    case "A256GCM":
    case "A128CBC-HS256":
      return 256;
    case "A192CBC-HS384":
      return 384;
    case "A256CBC-HS512":
      return 512;
    default:
      throw new JOSENotSupported(`Unsupported JWE Algorithm: ${alg}`);
  }
}
var cek_default;
var init_cek = __esm({
  "../../node_modules/jose/dist/browser/lib/cek.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_errors2();
    init_random();
    cek_default = (alg) => random_default(new Uint8Array(bitLength2(alg) >> 3));
  }
});

// ../../node_modules/jose/dist/browser/lib/format_pem.js
var init_format_pem = __esm({
  "../../node_modules/jose/dist/browser/lib/format_pem.js"() {
    init_functionsRoutes_0_9412289658568613();
  }
});

// ../../node_modules/jose/dist/browser/runtime/asn1.js
var init_asn1 = __esm({
  "../../node_modules/jose/dist/browser/runtime/asn1.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_webcrypto();
    init_invalid_key_input();
    init_base64url();
    init_format_pem();
    init_errors2();
    init_is_key_like();
  }
});

// ../../node_modules/jose/dist/browser/runtime/jwk_to_key.js
function subtleMapping(jwk) {
  let algorithm;
  let keyUsages;
  switch (jwk.kty) {
    case "oct": {
      switch (jwk.alg) {
        case "HS256":
        case "HS384":
        case "HS512":
          algorithm = { name: "HMAC", hash: `SHA-${jwk.alg.slice(-3)}` };
          keyUsages = ["sign", "verify"];
          break;
        case "A128CBC-HS256":
        case "A192CBC-HS384":
        case "A256CBC-HS512":
          throw new JOSENotSupported(`${jwk.alg} keys cannot be imported as CryptoKey instances`);
        case "A128GCM":
        case "A192GCM":
        case "A256GCM":
        case "A128GCMKW":
        case "A192GCMKW":
        case "A256GCMKW":
          algorithm = { name: "AES-GCM" };
          keyUsages = ["encrypt", "decrypt"];
          break;
        case "A128KW":
        case "A192KW":
        case "A256KW":
          algorithm = { name: "AES-KW" };
          keyUsages = ["wrapKey", "unwrapKey"];
          break;
        case "PBES2-HS256+A128KW":
        case "PBES2-HS384+A192KW":
        case "PBES2-HS512+A256KW":
          algorithm = { name: "PBKDF2" };
          keyUsages = ["deriveBits"];
          break;
        default:
          throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
      }
      break;
    }
    case "RSA": {
      switch (jwk.alg) {
        case "PS256":
        case "PS384":
        case "PS512":
          algorithm = { name: "RSA-PSS", hash: `SHA-${jwk.alg.slice(-3)}` };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "RS256":
        case "RS384":
        case "RS512":
          algorithm = { name: "RSASSA-PKCS1-v1_5", hash: `SHA-${jwk.alg.slice(-3)}` };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "RSA-OAEP":
        case "RSA-OAEP-256":
        case "RSA-OAEP-384":
        case "RSA-OAEP-512":
          algorithm = {
            name: "RSA-OAEP",
            hash: `SHA-${parseInt(jwk.alg.slice(-3), 10) || 1}`
          };
          keyUsages = jwk.d ? ["decrypt", "unwrapKey"] : ["encrypt", "wrapKey"];
          break;
        default:
          throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
      }
      break;
    }
    case "EC": {
      switch (jwk.alg) {
        case "ES256":
          algorithm = { name: "ECDSA", namedCurve: "P-256" };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "ES384":
          algorithm = { name: "ECDSA", namedCurve: "P-384" };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "ES512":
          algorithm = { name: "ECDSA", namedCurve: "P-521" };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "ECDH-ES":
        case "ECDH-ES+A128KW":
        case "ECDH-ES+A192KW":
        case "ECDH-ES+A256KW":
          algorithm = { name: "ECDH", namedCurve: jwk.crv };
          keyUsages = jwk.d ? ["deriveBits"] : [];
          break;
        default:
          throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
      }
      break;
    }
    case "OKP": {
      switch (jwk.alg) {
        case "EdDSA":
          algorithm = { name: jwk.crv };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "ECDH-ES":
        case "ECDH-ES+A128KW":
        case "ECDH-ES+A192KW":
        case "ECDH-ES+A256KW":
          algorithm = { name: jwk.crv };
          keyUsages = jwk.d ? ["deriveBits"] : [];
          break;
        default:
          throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
      }
      break;
    }
    default:
      throw new JOSENotSupported('Invalid or unsupported JWK "kty" (Key Type) Parameter value');
  }
  return { algorithm, keyUsages };
}
var parse, jwk_to_key_default;
var init_jwk_to_key = __esm({
  "../../node_modules/jose/dist/browser/runtime/jwk_to_key.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_webcrypto();
    init_errors2();
    init_base64url();
    parse = async (jwk) => {
      var _a, _b;
      if (!jwk.alg) {
        throw new TypeError('"alg" argument is required when "jwk.alg" is not present');
      }
      const { algorithm, keyUsages } = subtleMapping(jwk);
      const rest = [
        algorithm,
        (_a = jwk.ext) !== null && _a !== void 0 ? _a : false,
        (_b = jwk.key_ops) !== null && _b !== void 0 ? _b : keyUsages
      ];
      if (algorithm.name === "PBKDF2") {
        return webcrypto_default.subtle.importKey("raw", decode(jwk.k), ...rest);
      }
      const keyData = { ...jwk };
      delete keyData.alg;
      delete keyData.use;
      return webcrypto_default.subtle.importKey("jwk", keyData, ...rest);
    };
    jwk_to_key_default = parse;
  }
});

// ../../node_modules/jose/dist/browser/key/import.js
async function importJWK(jwk, alg, octAsKeyObject) {
  var _a;
  if (!isObject(jwk)) {
    throw new TypeError("JWK must be an object");
  }
  alg || (alg = jwk.alg);
  switch (jwk.kty) {
    case "oct":
      if (typeof jwk.k !== "string" || !jwk.k) {
        throw new TypeError('missing "k" (Key Value) Parameter value');
      }
      octAsKeyObject !== null && octAsKeyObject !== void 0 ? octAsKeyObject : octAsKeyObject = jwk.ext !== true;
      if (octAsKeyObject) {
        return jwk_to_key_default({ ...jwk, alg, ext: (_a = jwk.ext) !== null && _a !== void 0 ? _a : false });
      }
      return decode(jwk.k);
    case "RSA":
      if (jwk.oth !== void 0) {
        throw new JOSENotSupported('RSA JWK "oth" (Other Primes Info) Parameter value is not supported');
      }
    case "EC":
    case "OKP":
      return jwk_to_key_default({ ...jwk, alg });
    default:
      throw new JOSENotSupported('Unsupported "kty" (Key Type) Parameter value');
  }
}
var init_import = __esm({
  "../../node_modules/jose/dist/browser/key/import.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_base64url();
    init_asn1();
    init_jwk_to_key();
    init_errors2();
    init_is_object();
  }
});

// ../../node_modules/jose/dist/browser/lib/check_key_type.js
var symmetricTypeCheck, asymmetricTypeCheck, checkKeyType, check_key_type_default;
var init_check_key_type = __esm({
  "../../node_modules/jose/dist/browser/lib/check_key_type.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_invalid_key_input();
    init_is_key_like();
    symmetricTypeCheck = (alg, key) => {
      if (key instanceof Uint8Array)
        return;
      if (!is_key_like_default(key)) {
        throw new TypeError(withAlg(alg, key, ...types, "Uint8Array"));
      }
      if (key.type !== "secret") {
        throw new TypeError(`${types.join(" or ")} instances for symmetric algorithms must be of type "secret"`);
      }
    };
    asymmetricTypeCheck = (alg, key, usage) => {
      if (!is_key_like_default(key)) {
        throw new TypeError(withAlg(alg, key, ...types));
      }
      if (key.type === "secret") {
        throw new TypeError(`${types.join(" or ")} instances for asymmetric algorithms must not be of type "secret"`);
      }
      if (usage === "sign" && key.type === "public") {
        throw new TypeError(`${types.join(" or ")} instances for asymmetric algorithm signing must be of type "private"`);
      }
      if (usage === "decrypt" && key.type === "public") {
        throw new TypeError(`${types.join(" or ")} instances for asymmetric algorithm decryption must be of type "private"`);
      }
      if (key.algorithm && usage === "verify" && key.type === "private") {
        throw new TypeError(`${types.join(" or ")} instances for asymmetric algorithm verifying must be of type "public"`);
      }
      if (key.algorithm && usage === "encrypt" && key.type === "private") {
        throw new TypeError(`${types.join(" or ")} instances for asymmetric algorithm encryption must be of type "public"`);
      }
    };
    checkKeyType = (alg, key, usage) => {
      const symmetric = alg.startsWith("HS") || alg === "dir" || alg.startsWith("PBES2") || /^A\d{3}(?:GCM)?KW$/.test(alg);
      if (symmetric) {
        symmetricTypeCheck(alg, key);
      } else {
        asymmetricTypeCheck(alg, key, usage);
      }
    };
    check_key_type_default = checkKeyType;
  }
});

// ../../node_modules/jose/dist/browser/runtime/encrypt.js
async function cbcEncrypt(enc, plaintext, cek, iv, aad) {
  if (!(cek instanceof Uint8Array)) {
    throw new TypeError(invalid_key_input_default(cek, "Uint8Array"));
  }
  const keySize = parseInt(enc.slice(1, 4), 10);
  const encKey = await webcrypto_default.subtle.importKey("raw", cek.subarray(keySize >> 3), "AES-CBC", false, ["encrypt"]);
  const macKey = await webcrypto_default.subtle.importKey("raw", cek.subarray(0, keySize >> 3), {
    hash: `SHA-${keySize << 1}`,
    name: "HMAC"
  }, false, ["sign"]);
  const ciphertext = new Uint8Array(await webcrypto_default.subtle.encrypt({
    iv,
    name: "AES-CBC"
  }, encKey, plaintext));
  const macData = concat(aad, iv, ciphertext, uint64be(aad.length << 3));
  const tag = new Uint8Array((await webcrypto_default.subtle.sign("HMAC", macKey, macData)).slice(0, keySize >> 3));
  return { ciphertext, tag };
}
async function gcmEncrypt(enc, plaintext, cek, iv, aad) {
  let encKey;
  if (cek instanceof Uint8Array) {
    encKey = await webcrypto_default.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  } else {
    checkEncCryptoKey(cek, enc, "encrypt");
    encKey = cek;
  }
  const encrypted = new Uint8Array(await webcrypto_default.subtle.encrypt({
    additionalData: aad,
    iv,
    name: "AES-GCM",
    tagLength: 128
  }, encKey, plaintext));
  const tag = encrypted.slice(-16);
  const ciphertext = encrypted.slice(0, -16);
  return { ciphertext, tag };
}
var encrypt3, encrypt_default;
var init_encrypt = __esm({
  "../../node_modules/jose/dist/browser/runtime/encrypt.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_buffer_utils();
    init_check_iv_length();
    init_check_cek_length();
    init_webcrypto();
    init_crypto_key();
    init_invalid_key_input();
    init_errors2();
    init_is_key_like();
    encrypt3 = async (enc, plaintext, cek, iv, aad) => {
      if (!isCryptoKey(cek) && !(cek instanceof Uint8Array)) {
        throw new TypeError(invalid_key_input_default(cek, ...types, "Uint8Array"));
      }
      check_iv_length_default(enc, iv);
      switch (enc) {
        case "A128CBC-HS256":
        case "A192CBC-HS384":
        case "A256CBC-HS512":
          if (cek instanceof Uint8Array)
            check_cek_length_default(cek, parseInt(enc.slice(-3), 10));
          return cbcEncrypt(enc, plaintext, cek, iv, aad);
        case "A128GCM":
        case "A192GCM":
        case "A256GCM":
          if (cek instanceof Uint8Array)
            check_cek_length_default(cek, parseInt(enc.slice(1, 4), 10));
          return gcmEncrypt(enc, plaintext, cek, iv, aad);
        default:
          throw new JOSENotSupported("Unsupported JWE Content Encryption Algorithm");
      }
    };
    encrypt_default = encrypt3;
  }
});

// ../../node_modules/jose/dist/browser/lib/aesgcmkw.js
async function wrap2(alg, key, cek, iv) {
  const jweAlgorithm = alg.slice(0, 7);
  iv || (iv = iv_default(jweAlgorithm));
  const { ciphertext: encryptedKey, tag } = await encrypt_default(jweAlgorithm, cek, key, iv, new Uint8Array(0));
  return { encryptedKey, iv: encode(iv), tag: encode(tag) };
}
async function unwrap2(alg, key, encryptedKey, iv, tag) {
  const jweAlgorithm = alg.slice(0, 7);
  return decrypt_default(jweAlgorithm, key, encryptedKey, iv, tag, new Uint8Array(0));
}
var init_aesgcmkw = __esm({
  "../../node_modules/jose/dist/browser/lib/aesgcmkw.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_encrypt();
    init_decrypt();
    init_iv();
    init_base64url();
  }
});

// ../../node_modules/jose/dist/browser/lib/decrypt_key_management.js
async function decryptKeyManagement(alg, key, encryptedKey, joseHeader, options) {
  check_key_type_default(alg, key, "decrypt");
  switch (alg) {
    case "dir": {
      if (encryptedKey !== void 0)
        throw new JWEInvalid("Encountered unexpected JWE Encrypted Key");
      return key;
    }
    case "ECDH-ES":
      if (encryptedKey !== void 0)
        throw new JWEInvalid("Encountered unexpected JWE Encrypted Key");
    case "ECDH-ES+A128KW":
    case "ECDH-ES+A192KW":
    case "ECDH-ES+A256KW": {
      if (!isObject(joseHeader.epk))
        throw new JWEInvalid(`JOSE Header "epk" (Ephemeral Public Key) missing or invalid`);
      if (!ecdhAllowed(key))
        throw new JOSENotSupported("ECDH with the provided key is not allowed or not supported by your javascript runtime");
      const epk = await importJWK(joseHeader.epk, alg);
      let partyUInfo;
      let partyVInfo;
      if (joseHeader.apu !== void 0) {
        if (typeof joseHeader.apu !== "string")
          throw new JWEInvalid(`JOSE Header "apu" (Agreement PartyUInfo) invalid`);
        partyUInfo = decode(joseHeader.apu);
      }
      if (joseHeader.apv !== void 0) {
        if (typeof joseHeader.apv !== "string")
          throw new JWEInvalid(`JOSE Header "apv" (Agreement PartyVInfo) invalid`);
        partyVInfo = decode(joseHeader.apv);
      }
      const sharedSecret = await deriveKey(epk, key, alg === "ECDH-ES" ? joseHeader.enc : alg, alg === "ECDH-ES" ? bitLength2(joseHeader.enc) : parseInt(alg.slice(-5, -2), 10), partyUInfo, partyVInfo);
      if (alg === "ECDH-ES")
        return sharedSecret;
      if (encryptedKey === void 0)
        throw new JWEInvalid("JWE Encrypted Key missing");
      return unwrap(alg.slice(-6), sharedSecret, encryptedKey);
    }
    case "RSA1_5":
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      if (encryptedKey === void 0)
        throw new JWEInvalid("JWE Encrypted Key missing");
      return decrypt3(alg, key, encryptedKey);
    }
    case "PBES2-HS256+A128KW":
    case "PBES2-HS384+A192KW":
    case "PBES2-HS512+A256KW": {
      if (encryptedKey === void 0)
        throw new JWEInvalid("JWE Encrypted Key missing");
      if (typeof joseHeader.p2c !== "number")
        throw new JWEInvalid(`JOSE Header "p2c" (PBES2 Count) missing or invalid`);
      const p2cLimit = (options === null || options === void 0 ? void 0 : options.maxPBES2Count) || 1e4;
      if (joseHeader.p2c > p2cLimit)
        throw new JWEInvalid(`JOSE Header "p2c" (PBES2 Count) out is of acceptable bounds`);
      if (typeof joseHeader.p2s !== "string")
        throw new JWEInvalid(`JOSE Header "p2s" (PBES2 Salt) missing or invalid`);
      return decrypt2(alg, key, encryptedKey, joseHeader.p2c, decode(joseHeader.p2s));
    }
    case "A128KW":
    case "A192KW":
    case "A256KW": {
      if (encryptedKey === void 0)
        throw new JWEInvalid("JWE Encrypted Key missing");
      return unwrap(alg, key, encryptedKey);
    }
    case "A128GCMKW":
    case "A192GCMKW":
    case "A256GCMKW": {
      if (encryptedKey === void 0)
        throw new JWEInvalid("JWE Encrypted Key missing");
      if (typeof joseHeader.iv !== "string")
        throw new JWEInvalid(`JOSE Header "iv" (Initialization Vector) missing or invalid`);
      if (typeof joseHeader.tag !== "string")
        throw new JWEInvalid(`JOSE Header "tag" (Authentication Tag) missing or invalid`);
      const iv = decode(joseHeader.iv);
      const tag = decode(joseHeader.tag);
      return unwrap2(alg, key, encryptedKey, iv, tag);
    }
    default: {
      throw new JOSENotSupported('Invalid or unsupported "alg" (JWE Algorithm) header value');
    }
  }
}
var decrypt_key_management_default;
var init_decrypt_key_management = __esm({
  "../../node_modules/jose/dist/browser/lib/decrypt_key_management.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_aeskw();
    init_ecdhes();
    init_pbes2kw();
    init_rsaes();
    init_base64url();
    init_errors2();
    init_cek();
    init_import();
    init_check_key_type();
    init_is_object();
    init_aesgcmkw();
    decrypt_key_management_default = decryptKeyManagement;
  }
});

// ../../node_modules/jose/dist/browser/lib/validate_crit.js
function validateCrit(Err, recognizedDefault, recognizedOption, protectedHeader, joseHeader) {
  if (joseHeader.crit !== void 0 && protectedHeader.crit === void 0) {
    throw new Err('"crit" (Critical) Header Parameter MUST be integrity protected');
  }
  if (!protectedHeader || protectedHeader.crit === void 0) {
    return /* @__PURE__ */ new Set();
  }
  if (!Array.isArray(protectedHeader.crit) || protectedHeader.crit.length === 0 || protectedHeader.crit.some((input) => typeof input !== "string" || input.length === 0)) {
    throw new Err('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present');
  }
  let recognized;
  if (recognizedOption !== void 0) {
    recognized = new Map([...Object.entries(recognizedOption), ...recognizedDefault.entries()]);
  } else {
    recognized = recognizedDefault;
  }
  for (const parameter of protectedHeader.crit) {
    if (!recognized.has(parameter)) {
      throw new JOSENotSupported(`Extension Header Parameter "${parameter}" is not recognized`);
    }
    if (joseHeader[parameter] === void 0) {
      throw new Err(`Extension Header Parameter "${parameter}" is missing`);
    } else if (recognized.get(parameter) && protectedHeader[parameter] === void 0) {
      throw new Err(`Extension Header Parameter "${parameter}" MUST be integrity protected`);
    }
  }
  return new Set(protectedHeader.crit);
}
var validate_crit_default;
var init_validate_crit = __esm({
  "../../node_modules/jose/dist/browser/lib/validate_crit.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_errors2();
    validate_crit_default = validateCrit;
  }
});

// ../../node_modules/jose/dist/browser/lib/validate_algorithms.js
var validateAlgorithms, validate_algorithms_default;
var init_validate_algorithms = __esm({
  "../../node_modules/jose/dist/browser/lib/validate_algorithms.js"() {
    init_functionsRoutes_0_9412289658568613();
    validateAlgorithms = (option, algorithms) => {
      if (algorithms !== void 0 && (!Array.isArray(algorithms) || algorithms.some((s3) => typeof s3 !== "string"))) {
        throw new TypeError(`"${option}" option must be an array of strings`);
      }
      if (!algorithms) {
        return void 0;
      }
      return new Set(algorithms);
    };
    validate_algorithms_default = validateAlgorithms;
  }
});

// ../../node_modules/jose/dist/browser/jwe/flattened/decrypt.js
async function flattenedDecrypt(jwe, key, options) {
  var _a;
  if (!isObject(jwe)) {
    throw new JWEInvalid("Flattened JWE must be an object");
  }
  if (jwe.protected === void 0 && jwe.header === void 0 && jwe.unprotected === void 0) {
    throw new JWEInvalid("JOSE Header missing");
  }
  if (typeof jwe.iv !== "string") {
    throw new JWEInvalid("JWE Initialization Vector missing or incorrect type");
  }
  if (typeof jwe.ciphertext !== "string") {
    throw new JWEInvalid("JWE Ciphertext missing or incorrect type");
  }
  if (typeof jwe.tag !== "string") {
    throw new JWEInvalid("JWE Authentication Tag missing or incorrect type");
  }
  if (jwe.protected !== void 0 && typeof jwe.protected !== "string") {
    throw new JWEInvalid("JWE Protected Header incorrect type");
  }
  if (jwe.encrypted_key !== void 0 && typeof jwe.encrypted_key !== "string") {
    throw new JWEInvalid("JWE Encrypted Key incorrect type");
  }
  if (jwe.aad !== void 0 && typeof jwe.aad !== "string") {
    throw new JWEInvalid("JWE AAD incorrect type");
  }
  if (jwe.header !== void 0 && !isObject(jwe.header)) {
    throw new JWEInvalid("JWE Shared Unprotected Header incorrect type");
  }
  if (jwe.unprotected !== void 0 && !isObject(jwe.unprotected)) {
    throw new JWEInvalid("JWE Per-Recipient Unprotected Header incorrect type");
  }
  let parsedProt;
  if (jwe.protected) {
    try {
      const protectedHeader2 = decode(jwe.protected);
      parsedProt = JSON.parse(decoder.decode(protectedHeader2));
    } catch (_b) {
      throw new JWEInvalid("JWE Protected Header is invalid");
    }
  }
  if (!is_disjoint_default(parsedProt, jwe.header, jwe.unprotected)) {
    throw new JWEInvalid("JWE Protected, JWE Unprotected Header, and JWE Per-Recipient Unprotected Header Parameter names must be disjoint");
  }
  const joseHeader = {
    ...parsedProt,
    ...jwe.header,
    ...jwe.unprotected
  };
  validate_crit_default(JWEInvalid, /* @__PURE__ */ new Map(), options === null || options === void 0 ? void 0 : options.crit, parsedProt, joseHeader);
  if (joseHeader.zip !== void 0) {
    if (!parsedProt || !parsedProt.zip) {
      throw new JWEInvalid('JWE "zip" (Compression Algorithm) Header MUST be integrity protected');
    }
    if (joseHeader.zip !== "DEF") {
      throw new JOSENotSupported('Unsupported JWE "zip" (Compression Algorithm) Header Parameter value');
    }
  }
  const { alg, enc } = joseHeader;
  if (typeof alg !== "string" || !alg) {
    throw new JWEInvalid("missing JWE Algorithm (alg) in JWE Header");
  }
  if (typeof enc !== "string" || !enc) {
    throw new JWEInvalid("missing JWE Encryption Algorithm (enc) in JWE Header");
  }
  const keyManagementAlgorithms = options && validate_algorithms_default("keyManagementAlgorithms", options.keyManagementAlgorithms);
  const contentEncryptionAlgorithms = options && validate_algorithms_default("contentEncryptionAlgorithms", options.contentEncryptionAlgorithms);
  if (keyManagementAlgorithms && !keyManagementAlgorithms.has(alg)) {
    throw new JOSEAlgNotAllowed('"alg" (Algorithm) Header Parameter not allowed');
  }
  if (contentEncryptionAlgorithms && !contentEncryptionAlgorithms.has(enc)) {
    throw new JOSEAlgNotAllowed('"enc" (Encryption Algorithm) Header Parameter not allowed');
  }
  let encryptedKey;
  if (jwe.encrypted_key !== void 0) {
    encryptedKey = decode(jwe.encrypted_key);
  }
  let resolvedKey = false;
  if (typeof key === "function") {
    key = await key(parsedProt, jwe);
    resolvedKey = true;
  }
  let cek;
  try {
    cek = await decrypt_key_management_default(alg, key, encryptedKey, joseHeader, options);
  } catch (err) {
    if (err instanceof TypeError || err instanceof JWEInvalid || err instanceof JOSENotSupported) {
      throw err;
    }
    cek = cek_default(enc);
  }
  const iv = decode(jwe.iv);
  const tag = decode(jwe.tag);
  const protectedHeader = encoder.encode((_a = jwe.protected) !== null && _a !== void 0 ? _a : "");
  let additionalData;
  if (jwe.aad !== void 0) {
    additionalData = concat(protectedHeader, encoder.encode("."), encoder.encode(jwe.aad));
  } else {
    additionalData = protectedHeader;
  }
  let plaintext = await decrypt_default(enc, cek, decode(jwe.ciphertext), iv, tag, additionalData);
  if (joseHeader.zip === "DEF") {
    plaintext = await ((options === null || options === void 0 ? void 0 : options.inflateRaw) || inflate)(plaintext);
  }
  const result = { plaintext };
  if (jwe.protected !== void 0) {
    result.protectedHeader = parsedProt;
  }
  if (jwe.aad !== void 0) {
    result.additionalAuthenticatedData = decode(jwe.aad);
  }
  if (jwe.unprotected !== void 0) {
    result.sharedUnprotectedHeader = jwe.unprotected;
  }
  if (jwe.header !== void 0) {
    result.unprotectedHeader = jwe.header;
  }
  if (resolvedKey) {
    return { ...result, key };
  }
  return result;
}
var init_decrypt2 = __esm({
  "../../node_modules/jose/dist/browser/jwe/flattened/decrypt.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_base64url();
    init_decrypt();
    init_zlib();
    init_errors2();
    init_is_disjoint();
    init_is_object();
    init_decrypt_key_management();
    init_buffer_utils();
    init_cek();
    init_validate_crit();
    init_validate_algorithms();
  }
});

// ../../node_modules/jose/dist/browser/jwe/compact/decrypt.js
async function compactDecrypt(jwe, key, options) {
  if (jwe instanceof Uint8Array) {
    jwe = decoder.decode(jwe);
  }
  if (typeof jwe !== "string") {
    throw new JWEInvalid("Compact JWE must be a string or Uint8Array");
  }
  const { 0: protectedHeader, 1: encryptedKey, 2: iv, 3: ciphertext, 4: tag, length } = jwe.split(".");
  if (length !== 5) {
    throw new JWEInvalid("Invalid Compact JWE");
  }
  const decrypted = await flattenedDecrypt({
    ciphertext,
    iv: iv || void 0,
    protected: protectedHeader || void 0,
    tag: tag || void 0,
    encrypted_key: encryptedKey || void 0
  }, key, options);
  const result = { plaintext: decrypted.plaintext, protectedHeader: decrypted.protectedHeader };
  if (typeof key === "function") {
    return { ...result, key: decrypted.key };
  }
  return result;
}
var init_decrypt3 = __esm({
  "../../node_modules/jose/dist/browser/jwe/compact/decrypt.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_decrypt2();
    init_errors2();
    init_buffer_utils();
  }
});

// ../../node_modules/jose/dist/browser/jwe/general/decrypt.js
var init_decrypt4 = __esm({
  "../../node_modules/jose/dist/browser/jwe/general/decrypt.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_decrypt2();
    init_errors2();
    init_is_object();
  }
});

// ../../node_modules/jose/dist/browser/runtime/key_to_jwk.js
var keyToJWK, key_to_jwk_default;
var init_key_to_jwk = __esm({
  "../../node_modules/jose/dist/browser/runtime/key_to_jwk.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_webcrypto();
    init_invalid_key_input();
    init_base64url();
    init_is_key_like();
    keyToJWK = async (key) => {
      if (key instanceof Uint8Array) {
        return {
          kty: "oct",
          k: encode(key)
        };
      }
      if (!isCryptoKey(key)) {
        throw new TypeError(invalid_key_input_default(key, ...types, "Uint8Array"));
      }
      if (!key.extractable) {
        throw new TypeError("non-extractable CryptoKey cannot be exported as a JWK");
      }
      const { ext, key_ops, alg, use, ...jwk } = await webcrypto_default.subtle.exportKey("jwk", key);
      return jwk;
    };
    key_to_jwk_default = keyToJWK;
  }
});

// ../../node_modules/jose/dist/browser/key/export.js
async function exportJWK(key) {
  return key_to_jwk_default(key);
}
var init_export = __esm({
  "../../node_modules/jose/dist/browser/key/export.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_asn1();
    init_asn1();
    init_key_to_jwk();
  }
});

// ../../node_modules/jose/dist/browser/lib/encrypt_key_management.js
async function encryptKeyManagement(alg, enc, key, providedCek, providedParameters = {}) {
  let encryptedKey;
  let parameters;
  let cek;
  check_key_type_default(alg, key, "encrypt");
  switch (alg) {
    case "dir": {
      cek = key;
      break;
    }
    case "ECDH-ES":
    case "ECDH-ES+A128KW":
    case "ECDH-ES+A192KW":
    case "ECDH-ES+A256KW": {
      if (!ecdhAllowed(key)) {
        throw new JOSENotSupported("ECDH with the provided key is not allowed or not supported by your javascript runtime");
      }
      const { apu, apv } = providedParameters;
      let { epk: ephemeralKey } = providedParameters;
      ephemeralKey || (ephemeralKey = (await generateEpk(key)).privateKey);
      const { x: x2, y: y2, crv, kty } = await exportJWK(ephemeralKey);
      const sharedSecret = await deriveKey(key, ephemeralKey, alg === "ECDH-ES" ? enc : alg, alg === "ECDH-ES" ? bitLength2(enc) : parseInt(alg.slice(-5, -2), 10), apu, apv);
      parameters = { epk: { x: x2, crv, kty } };
      if (kty === "EC")
        parameters.epk.y = y2;
      if (apu)
        parameters.apu = encode(apu);
      if (apv)
        parameters.apv = encode(apv);
      if (alg === "ECDH-ES") {
        cek = sharedSecret;
        break;
      }
      cek = providedCek || cek_default(enc);
      const kwAlg = alg.slice(-6);
      encryptedKey = await wrap(kwAlg, sharedSecret, cek);
      break;
    }
    case "RSA1_5":
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      cek = providedCek || cek_default(enc);
      encryptedKey = await encrypt2(alg, key, cek);
      break;
    }
    case "PBES2-HS256+A128KW":
    case "PBES2-HS384+A192KW":
    case "PBES2-HS512+A256KW": {
      cek = providedCek || cek_default(enc);
      const { p2c, p2s: p2s2 } = providedParameters;
      ({ encryptedKey, ...parameters } = await encrypt(alg, key, cek, p2c, p2s2));
      break;
    }
    case "A128KW":
    case "A192KW":
    case "A256KW": {
      cek = providedCek || cek_default(enc);
      encryptedKey = await wrap(alg, key, cek);
      break;
    }
    case "A128GCMKW":
    case "A192GCMKW":
    case "A256GCMKW": {
      cek = providedCek || cek_default(enc);
      const { iv } = providedParameters;
      ({ encryptedKey, ...parameters } = await wrap2(alg, key, cek, iv));
      break;
    }
    default: {
      throw new JOSENotSupported('Invalid or unsupported "alg" (JWE Algorithm) header value');
    }
  }
  return { cek, encryptedKey, parameters };
}
var encrypt_key_management_default;
var init_encrypt_key_management = __esm({
  "../../node_modules/jose/dist/browser/lib/encrypt_key_management.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_aeskw();
    init_ecdhes();
    init_pbes2kw();
    init_rsaes();
    init_base64url();
    init_cek();
    init_errors2();
    init_export();
    init_check_key_type();
    init_aesgcmkw();
    encrypt_key_management_default = encryptKeyManagement;
  }
});

// ../../node_modules/jose/dist/browser/jwe/flattened/encrypt.js
var unprotected, FlattenedEncrypt;
var init_encrypt2 = __esm({
  "../../node_modules/jose/dist/browser/jwe/flattened/encrypt.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_base64url();
    init_encrypt();
    init_zlib();
    init_iv();
    init_encrypt_key_management();
    init_errors2();
    init_is_disjoint();
    init_buffer_utils();
    init_validate_crit();
    unprotected = Symbol();
    FlattenedEncrypt = class {
      constructor(plaintext) {
        if (!(plaintext instanceof Uint8Array)) {
          throw new TypeError("plaintext must be an instance of Uint8Array");
        }
        this._plaintext = plaintext;
      }
      setKeyManagementParameters(parameters) {
        if (this._keyManagementParameters) {
          throw new TypeError("setKeyManagementParameters can only be called once");
        }
        this._keyManagementParameters = parameters;
        return this;
      }
      setProtectedHeader(protectedHeader) {
        if (this._protectedHeader) {
          throw new TypeError("setProtectedHeader can only be called once");
        }
        this._protectedHeader = protectedHeader;
        return this;
      }
      setSharedUnprotectedHeader(sharedUnprotectedHeader) {
        if (this._sharedUnprotectedHeader) {
          throw new TypeError("setSharedUnprotectedHeader can only be called once");
        }
        this._sharedUnprotectedHeader = sharedUnprotectedHeader;
        return this;
      }
      setUnprotectedHeader(unprotectedHeader) {
        if (this._unprotectedHeader) {
          throw new TypeError("setUnprotectedHeader can only be called once");
        }
        this._unprotectedHeader = unprotectedHeader;
        return this;
      }
      setAdditionalAuthenticatedData(aad) {
        this._aad = aad;
        return this;
      }
      setContentEncryptionKey(cek) {
        if (this._cek) {
          throw new TypeError("setContentEncryptionKey can only be called once");
        }
        this._cek = cek;
        return this;
      }
      setInitializationVector(iv) {
        if (this._iv) {
          throw new TypeError("setInitializationVector can only be called once");
        }
        this._iv = iv;
        return this;
      }
      async encrypt(key, options) {
        if (!this._protectedHeader && !this._unprotectedHeader && !this._sharedUnprotectedHeader) {
          throw new JWEInvalid("either setProtectedHeader, setUnprotectedHeader, or sharedUnprotectedHeader must be called before #encrypt()");
        }
        if (!is_disjoint_default(this._protectedHeader, this._unprotectedHeader, this._sharedUnprotectedHeader)) {
          throw new JWEInvalid("JWE Protected, JWE Shared Unprotected and JWE Per-Recipient Header Parameter names must be disjoint");
        }
        const joseHeader = {
          ...this._protectedHeader,
          ...this._unprotectedHeader,
          ...this._sharedUnprotectedHeader
        };
        validate_crit_default(JWEInvalid, /* @__PURE__ */ new Map(), options === null || options === void 0 ? void 0 : options.crit, this._protectedHeader, joseHeader);
        if (joseHeader.zip !== void 0) {
          if (!this._protectedHeader || !this._protectedHeader.zip) {
            throw new JWEInvalid('JWE "zip" (Compression Algorithm) Header MUST be integrity protected');
          }
          if (joseHeader.zip !== "DEF") {
            throw new JOSENotSupported('Unsupported JWE "zip" (Compression Algorithm) Header Parameter value');
          }
        }
        const { alg, enc } = joseHeader;
        if (typeof alg !== "string" || !alg) {
          throw new JWEInvalid('JWE "alg" (Algorithm) Header Parameter missing or invalid');
        }
        if (typeof enc !== "string" || !enc) {
          throw new JWEInvalid('JWE "enc" (Encryption Algorithm) Header Parameter missing or invalid');
        }
        let encryptedKey;
        if (alg === "dir") {
          if (this._cek) {
            throw new TypeError("setContentEncryptionKey cannot be called when using Direct Encryption");
          }
        } else if (alg === "ECDH-ES") {
          if (this._cek) {
            throw new TypeError("setContentEncryptionKey cannot be called when using Direct Key Agreement");
          }
        }
        let cek;
        {
          let parameters;
          ({ cek, encryptedKey, parameters } = await encrypt_key_management_default(alg, enc, key, this._cek, this._keyManagementParameters));
          if (parameters) {
            if (options && unprotected in options) {
              if (!this._unprotectedHeader) {
                this.setUnprotectedHeader(parameters);
              } else {
                this._unprotectedHeader = { ...this._unprotectedHeader, ...parameters };
              }
            } else {
              if (!this._protectedHeader) {
                this.setProtectedHeader(parameters);
              } else {
                this._protectedHeader = { ...this._protectedHeader, ...parameters };
              }
            }
          }
        }
        this._iv || (this._iv = iv_default(enc));
        let additionalData;
        let protectedHeader;
        let aadMember;
        if (this._protectedHeader) {
          protectedHeader = encoder.encode(encode(JSON.stringify(this._protectedHeader)));
        } else {
          protectedHeader = encoder.encode("");
        }
        if (this._aad) {
          aadMember = encode(this._aad);
          additionalData = concat(protectedHeader, encoder.encode("."), encoder.encode(aadMember));
        } else {
          additionalData = protectedHeader;
        }
        let ciphertext;
        let tag;
        if (joseHeader.zip === "DEF") {
          const deflated = await ((options === null || options === void 0 ? void 0 : options.deflateRaw) || deflate)(this._plaintext);
          ({ ciphertext, tag } = await encrypt_default(enc, deflated, cek, this._iv, additionalData));
        } else {
          ;
          ({ ciphertext, tag } = await encrypt_default(enc, this._plaintext, cek, this._iv, additionalData));
        }
        const jwe = {
          ciphertext: encode(ciphertext),
          iv: encode(this._iv),
          tag: encode(tag)
        };
        if (encryptedKey) {
          jwe.encrypted_key = encode(encryptedKey);
        }
        if (aadMember) {
          jwe.aad = aadMember;
        }
        if (this._protectedHeader) {
          jwe.protected = decoder.decode(protectedHeader);
        }
        if (this._sharedUnprotectedHeader) {
          jwe.unprotected = this._sharedUnprotectedHeader;
        }
        if (this._unprotectedHeader) {
          jwe.header = this._unprotectedHeader;
        }
        return jwe;
      }
    };
  }
});

// ../../node_modules/jose/dist/browser/jwe/general/encrypt.js
var init_encrypt3 = __esm({
  "../../node_modules/jose/dist/browser/jwe/general/encrypt.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_encrypt2();
    init_errors2();
    init_cek();
    init_is_disjoint();
    init_encrypt_key_management();
    init_base64url();
    init_validate_crit();
  }
});

// ../../node_modules/jose/dist/browser/runtime/subtle_dsa.js
var init_subtle_dsa = __esm({
  "../../node_modules/jose/dist/browser/runtime/subtle_dsa.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_errors2();
  }
});

// ../../node_modules/jose/dist/browser/runtime/get_sign_verify_key.js
var init_get_sign_verify_key = __esm({
  "../../node_modules/jose/dist/browser/runtime/get_sign_verify_key.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_webcrypto();
    init_crypto_key();
    init_invalid_key_input();
    init_is_key_like();
  }
});

// ../../node_modules/jose/dist/browser/runtime/verify.js
var init_verify = __esm({
  "../../node_modules/jose/dist/browser/runtime/verify.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_subtle_dsa();
    init_webcrypto();
    init_check_key_length();
    init_get_sign_verify_key();
  }
});

// ../../node_modules/jose/dist/browser/jws/flattened/verify.js
var init_verify2 = __esm({
  "../../node_modules/jose/dist/browser/jws/flattened/verify.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_base64url();
    init_verify();
    init_errors2();
    init_buffer_utils();
    init_is_disjoint();
    init_is_object();
    init_check_key_type();
    init_validate_crit();
    init_validate_algorithms();
  }
});

// ../../node_modules/jose/dist/browser/jws/compact/verify.js
var init_verify3 = __esm({
  "../../node_modules/jose/dist/browser/jws/compact/verify.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_verify2();
    init_errors2();
    init_buffer_utils();
  }
});

// ../../node_modules/jose/dist/browser/jws/general/verify.js
var init_verify4 = __esm({
  "../../node_modules/jose/dist/browser/jws/general/verify.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_verify2();
    init_errors2();
    init_is_object();
  }
});

// ../../node_modules/jose/dist/browser/lib/epoch.js
var epoch_default;
var init_epoch = __esm({
  "../../node_modules/jose/dist/browser/lib/epoch.js"() {
    init_functionsRoutes_0_9412289658568613();
    epoch_default = (date) => Math.floor(date.getTime() / 1e3);
  }
});

// ../../node_modules/jose/dist/browser/lib/secs.js
var minute, hour, day, week, year, REGEX, secs_default;
var init_secs = __esm({
  "../../node_modules/jose/dist/browser/lib/secs.js"() {
    init_functionsRoutes_0_9412289658568613();
    minute = 60;
    hour = minute * 60;
    day = hour * 24;
    week = day * 7;
    year = day * 365.25;
    REGEX = /^(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)$/i;
    secs_default = (str) => {
      const matched = REGEX.exec(str);
      if (!matched) {
        throw new TypeError("Invalid time period format");
      }
      const value = parseFloat(matched[1]);
      const unit = matched[2].toLowerCase();
      switch (unit) {
        case "sec":
        case "secs":
        case "second":
        case "seconds":
        case "s":
          return Math.round(value);
        case "minute":
        case "minutes":
        case "min":
        case "mins":
        case "m":
          return Math.round(value * minute);
        case "hour":
        case "hours":
        case "hr":
        case "hrs":
        case "h":
          return Math.round(value * hour);
        case "day":
        case "days":
        case "d":
          return Math.round(value * day);
        case "week":
        case "weeks":
        case "w":
          return Math.round(value * week);
        default:
          return Math.round(value * year);
      }
    };
  }
});

// ../../node_modules/jose/dist/browser/lib/jwt_claims_set.js
var normalizeTyp, checkAudiencePresence, jwt_claims_set_default;
var init_jwt_claims_set = __esm({
  "../../node_modules/jose/dist/browser/lib/jwt_claims_set.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_errors2();
    init_buffer_utils();
    init_epoch();
    init_secs();
    init_is_object();
    normalizeTyp = (value) => value.toLowerCase().replace(/^application\//, "");
    checkAudiencePresence = (audPayload, audOption) => {
      if (typeof audPayload === "string") {
        return audOption.includes(audPayload);
      }
      if (Array.isArray(audPayload)) {
        return audOption.some(Set.prototype.has.bind(new Set(audPayload)));
      }
      return false;
    };
    jwt_claims_set_default = (protectedHeader, encodedPayload, options = {}) => {
      const { typ } = options;
      if (typ && (typeof protectedHeader.typ !== "string" || normalizeTyp(protectedHeader.typ) !== normalizeTyp(typ))) {
        throw new JWTClaimValidationFailed('unexpected "typ" JWT header value', "typ", "check_failed");
      }
      let payload;
      try {
        payload = JSON.parse(decoder.decode(encodedPayload));
      } catch (_a) {
      }
      if (!isObject(payload)) {
        throw new JWTInvalid("JWT Claims Set must be a top-level JSON object");
      }
      const { requiredClaims = [], issuer, subject, audience, maxTokenAge } = options;
      if (maxTokenAge !== void 0)
        requiredClaims.push("iat");
      if (audience !== void 0)
        requiredClaims.push("aud");
      if (subject !== void 0)
        requiredClaims.push("sub");
      if (issuer !== void 0)
        requiredClaims.push("iss");
      for (const claim of new Set(requiredClaims.reverse())) {
        if (!(claim in payload)) {
          throw new JWTClaimValidationFailed(`missing required "${claim}" claim`, claim, "missing");
        }
      }
      if (issuer && !(Array.isArray(issuer) ? issuer : [issuer]).includes(payload.iss)) {
        throw new JWTClaimValidationFailed('unexpected "iss" claim value', "iss", "check_failed");
      }
      if (subject && payload.sub !== subject) {
        throw new JWTClaimValidationFailed('unexpected "sub" claim value', "sub", "check_failed");
      }
      if (audience && !checkAudiencePresence(payload.aud, typeof audience === "string" ? [audience] : audience)) {
        throw new JWTClaimValidationFailed('unexpected "aud" claim value', "aud", "check_failed");
      }
      let tolerance;
      switch (typeof options.clockTolerance) {
        case "string":
          tolerance = secs_default(options.clockTolerance);
          break;
        case "number":
          tolerance = options.clockTolerance;
          break;
        case "undefined":
          tolerance = 0;
          break;
        default:
          throw new TypeError("Invalid clockTolerance option type");
      }
      const { currentDate } = options;
      const now2 = epoch_default(currentDate || new Date());
      if ((payload.iat !== void 0 || maxTokenAge) && typeof payload.iat !== "number") {
        throw new JWTClaimValidationFailed('"iat" claim must be a number', "iat", "invalid");
      }
      if (payload.nbf !== void 0) {
        if (typeof payload.nbf !== "number") {
          throw new JWTClaimValidationFailed('"nbf" claim must be a number', "nbf", "invalid");
        }
        if (payload.nbf > now2 + tolerance) {
          throw new JWTClaimValidationFailed('"nbf" claim timestamp check failed', "nbf", "check_failed");
        }
      }
      if (payload.exp !== void 0) {
        if (typeof payload.exp !== "number") {
          throw new JWTClaimValidationFailed('"exp" claim must be a number', "exp", "invalid");
        }
        if (payload.exp <= now2 - tolerance) {
          throw new JWTExpired('"exp" claim timestamp check failed', "exp", "check_failed");
        }
      }
      if (maxTokenAge) {
        const age = now2 - payload.iat;
        const max = typeof maxTokenAge === "number" ? maxTokenAge : secs_default(maxTokenAge);
        if (age - tolerance > max) {
          throw new JWTExpired('"iat" claim timestamp check failed (too far in the past)', "iat", "check_failed");
        }
        if (age < 0 - tolerance) {
          throw new JWTClaimValidationFailed('"iat" claim timestamp check failed (it should be in the past)', "iat", "check_failed");
        }
      }
      return payload;
    };
  }
});

// ../../node_modules/jose/dist/browser/jwt/verify.js
var init_verify5 = __esm({
  "../../node_modules/jose/dist/browser/jwt/verify.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_verify3();
    init_jwt_claims_set();
    init_errors2();
  }
});

// ../../node_modules/jose/dist/browser/jwt/decrypt.js
async function jwtDecrypt(jwt2, key, options) {
  const decrypted = await compactDecrypt(jwt2, key, options);
  const payload = jwt_claims_set_default(decrypted.protectedHeader, decrypted.plaintext, options);
  const { protectedHeader } = decrypted;
  if (protectedHeader.iss !== void 0 && protectedHeader.iss !== payload.iss) {
    throw new JWTClaimValidationFailed('replicated "iss" claim header parameter mismatch', "iss", "mismatch");
  }
  if (protectedHeader.sub !== void 0 && protectedHeader.sub !== payload.sub) {
    throw new JWTClaimValidationFailed('replicated "sub" claim header parameter mismatch', "sub", "mismatch");
  }
  if (protectedHeader.aud !== void 0 && JSON.stringify(protectedHeader.aud) !== JSON.stringify(payload.aud)) {
    throw new JWTClaimValidationFailed('replicated "aud" claim header parameter mismatch', "aud", "mismatch");
  }
  const result = { payload, protectedHeader };
  if (typeof key === "function") {
    return { ...result, key: decrypted.key };
  }
  return result;
}
var init_decrypt5 = __esm({
  "../../node_modules/jose/dist/browser/jwt/decrypt.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_decrypt3();
    init_jwt_claims_set();
    init_errors2();
  }
});

// ../../node_modules/jose/dist/browser/jwe/compact/encrypt.js
var CompactEncrypt;
var init_encrypt4 = __esm({
  "../../node_modules/jose/dist/browser/jwe/compact/encrypt.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_encrypt2();
    CompactEncrypt = class {
      constructor(plaintext) {
        this._flattened = new FlattenedEncrypt(plaintext);
      }
      setContentEncryptionKey(cek) {
        this._flattened.setContentEncryptionKey(cek);
        return this;
      }
      setInitializationVector(iv) {
        this._flattened.setInitializationVector(iv);
        return this;
      }
      setProtectedHeader(protectedHeader) {
        this._flattened.setProtectedHeader(protectedHeader);
        return this;
      }
      setKeyManagementParameters(parameters) {
        this._flattened.setKeyManagementParameters(parameters);
        return this;
      }
      async encrypt(key, options) {
        const jwe = await this._flattened.encrypt(key, options);
        return [jwe.protected, jwe.encrypted_key, jwe.iv, jwe.ciphertext, jwe.tag].join(".");
      }
    };
  }
});

// ../../node_modules/jose/dist/browser/runtime/sign.js
var init_sign = __esm({
  "../../node_modules/jose/dist/browser/runtime/sign.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_subtle_dsa();
    init_webcrypto();
    init_check_key_length();
    init_get_sign_verify_key();
  }
});

// ../../node_modules/jose/dist/browser/jws/flattened/sign.js
var init_sign2 = __esm({
  "../../node_modules/jose/dist/browser/jws/flattened/sign.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_base64url();
    init_sign();
    init_is_disjoint();
    init_errors2();
    init_buffer_utils();
    init_check_key_type();
    init_validate_crit();
  }
});

// ../../node_modules/jose/dist/browser/jws/compact/sign.js
var init_sign3 = __esm({
  "../../node_modules/jose/dist/browser/jws/compact/sign.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_sign2();
  }
});

// ../../node_modules/jose/dist/browser/jws/general/sign.js
var init_sign4 = __esm({
  "../../node_modules/jose/dist/browser/jws/general/sign.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_sign2();
    init_errors2();
  }
});

// ../../node_modules/jose/dist/browser/jwt/produce.js
var ProduceJWT;
var init_produce = __esm({
  "../../node_modules/jose/dist/browser/jwt/produce.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_epoch();
    init_is_object();
    init_secs();
    ProduceJWT = class {
      constructor(payload) {
        if (!isObject(payload)) {
          throw new TypeError("JWT Claims Set MUST be an object");
        }
        this._payload = payload;
      }
      setIssuer(issuer) {
        this._payload = { ...this._payload, iss: issuer };
        return this;
      }
      setSubject(subject) {
        this._payload = { ...this._payload, sub: subject };
        return this;
      }
      setAudience(audience) {
        this._payload = { ...this._payload, aud: audience };
        return this;
      }
      setJti(jwtId) {
        this._payload = { ...this._payload, jti: jwtId };
        return this;
      }
      setNotBefore(input) {
        if (typeof input === "number") {
          this._payload = { ...this._payload, nbf: input };
        } else {
          this._payload = { ...this._payload, nbf: epoch_default(new Date()) + secs_default(input) };
        }
        return this;
      }
      setExpirationTime(input) {
        if (typeof input === "number") {
          this._payload = { ...this._payload, exp: input };
        } else {
          this._payload = { ...this._payload, exp: epoch_default(new Date()) + secs_default(input) };
        }
        return this;
      }
      setIssuedAt(input) {
        if (typeof input === "undefined") {
          this._payload = { ...this._payload, iat: epoch_default(new Date()) };
        } else {
          this._payload = { ...this._payload, iat: input };
        }
        return this;
      }
    };
  }
});

// ../../node_modules/jose/dist/browser/jwt/sign.js
var init_sign5 = __esm({
  "../../node_modules/jose/dist/browser/jwt/sign.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_sign3();
    init_errors2();
    init_buffer_utils();
    init_produce();
  }
});

// ../../node_modules/jose/dist/browser/jwt/encrypt.js
var EncryptJWT;
var init_encrypt5 = __esm({
  "../../node_modules/jose/dist/browser/jwt/encrypt.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_encrypt4();
    init_buffer_utils();
    init_produce();
    EncryptJWT = class extends ProduceJWT {
      setProtectedHeader(protectedHeader) {
        if (this._protectedHeader) {
          throw new TypeError("setProtectedHeader can only be called once");
        }
        this._protectedHeader = protectedHeader;
        return this;
      }
      setKeyManagementParameters(parameters) {
        if (this._keyManagementParameters) {
          throw new TypeError("setKeyManagementParameters can only be called once");
        }
        this._keyManagementParameters = parameters;
        return this;
      }
      setContentEncryptionKey(cek) {
        if (this._cek) {
          throw new TypeError("setContentEncryptionKey can only be called once");
        }
        this._cek = cek;
        return this;
      }
      setInitializationVector(iv) {
        if (this._iv) {
          throw new TypeError("setInitializationVector can only be called once");
        }
        this._iv = iv;
        return this;
      }
      replicateIssuerAsHeader() {
        this._replicateIssuerAsHeader = true;
        return this;
      }
      replicateSubjectAsHeader() {
        this._replicateSubjectAsHeader = true;
        return this;
      }
      replicateAudienceAsHeader() {
        this._replicateAudienceAsHeader = true;
        return this;
      }
      async encrypt(key, options) {
        const enc = new CompactEncrypt(encoder.encode(JSON.stringify(this._payload)));
        if (this._replicateIssuerAsHeader) {
          this._protectedHeader = { ...this._protectedHeader, iss: this._payload.iss };
        }
        if (this._replicateSubjectAsHeader) {
          this._protectedHeader = { ...this._protectedHeader, sub: this._payload.sub };
        }
        if (this._replicateAudienceAsHeader) {
          this._protectedHeader = { ...this._protectedHeader, aud: this._payload.aud };
        }
        enc.setProtectedHeader(this._protectedHeader);
        if (this._iv) {
          enc.setInitializationVector(this._iv);
        }
        if (this._cek) {
          enc.setContentEncryptionKey(this._cek);
        }
        if (this._keyManagementParameters) {
          enc.setKeyManagementParameters(this._keyManagementParameters);
        }
        return enc.encrypt(key, options);
      }
    };
  }
});

// ../../node_modules/jose/dist/browser/jwk/thumbprint.js
var init_thumbprint = __esm({
  "../../node_modules/jose/dist/browser/jwk/thumbprint.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_digest();
    init_base64url();
    init_errors2();
    init_buffer_utils();
    init_is_object();
  }
});

// ../../node_modules/jose/dist/browser/jwk/embedded.js
var init_embedded = __esm({
  "../../node_modules/jose/dist/browser/jwk/embedded.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_import();
    init_is_object();
    init_errors2();
  }
});

// ../../node_modules/jose/dist/browser/jwks/local.js
var init_local = __esm({
  "../../node_modules/jose/dist/browser/jwks/local.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_import();
    init_errors2();
    init_is_object();
  }
});

// ../../node_modules/jose/dist/browser/runtime/fetch_jwks.js
var init_fetch_jwks = __esm({
  "../../node_modules/jose/dist/browser/runtime/fetch_jwks.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_errors2();
  }
});

// ../../node_modules/jose/dist/browser/jwks/remote.js
var init_remote = __esm({
  "../../node_modules/jose/dist/browser/jwks/remote.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_fetch_jwks();
    init_errors2();
    init_local();
  }
});

// ../../node_modules/jose/dist/browser/jwt/unsecured.js
var init_unsecured = __esm({
  "../../node_modules/jose/dist/browser/jwt/unsecured.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_base64url();
    init_buffer_utils();
    init_errors2();
    init_jwt_claims_set();
    init_produce();
  }
});

// ../../node_modules/jose/dist/browser/util/base64url.js
var base64url_exports2 = {};
__export(base64url_exports2, {
  decode: () => decode2,
  encode: () => encode2
});
var encode2, decode2;
var init_base64url2 = __esm({
  "../../node_modules/jose/dist/browser/util/base64url.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_base64url();
    encode2 = encode;
    decode2 = decode;
  }
});

// ../../node_modules/jose/dist/browser/util/decode_protected_header.js
var init_decode_protected_header = __esm({
  "../../node_modules/jose/dist/browser/util/decode_protected_header.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_base64url2();
    init_buffer_utils();
    init_is_object();
  }
});

// ../../node_modules/jose/dist/browser/util/decode_jwt.js
var init_decode_jwt = __esm({
  "../../node_modules/jose/dist/browser/util/decode_jwt.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_base64url2();
    init_buffer_utils();
    init_is_object();
    init_errors2();
  }
});

// ../../node_modules/jose/dist/browser/runtime/generate.js
var init_generate = __esm({
  "../../node_modules/jose/dist/browser/runtime/generate.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_webcrypto();
    init_errors2();
    init_random();
  }
});

// ../../node_modules/jose/dist/browser/key/generate_key_pair.js
var init_generate_key_pair = __esm({
  "../../node_modules/jose/dist/browser/key/generate_key_pair.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_generate();
  }
});

// ../../node_modules/jose/dist/browser/key/generate_secret.js
var init_generate_secret = __esm({
  "../../node_modules/jose/dist/browser/key/generate_secret.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_generate();
  }
});

// ../../node_modules/jose/dist/browser/index.js
var init_browser = __esm({
  "../../node_modules/jose/dist/browser/index.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_decrypt3();
    init_decrypt2();
    init_decrypt4();
    init_encrypt3();
    init_verify3();
    init_verify2();
    init_verify4();
    init_verify5();
    init_decrypt5();
    init_encrypt4();
    init_encrypt2();
    init_sign3();
    init_sign2();
    init_sign4();
    init_sign5();
    init_encrypt5();
    init_thumbprint();
    init_embedded();
    init_local();
    init_remote();
    init_unsecured();
    init_export();
    init_import();
    init_decode_protected_header();
    init_decode_jwt();
    init_errors2();
    init_generate_key_pair();
    init_generate_secret();
    init_base64url2();
  }
});

// ../../node_modules/@auth/core/jwt.js
async function encode3(params) {
  const { token = {}, secret, maxAge = DEFAULT_MAX_AGE } = params;
  const encryptionSecret = await getDerivedEncryptionKey(secret);
  return await new EncryptJWT(token).setProtectedHeader({ alg: "dir", enc: "A256GCM" }).setIssuedAt().setExpirationTime(now() + maxAge).setJti(crypto.randomUUID()).encrypt(encryptionSecret);
}
async function decode3(params) {
  const { token, secret } = params;
  if (!token)
    return null;
  const encryptionSecret = await getDerivedEncryptionKey(secret);
  const { payload } = await jwtDecrypt(token, encryptionSecret, {
    clockTolerance: 15
  });
  return payload;
}
async function getDerivedEncryptionKey(secret) {
  return await hkdf("sha256", secret, "", "Auth.js Generated Encryption Key", 32);
}
var DEFAULT_MAX_AGE, now;
var init_jwt = __esm({
  "../../node_modules/@auth/core/jwt.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_web();
    init_browser();
    init_cookie();
    init_errors();
    DEFAULT_MAX_AGE = 30 * 24 * 60 * 60;
    now = () => Date.now() / 1e3 | 0;
  }
});

// ../../node_modules/@auth/core/lib/callback-url.js
async function createCallbackUrl({ options, paramValue, cookieValue }) {
  const { url, callbacks } = options;
  let callbackUrl = url.origin;
  if (paramValue) {
    callbackUrl = await callbacks.redirect({
      url: paramValue,
      baseUrl: url.origin
    });
  } else if (cookieValue) {
    callbackUrl = await callbacks.redirect({
      url: cookieValue,
      baseUrl: url.origin
    });
  }
  return {
    callbackUrl,
    callbackUrlCookie: callbackUrl !== cookieValue ? callbackUrl : void 0
  };
}
var init_callback_url = __esm({
  "../../node_modules/@auth/core/lib/callback-url.js"() {
    init_functionsRoutes_0_9412289658568613();
  }
});

// ../../node_modules/cookie/index.js
var require_cookie = __commonJS({
  "../../node_modules/cookie/index.js"(exports) {
    "use strict";
    init_functionsRoutes_0_9412289658568613();
    exports.parse = parse3;
    exports.serialize = serialize2;
    var __toString = Object.prototype.toString;
    var fieldContentRegExp = /^[\u0009\u0020-\u007e\u0080-\u00ff]+$/;
    function parse3(str, options) {
      if (typeof str !== "string") {
        throw new TypeError("argument str must be a string");
      }
      var obj = {};
      var opt = options || {};
      var dec = opt.decode || decode4;
      var index = 0;
      while (index < str.length) {
        var eqIdx = str.indexOf("=", index);
        if (eqIdx === -1) {
          break;
        }
        var endIdx = str.indexOf(";", index);
        if (endIdx === -1) {
          endIdx = str.length;
        } else if (endIdx < eqIdx) {
          index = str.lastIndexOf(";", eqIdx - 1) + 1;
          continue;
        }
        var key = str.slice(index, eqIdx).trim();
        if (void 0 === obj[key]) {
          var val = str.slice(eqIdx + 1, endIdx).trim();
          if (val.charCodeAt(0) === 34) {
            val = val.slice(1, -1);
          }
          obj[key] = tryDecode(val, dec);
        }
        index = endIdx + 1;
      }
      return obj;
    }
    function serialize2(name, val, options) {
      var opt = options || {};
      var enc = opt.encode || encode4;
      if (typeof enc !== "function") {
        throw new TypeError("option encode is invalid");
      }
      if (!fieldContentRegExp.test(name)) {
        throw new TypeError("argument name is invalid");
      }
      var value = enc(val);
      if (value && !fieldContentRegExp.test(value)) {
        throw new TypeError("argument val is invalid");
      }
      var str = name + "=" + value;
      if (null != opt.maxAge) {
        var maxAge = opt.maxAge - 0;
        if (isNaN(maxAge) || !isFinite(maxAge)) {
          throw new TypeError("option maxAge is invalid");
        }
        str += "; Max-Age=" + Math.floor(maxAge);
      }
      if (opt.domain) {
        if (!fieldContentRegExp.test(opt.domain)) {
          throw new TypeError("option domain is invalid");
        }
        str += "; Domain=" + opt.domain;
      }
      if (opt.path) {
        if (!fieldContentRegExp.test(opt.path)) {
          throw new TypeError("option path is invalid");
        }
        str += "; Path=" + opt.path;
      }
      if (opt.expires) {
        var expires = opt.expires;
        if (!isDate(expires) || isNaN(expires.valueOf())) {
          throw new TypeError("option expires is invalid");
        }
        str += "; Expires=" + expires.toUTCString();
      }
      if (opt.httpOnly) {
        str += "; HttpOnly";
      }
      if (opt.secure) {
        str += "; Secure";
      }
      if (opt.priority) {
        var priority = typeof opt.priority === "string" ? opt.priority.toLowerCase() : opt.priority;
        switch (priority) {
          case "low":
            str += "; Priority=Low";
            break;
          case "medium":
            str += "; Priority=Medium";
            break;
          case "high":
            str += "; Priority=High";
            break;
          default:
            throw new TypeError("option priority is invalid");
        }
      }
      if (opt.sameSite) {
        var sameSite = typeof opt.sameSite === "string" ? opt.sameSite.toLowerCase() : opt.sameSite;
        switch (sameSite) {
          case true:
            str += "; SameSite=Strict";
            break;
          case "lax":
            str += "; SameSite=Lax";
            break;
          case "strict":
            str += "; SameSite=Strict";
            break;
          case "none":
            str += "; SameSite=None";
            break;
          default:
            throw new TypeError("option sameSite is invalid");
        }
      }
      return str;
    }
    function decode4(str) {
      return str.indexOf("%") !== -1 ? decodeURIComponent(str) : str;
    }
    function encode4(val) {
      return encodeURIComponent(val);
    }
    function isDate(val) {
      return __toString.call(val) === "[object Date]" || val instanceof Date;
    }
    function tryDecode(str, decode5) {
      try {
        return decode5(str);
      } catch (e2) {
        return str;
      }
    }
  }
});

// ../../node_modules/@auth/core/lib/web.js
async function getBody(req) {
  if (!("body" in req) || !req.body || req.method !== "POST")
    return;
  const contentType = req.headers.get("content-type");
  if (contentType?.includes("application/json")) {
    return await req.json();
  } else if (contentType?.includes("application/x-www-form-urlencoded")) {
    const params = new URLSearchParams(await req.text());
    return Object.fromEntries(params);
  }
}
async function toInternalRequest(req) {
  try {
    const url = new URL(req.url.replace(/\/$/, ""));
    url.searchParams.delete("nextauth");
    const { pathname } = url;
    const action = actions.find((a3) => pathname.includes(a3));
    if (!action) {
      throw new UnknownAction(`Cannot detect action in pathname (${pathname}).`);
    }
    if (req.method !== "GET" && req.method !== "POST") {
      throw new UnknownAction("Only GET and POST requests are supported.");
    }
    const providerIdOrAction = pathname.split("/").pop();
    let providerId;
    if (providerIdOrAction && !action.includes(providerIdOrAction) && ["signin", "callback"].includes(action)) {
      providerId = providerIdOrAction;
    }
    return {
      url,
      action,
      providerId,
      method: req.method,
      headers: Object.fromEntries(req.headers),
      body: req.body ? await getBody(req) : void 0,
      cookies: (0, import_cookie3.parse)(req.headers.get("cookie") ?? "") ?? {},
      error: url.searchParams.get("error") ?? void 0,
      query: Object.fromEntries(url.searchParams)
    };
  } catch (e2) {
    return e2;
  }
}
function toResponse(res) {
  const headers = new Headers(res.headers);
  res.cookies?.forEach((cookie) => {
    const { name, value, options } = cookie;
    const cookieHeader = (0, import_cookie3.serialize)(name, value, options);
    if (headers.has("Set-Cookie"))
      headers.append("Set-Cookie", cookieHeader);
    else
      headers.set("Set-Cookie", cookieHeader);
  });
  let body = res.body;
  if (headers.get("content-type") === "application/json")
    body = JSON.stringify(res.body);
  else if (headers.get("content-type") === "application/x-www-form-urlencoded")
    body = new URLSearchParams(res.body).toString();
  const status = res.redirect ? 302 : res.status ?? 200;
  const response = new Response(body, { headers, status });
  if (res.redirect)
    response.headers.set("Location", res.redirect);
  return response;
}
async function createHash(message2) {
  const data = new TextEncoder().encode(message2);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map((b3) => b3.toString(16).padStart(2, "0")).join("").toString();
}
function randomString(size) {
  const i2hex = (i3) => ("0" + i3.toString(16)).slice(-2);
  const r3 = (a3, i3) => a3 + i2hex(i3);
  const bytes = crypto.getRandomValues(new Uint8Array(size));
  return Array.from(bytes).reduce(r3, "");
}
var import_cookie3, actions;
var init_web2 = __esm({
  "../../node_modules/@auth/core/lib/web.js"() {
    init_functionsRoutes_0_9412289658568613();
    import_cookie3 = __toESM(require_cookie(), 1);
    init_errors();
    actions = [
      "providers",
      "session",
      "csrf",
      "signin",
      "signout",
      "callback",
      "verify-request",
      "error"
    ];
  }
});

// ../../node_modules/@auth/core/lib/csrf-token.js
async function createCSRFToken({ options, cookieValue, isPost, bodyValue }) {
  if (cookieValue) {
    const [csrfToken2, csrfTokenHash2] = cookieValue.split("|");
    const expectedCsrfTokenHash = await createHash(`${csrfToken2}${options.secret}`);
    if (csrfTokenHash2 === expectedCsrfTokenHash) {
      const csrfTokenVerified = isPost && csrfToken2 === bodyValue;
      return { csrfTokenVerified, csrfToken: csrfToken2 };
    }
  }
  const csrfToken = randomString(32);
  const csrfTokenHash = await createHash(`${csrfToken}${options.secret}`);
  const cookie = `${csrfToken}|${csrfTokenHash}`;
  return { cookie, csrfToken };
}
var init_csrf_token = __esm({
  "../../node_modules/@auth/core/lib/csrf-token.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_web2();
  }
});

// ../../node_modules/@auth/core/lib/default-callbacks.js
var defaultCallbacks;
var init_default_callbacks = __esm({
  "../../node_modules/@auth/core/lib/default-callbacks.js"() {
    init_functionsRoutes_0_9412289658568613();
    defaultCallbacks = {
      signIn() {
        return true;
      },
      redirect({ url, baseUrl }) {
        if (url.startsWith("/"))
          return `${baseUrl}${url}`;
        else if (new URL(url).origin === baseUrl)
          return url;
        return baseUrl;
      },
      session({ session: session2 }) {
        return session2;
      },
      jwt({ token }) {
        return token;
      }
    };
  }
});

// ../../node_modules/@auth/core/lib/utils/merge.js
function isObject2(item) {
  return item && typeof item === "object" && !Array.isArray(item);
}
function merge(target, ...sources) {
  if (!sources.length)
    return target;
  const source = sources.shift();
  if (isObject2(target) && isObject2(source)) {
    for (const key in source) {
      if (isObject2(source[key])) {
        if (!target[key])
          Object.assign(target, { [key]: {} });
        merge(target[key], source[key]);
      } else {
        Object.assign(target, { [key]: source[key] });
      }
    }
  }
  return merge(target, ...sources);
}
var init_merge = __esm({
  "../../node_modules/@auth/core/lib/utils/merge.js"() {
    init_functionsRoutes_0_9412289658568613();
  }
});

// ../../node_modules/@auth/core/lib/providers.js
function parseProviders(params) {
  const { url, providerId, options } = params;
  const providers2 = params.providers.map((p3) => {
    const provider = typeof p3 === "function" ? p3() : p3;
    const { options: userOptions, ...defaults } = provider;
    const id = userOptions?.id ?? defaults.id;
    const merged = merge(defaults, userOptions, {
      signinUrl: `${url}/signin/${id}`,
      callbackUrl: `${url}/callback/${id}`
    });
    if (provider.type === "oauth" || provider.type === "oidc") {
      merged.redirectProxyUrl ?? (merged.redirectProxyUrl = options.redirectProxyUrl);
      return normalizeOAuth(merged);
    }
    return merged;
  });
  return {
    providers: providers2,
    provider: providers2.find(({ id }) => id === providerId)
  };
}
function normalizeOAuth(c3) {
  if (c3.issuer)
    c3.wellKnown ?? (c3.wellKnown = `${c3.issuer}/.well-known/openid-configuration`);
  const authorization = normalizeEndpoint(c3.authorization, c3.issuer);
  if (authorization && !authorization.url?.searchParams.has("scope")) {
    authorization.url.searchParams.set("scope", "openid profile email");
  }
  const token = normalizeEndpoint(c3.token, c3.issuer);
  const userinfo = normalizeEndpoint(c3.userinfo, c3.issuer);
  const checks = c3.checks ?? ["pkce"];
  if (c3.redirectProxyUrl) {
    if (!checks.includes("state"))
      checks.push("state");
    c3.redirectProxyUrl = `${c3.redirectProxyUrl}/callback/${c3.id}`;
  }
  return {
    ...c3,
    authorization,
    token,
    checks,
    userinfo,
    profile: c3.profile ?? defaultProfile,
    account: c3.account ?? defaultAccount
  };
}
function stripUndefined(o4) {
  const result = {};
  for (let [k3, v3] of Object.entries(o4))
    v3 !== void 0 && (result[k3] = v3);
  return result;
}
function normalizeEndpoint(e2, issuer) {
  if (!e2 && issuer)
    return;
  if (typeof e2 === "string") {
    return { url: new URL(e2) };
  }
  const url = new URL(e2?.url ?? "https://authjs.dev");
  if (e2?.params != null) {
    for (let [key, value] of Object.entries(e2.params)) {
      if (key === "claims")
        value = JSON.stringify(value);
      url.searchParams.set(key, String(value));
    }
  }
  return { url, request: e2?.request, conform: e2?.conform };
}
var defaultProfile, defaultAccount;
var init_providers = __esm({
  "../../node_modules/@auth/core/lib/providers.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_errors();
    init_merge();
    defaultProfile = (profile) => {
      const id = profile.sub ?? profile.id;
      if (!id)
        throw new OAuthProfileParseError("Missing user id");
      return stripUndefined({
        id: id.toString(),
        name: profile.name ?? profile.nickname ?? profile.preferred_username,
        email: profile.email,
        image: profile.picture
      });
    };
    defaultAccount = (account) => {
      return stripUndefined({
        access_token: account.access_token,
        id_token: account.id_token,
        refresh_token: account.refresh_token,
        expires_at: account.expires_at,
        scope: account.scope,
        token_type: account.token_type,
        session_state: account.session_state
      });
    };
  }
});

// ../../node_modules/@auth/core/lib/utils/logger.js
function setLogger(newLogger = {}, debug) {
  if (!debug)
    logger.debug = () => {
    };
  if (newLogger.error)
    logger.error = newLogger.error;
  if (newLogger.warn)
    logger.warn = newLogger.warn;
  if (newLogger.debug)
    logger.debug = newLogger.debug;
}
var red, yellow, grey, reset, logger;
var init_logger = __esm({
  "../../node_modules/@auth/core/lib/utils/logger.js"() {
    init_functionsRoutes_0_9412289658568613();
    red = "\x1B[31m";
    yellow = "\x1B[33m";
    grey = "\x1B[90m";
    reset = "\x1B[0m";
    logger = {
      error(error) {
        const url = `https://errors.authjs.dev#${error.name.toLowerCase()}`;
        console.error(`${red}[auth][error][${error.name}]${reset}:${error.message ? ` ${error.message}.` : ""} Read more at ${url}`);
        if (error.cause) {
          const { err, ...data } = error.cause;
          console.error(`${red}[auth][cause]${reset}:`, err.stack);
          console.error(`${red}[auth][details]${reset}:`, JSON.stringify(data, null, 2));
        } else if (error.stack) {
          console.error(error.stack.replace(/.*/, "").substring(1));
        }
      },
      warn(code) {
        const url = `https://warnings.authjs.dev#${code}`;
        console.warn(`${yellow}[auth][warn][${code}]${reset}`, `Read more: ${url}`);
      },
      debug(message2, metadata) {
        console.log(`${grey}[auth][debug]:${reset} ${message2}`, JSON.stringify(metadata, null, 2));
      }
    };
  }
});

// ../../node_modules/@auth/core/lib/utils/parse-url.js
function parseUrl(url) {
  const defaultUrl = new URL("http://localhost:3000/api/auth");
  if (url && !url.toString().startsWith("http")) {
    url = `https://${url}`;
  }
  const _url = new URL(url ?? defaultUrl);
  const path = (_url.pathname === "/" ? defaultUrl.pathname : _url.pathname).replace(/\/$/, "");
  const base = `${_url.origin}${path}`;
  return {
    origin: _url.origin,
    host: _url.host,
    path,
    base,
    toString: () => base
  };
}
var init_parse_url = __esm({
  "../../node_modules/@auth/core/lib/utils/parse-url.js"() {
    init_functionsRoutes_0_9412289658568613();
  }
});

// ../../node_modules/@auth/core/lib/init.js
async function init({ authOptions, providerId, action, url: reqUrl, cookies: reqCookies, callbackUrl: reqCallbackUrl, csrfToken: reqCsrfToken, csrfDisabled, isPost }) {
  const parsed = parseUrl(reqUrl.origin + reqUrl.pathname.replace(`/${action}`, "").replace(`/${providerId}`, ""));
  const url = new URL(parsed.toString());
  const { providers: providers2, provider } = parseProviders({
    providers: authOptions.providers,
    url,
    providerId,
    options: authOptions
  });
  const maxAge = 30 * 24 * 60 * 60;
  let isOnRedirectProxy = false;
  if ((provider?.type === "oauth" || provider?.type === "oidc") && provider.redirectProxyUrl) {
    try {
      isOnRedirectProxy = new URL(provider.redirectProxyUrl).origin === url.origin;
    } catch {
      throw new TypeError(`redirectProxyUrl must be a valid URL. Received: ${provider.redirectProxyUrl}`);
    }
  }
  const options = {
    debug: false,
    pages: {},
    theme: {
      colorScheme: "auto",
      logo: "",
      brandColor: "",
      buttonText: ""
    },
    ...authOptions,
    url,
    action,
    provider,
    cookies: {
      ...defaultCookies(authOptions.useSecureCookies ?? url.protocol === "https:"),
      ...authOptions.cookies
    },
    providers: providers2,
    session: {
      strategy: authOptions.adapter ? "database" : "jwt",
      maxAge,
      updateAge: 24 * 60 * 60,
      generateSessionToken: () => crypto.randomUUID(),
      ...authOptions.session
    },
    jwt: {
      secret: authOptions.secret,
      maxAge: authOptions.session?.maxAge ?? maxAge,
      encode: encode3,
      decode: decode3,
      ...authOptions.jwt
    },
    events: eventsErrorHandler(authOptions.events ?? {}, logger),
    adapter: adapterErrorHandler(authOptions.adapter, logger),
    callbacks: { ...defaultCallbacks, ...authOptions.callbacks },
    logger,
    callbackUrl: url.origin,
    isOnRedirectProxy
  };
  const cookies = [];
  if (!csrfDisabled) {
    const { csrfToken, cookie: csrfCookie, csrfTokenVerified } = await createCSRFToken({
      options,
      cookieValue: reqCookies?.[options.cookies.csrfToken.name],
      isPost,
      bodyValue: reqCsrfToken
    });
    options.csrfToken = csrfToken;
    options.csrfTokenVerified = csrfTokenVerified;
    if (csrfCookie) {
      cookies.push({
        name: options.cookies.csrfToken.name,
        value: csrfCookie,
        options: options.cookies.csrfToken.options
      });
    }
  }
  const { callbackUrl, callbackUrlCookie } = await createCallbackUrl({
    options,
    cookieValue: reqCookies?.[options.cookies.callbackUrl.name],
    paramValue: reqCallbackUrl
  });
  options.callbackUrl = callbackUrl;
  if (callbackUrlCookie) {
    cookies.push({
      name: options.cookies.callbackUrl.name,
      value: callbackUrlCookie,
      options: options.cookies.callbackUrl.options
    });
  }
  return { options, cookies };
}
function eventsErrorHandler(methods, logger2) {
  return Object.keys(methods).reduce((acc, name) => {
    acc[name] = async (...args) => {
      try {
        const method = methods[name];
        return await method(...args);
      } catch (e2) {
        logger2.error(new EventError(e2));
      }
    };
    return acc;
  }, {});
}
function adapterErrorHandler(adapter, logger2) {
  if (!adapter)
    return;
  return Object.keys(adapter).reduce((acc, name) => {
    acc[name] = async (...args) => {
      try {
        logger2.debug(`adapter_${name}`, { args });
        const method = adapter[name];
        return await method(...args);
      } catch (e2) {
        const error = new AdapterError(e2);
        logger2.error(error);
        throw error;
      }
    };
    return acc;
  }, {});
}
var init_init = __esm({
  "../../node_modules/@auth/core/lib/init.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_jwt();
    init_callback_url();
    init_cookie();
    init_csrf_token();
    init_default_callbacks();
    init_errors();
    init_providers();
    init_logger();
    init_parse_url();
  }
});

// ../../node_modules/preact/dist/preact.module.js
function s(n3, l3) {
  for (var u3 in l3)
    n3[u3] = l3[u3];
  return n3;
}
function a(n3) {
  var l3 = n3.parentNode;
  l3 && l3.removeChild(n3);
}
function v(n3, i3, t2, o4, r3) {
  var f3 = { type: n3, props: i3, key: t2, ref: o4, __k: null, __: null, __b: 0, __e: null, __d: void 0, __c: null, __h: null, constructor: void 0, __v: null == r3 ? ++u : r3 };
  return null == r3 && null != l.vnode && l.vnode(f3), f3;
}
function p(n3) {
  return n3.children;
}
function d(n3, l3) {
  this.props = n3, this.context = l3;
}
function _(n3, l3) {
  if (null == l3)
    return n3.__ ? _(n3.__, n3.__.__k.indexOf(n3) + 1) : null;
  for (var u3; l3 < n3.__k.length; l3++)
    if (null != (u3 = n3.__k[l3]) && null != u3.__e)
      return u3.__e;
  return "function" == typeof n3.type ? _(n3) : null;
}
function k(n3) {
  var l3, u3;
  if (null != (n3 = n3.__) && null != n3.__c) {
    for (n3.__e = n3.__c.base = null, l3 = 0; l3 < n3.__k.length; l3++)
      if (null != (u3 = n3.__k[l3]) && null != u3.__e) {
        n3.__e = n3.__c.base = u3.__e;
        break;
      }
    return k(n3);
  }
}
function b(n3) {
  (!n3.__d && (n3.__d = true) && t.push(n3) && !g.__r++ || o !== l.debounceRendering) && ((o = l.debounceRendering) || setTimeout)(g);
}
function g() {
  for (var n3; g.__r = t.length; )
    n3 = t.sort(function(n4, l3) {
      return n4.__v.__b - l3.__v.__b;
    }), t = [], n3.some(function(n4) {
      var l3, u3, i3, t2, o4, r3;
      n4.__d && (o4 = (t2 = (l3 = n4).__v).__e, (r3 = l3.__P) && (u3 = [], (i3 = s({}, t2)).__v = t2.__v + 1, j(r3, t2, i3, l3.__n, void 0 !== r3.ownerSVGElement, null != t2.__h ? [o4] : null, u3, null == o4 ? _(t2) : o4, t2.__h), z(u3, t2), t2.__e != o4 && k(t2)));
    });
}
function w(n3, l3, u3, i3, t2, o4, r3, c3, s3, a3) {
  var h2, y2, d3, k3, b3, g3, w3, x2 = i3 && i3.__k || e, C3 = x2.length;
  for (u3.__k = [], h2 = 0; h2 < l3.length; h2++)
    if (null != (k3 = u3.__k[h2] = null == (k3 = l3[h2]) || "boolean" == typeof k3 ? null : "string" == typeof k3 || "number" == typeof k3 || "bigint" == typeof k3 ? v(null, k3, null, null, k3) : Array.isArray(k3) ? v(p, { children: k3 }, null, null, null) : k3.__b > 0 ? v(k3.type, k3.props, k3.key, k3.ref ? k3.ref : null, k3.__v) : k3)) {
      if (k3.__ = u3, k3.__b = u3.__b + 1, null === (d3 = x2[h2]) || d3 && k3.key == d3.key && k3.type === d3.type)
        x2[h2] = void 0;
      else
        for (y2 = 0; y2 < C3; y2++) {
          if ((d3 = x2[y2]) && k3.key == d3.key && k3.type === d3.type) {
            x2[y2] = void 0;
            break;
          }
          d3 = null;
        }
      j(n3, k3, d3 = d3 || f, t2, o4, r3, c3, s3, a3), b3 = k3.__e, (y2 = k3.ref) && d3.ref != y2 && (w3 || (w3 = []), d3.ref && w3.push(d3.ref, null, k3), w3.push(y2, k3.__c || b3, k3)), null != b3 ? (null == g3 && (g3 = b3), "function" == typeof k3.type && k3.__k === d3.__k ? k3.__d = s3 = m(k3, s3, n3) : s3 = A(n3, k3, d3, x2, b3, s3), "function" == typeof u3.type && (u3.__d = s3)) : s3 && d3.__e == s3 && s3.parentNode != n3 && (s3 = _(d3));
    }
  for (u3.__e = g3, h2 = C3; h2--; )
    null != x2[h2] && N(x2[h2], x2[h2]);
  if (w3)
    for (h2 = 0; h2 < w3.length; h2++)
      M(w3[h2], w3[++h2], w3[++h2]);
}
function m(n3, l3, u3) {
  for (var i3, t2 = n3.__k, o4 = 0; t2 && o4 < t2.length; o4++)
    (i3 = t2[o4]) && (i3.__ = n3, l3 = "function" == typeof i3.type ? m(i3, l3, u3) : A(u3, i3, i3, t2, i3.__e, l3));
  return l3;
}
function A(n3, l3, u3, i3, t2, o4) {
  var r3, f3, e2;
  if (void 0 !== l3.__d)
    r3 = l3.__d, l3.__d = void 0;
  else if (null == u3 || t2 != o4 || null == t2.parentNode)
    n:
      if (null == o4 || o4.parentNode !== n3)
        n3.appendChild(t2), r3 = null;
      else {
        for (f3 = o4, e2 = 0; (f3 = f3.nextSibling) && e2 < i3.length; e2 += 1)
          if (f3 == t2)
            break n;
        n3.insertBefore(t2, o4), r3 = o4;
      }
  return void 0 !== r3 ? r3 : t2.nextSibling;
}
function C(n3, l3, u3, i3, t2) {
  var o4;
  for (o4 in u3)
    "children" === o4 || "key" === o4 || o4 in l3 || H(n3, o4, null, u3[o4], i3);
  for (o4 in l3)
    t2 && "function" != typeof l3[o4] || "children" === o4 || "key" === o4 || "value" === o4 || "checked" === o4 || u3[o4] === l3[o4] || H(n3, o4, l3[o4], u3[o4], i3);
}
function $(n3, l3, u3) {
  "-" === l3[0] ? n3.setProperty(l3, u3) : n3[l3] = null == u3 ? "" : "number" != typeof u3 || c.test(l3) ? u3 : u3 + "px";
}
function H(n3, l3, u3, i3, t2) {
  var o4;
  n:
    if ("style" === l3)
      if ("string" == typeof u3)
        n3.style.cssText = u3;
      else {
        if ("string" == typeof i3 && (n3.style.cssText = i3 = ""), i3)
          for (l3 in i3)
            u3 && l3 in u3 || $(n3.style, l3, "");
        if (u3)
          for (l3 in u3)
            i3 && u3[l3] === i3[l3] || $(n3.style, l3, u3[l3]);
      }
    else if ("o" === l3[0] && "n" === l3[1])
      o4 = l3 !== (l3 = l3.replace(/Capture$/, "")), l3 = l3.toLowerCase() in n3 ? l3.toLowerCase().slice(2) : l3.slice(2), n3.l || (n3.l = {}), n3.l[l3 + o4] = u3, u3 ? i3 || n3.addEventListener(l3, o4 ? T : I, o4) : n3.removeEventListener(l3, o4 ? T : I, o4);
    else if ("dangerouslySetInnerHTML" !== l3) {
      if (t2)
        l3 = l3.replace(/xlink(H|:h)/, "h").replace(/sName$/, "s");
      else if ("href" !== l3 && "list" !== l3 && "form" !== l3 && "tabIndex" !== l3 && "download" !== l3 && l3 in n3)
        try {
          n3[l3] = null == u3 ? "" : u3;
          break n;
        } catch (n4) {
        }
      "function" == typeof u3 || (null == u3 || false === u3 && -1 == l3.indexOf("-") ? n3.removeAttribute(l3) : n3.setAttribute(l3, u3));
    }
}
function I(n3) {
  this.l[n3.type + false](l.event ? l.event(n3) : n3);
}
function T(n3) {
  this.l[n3.type + true](l.event ? l.event(n3) : n3);
}
function j(n3, u3, i3, t2, o4, r3, f3, e2, c3) {
  var a3, h2, v3, y2, _4, k3, b3, g3, m3, x2, A2, C3, $2, H2, I2, T2 = u3.type;
  if (void 0 !== u3.constructor)
    return null;
  null != i3.__h && (c3 = i3.__h, e2 = u3.__e = i3.__e, u3.__h = null, r3 = [e2]), (a3 = l.__b) && a3(u3);
  try {
    n:
      if ("function" == typeof T2) {
        if (g3 = u3.props, m3 = (a3 = T2.contextType) && t2[a3.__c], x2 = a3 ? m3 ? m3.props.value : a3.__ : t2, i3.__c ? b3 = (h2 = u3.__c = i3.__c).__ = h2.__E : ("prototype" in T2 && T2.prototype.render ? u3.__c = h2 = new T2(g3, x2) : (u3.__c = h2 = new d(g3, x2), h2.constructor = T2, h2.render = O), m3 && m3.sub(h2), h2.props = g3, h2.state || (h2.state = {}), h2.context = x2, h2.__n = t2, v3 = h2.__d = true, h2.__h = [], h2._sb = []), null == h2.__s && (h2.__s = h2.state), null != T2.getDerivedStateFromProps && (h2.__s == h2.state && (h2.__s = s({}, h2.__s)), s(h2.__s, T2.getDerivedStateFromProps(g3, h2.__s))), y2 = h2.props, _4 = h2.state, v3)
          null == T2.getDerivedStateFromProps && null != h2.componentWillMount && h2.componentWillMount(), null != h2.componentDidMount && h2.__h.push(h2.componentDidMount);
        else {
          if (null == T2.getDerivedStateFromProps && g3 !== y2 && null != h2.componentWillReceiveProps && h2.componentWillReceiveProps(g3, x2), !h2.__e && null != h2.shouldComponentUpdate && false === h2.shouldComponentUpdate(g3, h2.__s, x2) || u3.__v === i3.__v) {
            for (h2.props = g3, h2.state = h2.__s, u3.__v !== i3.__v && (h2.__d = false), h2.__v = u3, u3.__e = i3.__e, u3.__k = i3.__k, u3.__k.forEach(function(n4) {
              n4 && (n4.__ = u3);
            }), A2 = 0; A2 < h2._sb.length; A2++)
              h2.__h.push(h2._sb[A2]);
            h2._sb = [], h2.__h.length && f3.push(h2);
            break n;
          }
          null != h2.componentWillUpdate && h2.componentWillUpdate(g3, h2.__s, x2), null != h2.componentDidUpdate && h2.__h.push(function() {
            h2.componentDidUpdate(y2, _4, k3);
          });
        }
        if (h2.context = x2, h2.props = g3, h2.__v = u3, h2.__P = n3, C3 = l.__r, $2 = 0, "prototype" in T2 && T2.prototype.render) {
          for (h2.state = h2.__s, h2.__d = false, C3 && C3(u3), a3 = h2.render(h2.props, h2.state, h2.context), H2 = 0; H2 < h2._sb.length; H2++)
            h2.__h.push(h2._sb[H2]);
          h2._sb = [];
        } else
          do {
            h2.__d = false, C3 && C3(u3), a3 = h2.render(h2.props, h2.state, h2.context), h2.state = h2.__s;
          } while (h2.__d && ++$2 < 25);
        h2.state = h2.__s, null != h2.getChildContext && (t2 = s(s({}, t2), h2.getChildContext())), v3 || null == h2.getSnapshotBeforeUpdate || (k3 = h2.getSnapshotBeforeUpdate(y2, _4)), I2 = null != a3 && a3.type === p && null == a3.key ? a3.props.children : a3, w(n3, Array.isArray(I2) ? I2 : [I2], u3, i3, t2, o4, r3, f3, e2, c3), h2.base = u3.__e, u3.__h = null, h2.__h.length && f3.push(h2), b3 && (h2.__E = h2.__ = null), h2.__e = false;
      } else
        null == r3 && u3.__v === i3.__v ? (u3.__k = i3.__k, u3.__e = i3.__e) : u3.__e = L(i3.__e, u3, i3, t2, o4, r3, f3, c3);
    (a3 = l.diffed) && a3(u3);
  } catch (n4) {
    u3.__v = null, (c3 || null != r3) && (u3.__e = e2, u3.__h = !!c3, r3[r3.indexOf(e2)] = null), l.__e(n4, u3, i3);
  }
}
function z(n3, u3) {
  l.__c && l.__c(u3, n3), n3.some(function(u4) {
    try {
      n3 = u4.__h, u4.__h = [], n3.some(function(n4) {
        n4.call(u4);
      });
    } catch (n4) {
      l.__e(n4, u4.__v);
    }
  });
}
function L(l3, u3, i3, t2, o4, r3, e2, c3) {
  var s3, h2, v3, y2 = i3.props, p3 = u3.props, d3 = u3.type, k3 = 0;
  if ("svg" === d3 && (o4 = true), null != r3) {
    for (; k3 < r3.length; k3++)
      if ((s3 = r3[k3]) && "setAttribute" in s3 == !!d3 && (d3 ? s3.localName === d3 : 3 === s3.nodeType)) {
        l3 = s3, r3[k3] = null;
        break;
      }
  }
  if (null == l3) {
    if (null === d3)
      return document.createTextNode(p3);
    l3 = o4 ? document.createElementNS("http://www.w3.org/2000/svg", d3) : document.createElement(d3, p3.is && p3), r3 = null, c3 = false;
  }
  if (null === d3)
    y2 === p3 || c3 && l3.data === p3 || (l3.data = p3);
  else {
    if (r3 = r3 && n.call(l3.childNodes), h2 = (y2 = i3.props || f).dangerouslySetInnerHTML, v3 = p3.dangerouslySetInnerHTML, !c3) {
      if (null != r3)
        for (y2 = {}, k3 = 0; k3 < l3.attributes.length; k3++)
          y2[l3.attributes[k3].name] = l3.attributes[k3].value;
      (v3 || h2) && (v3 && (h2 && v3.__html == h2.__html || v3.__html === l3.innerHTML) || (l3.innerHTML = v3 && v3.__html || ""));
    }
    if (C(l3, p3, y2, o4, c3), v3)
      u3.__k = [];
    else if (k3 = u3.props.children, w(l3, Array.isArray(k3) ? k3 : [k3], u3, i3, t2, o4 && "foreignObject" !== d3, r3, e2, r3 ? r3[0] : i3.__k && _(i3, 0), c3), null != r3)
      for (k3 = r3.length; k3--; )
        null != r3[k3] && a(r3[k3]);
    c3 || ("value" in p3 && void 0 !== (k3 = p3.value) && (k3 !== l3.value || "progress" === d3 && !k3 || "option" === d3 && k3 !== y2.value) && H(l3, "value", k3, y2.value, false), "checked" in p3 && void 0 !== (k3 = p3.checked) && k3 !== l3.checked && H(l3, "checked", k3, y2.checked, false));
  }
  return l3;
}
function M(n3, u3, i3) {
  try {
    "function" == typeof n3 ? n3(u3) : n3.current = u3;
  } catch (n4) {
    l.__e(n4, i3);
  }
}
function N(n3, u3, i3) {
  var t2, o4;
  if (l.unmount && l.unmount(n3), (t2 = n3.ref) && (t2.current && t2.current !== n3.__e || M(t2, null, u3)), null != (t2 = n3.__c)) {
    if (t2.componentWillUnmount)
      try {
        t2.componentWillUnmount();
      } catch (n4) {
        l.__e(n4, u3);
      }
    t2.base = t2.__P = null, n3.__c = void 0;
  }
  if (t2 = n3.__k)
    for (o4 = 0; o4 < t2.length; o4++)
      t2[o4] && N(t2[o4], u3, i3 || "function" != typeof n3.type);
  i3 || null == n3.__e || a(n3.__e), n3.__ = n3.__e = n3.__d = void 0;
}
function O(n3, l3, u3) {
  return this.constructor(n3, u3);
}
var n, l, u, i, t, o, r, f, e, c;
var init_preact_module = __esm({
  "../../node_modules/preact/dist/preact.module.js"() {
    init_functionsRoutes_0_9412289658568613();
    f = {};
    e = [];
    c = /acit|ex(?:s|g|n|p|$)|rph|grid|ows|mnc|ntw|ine[ch]|zoo|^ord|itera/i;
    n = e.slice, l = { __e: function(n3, l3, u3, i3) {
      for (var t2, o4, r3; l3 = l3.__; )
        if ((t2 = l3.__c) && !t2.__)
          try {
            if ((o4 = t2.constructor) && null != o4.getDerivedStateFromError && (t2.setState(o4.getDerivedStateFromError(n3)), r3 = t2.__d), null != t2.componentDidCatch && (t2.componentDidCatch(n3, i3 || {}), r3 = t2.__d), r3)
              return t2.__E = t2;
          } catch (l4) {
            n3 = l4;
          }
      throw n3;
    } }, u = 0, i = function(n3) {
      return null != n3 && void 0 === n3.constructor;
    }, d.prototype.setState = function(n3, l3) {
      var u3;
      u3 = null != this.__s && this.__s !== this.state ? this.__s : this.__s = s({}, this.state), "function" == typeof n3 && (n3 = n3(s({}, u3), this.props)), n3 && s(u3, n3), null != n3 && this.__v && (l3 && this._sb.push(l3), b(this));
    }, d.prototype.forceUpdate = function(n3) {
      this.__v && (this.__e = true, n3 && this.__h.push(n3), b(this));
    }, d.prototype.render = p, t = [], g.__r = 0, r = 0;
  }
});

// ../../node_modules/preact-render-to-string/dist/index.mjs
function l2(e2) {
  if (false === a2.test(e2 += ""))
    return e2;
  for (var t2 = 0, r3 = 0, n3 = "", o4 = ""; r3 < e2.length; r3++) {
    switch (e2.charCodeAt(r3)) {
      case 34:
        o4 = "&quot;";
        break;
      case 38:
        o4 = "&amp;";
        break;
      case 60:
        o4 = "&lt;";
        break;
      default:
        continue;
    }
    r3 !== t2 && (n3 += e2.slice(t2, r3)), n3 += o4, t2 = r3 + 1;
  }
  return r3 !== t2 && (n3 += e2.slice(t2, r3)), n3;
}
function p2(e2) {
  var t2 = "";
  for (var n3 in e2) {
    var o4 = e2[n3];
    null != o4 && "" !== o4 && (t2 && (t2 += " "), t2 += "-" == n3[0] ? n3 : c2[n3] || (c2[n3] = n3.replace(u2, "-$1").toLowerCase()), t2 = "number" == typeof o4 && false === r2.test(n3) ? t2 + ": " + o4 + "px;" : t2 + ": " + o4 + ";");
  }
  return t2 || void 0;
}
function _2(e2, t2) {
  return Array.isArray(t2) ? t2.reduce(_2, e2) : null != t2 && false !== t2 && e2.push(t2), e2;
}
function d2() {
  this.__d = true;
}
function v2(e2, t2) {
  return { __v: e2, context: t2, props: e2.props, setState: d2, forceUpdate: d2, __d: true, __h: [] };
}
function h(e2, t2) {
  var r3 = e2.contextType, n3 = r3 && t2[r3.__c];
  return null != r3 ? n3 ? n3.props.value : r3.__ : t2;
}
function y(r3, a3, c3, u3, d3, m3) {
  if (null == r3 || "boolean" == typeof r3)
    return "";
  if ("object" != typeof r3)
    return l2(r3);
  var b3 = c3.pretty, x2 = b3 && "string" == typeof b3 ? b3 : "	";
  if (Array.isArray(r3)) {
    for (var k3 = "", S2 = 0; S2 < r3.length; S2++)
      b3 && S2 > 0 && (k3 += "\n"), k3 += y(r3[S2], a3, c3, u3, d3, m3);
    return k3;
  }
  var w3, C3 = r3.type, O3 = r3.props, j3 = false;
  if ("function" == typeof C3) {
    if (j3 = true, !c3.shallow || !u3 && false !== c3.renderRootComponent) {
      if (C3 === p) {
        var A2 = [];
        return _2(A2, r3.props.children), y(A2, a3, c3, false !== c3.shallowHighOrder, d3, m3);
      }
      var F, H2 = r3.__c = v2(r3, a3);
      l.__b && l.__b(r3);
      var M2 = l.__r;
      if (C3.prototype && "function" == typeof C3.prototype.render) {
        var L2 = h(C3, a3);
        (H2 = r3.__c = new C3(O3, L2)).__v = r3, H2._dirty = H2.__d = true, H2.props = O3, null == H2.state && (H2.state = {}), null == H2._nextState && null == H2.__s && (H2._nextState = H2.__s = H2.state), H2.context = L2, C3.getDerivedStateFromProps ? H2.state = Object.assign({}, H2.state, C3.getDerivedStateFromProps(H2.props, H2.state)) : H2.componentWillMount && (H2.componentWillMount(), H2.state = H2._nextState !== H2.state ? H2._nextState : H2.__s !== H2.state ? H2.__s : H2.state), M2 && M2(r3), F = H2.render(H2.props, H2.state, H2.context);
      } else
        for (var T2 = h(C3, a3), E = 0; H2.__d && E++ < 25; )
          H2.__d = false, M2 && M2(r3), F = C3.call(r3.__c, O3, T2);
      return H2.getChildContext && (a3 = Object.assign({}, a3, H2.getChildContext())), l.diffed && l.diffed(r3), y(F, a3, c3, false !== c3.shallowHighOrder, d3, m3);
    }
    C3 = (w3 = C3).displayName || w3 !== Function && w3.name || function(e2) {
      var t2 = (Function.prototype.toString.call(e2).match(/^\s*function\s+([^( ]+)/) || "")[1];
      if (!t2) {
        for (var r4 = -1, n3 = g2.length; n3--; )
          if (g2[n3] === e2) {
            r4 = n3;
            break;
          }
        r4 < 0 && (r4 = g2.push(e2) - 1), t2 = "UnnamedComponent" + r4;
      }
      return t2;
    }(w3);
  }
  var $2, D, N2 = "<" + C3;
  if (O3) {
    var P = Object.keys(O3);
    c3 && true === c3.sortAttributes && P.sort();
    for (var W = 0; W < P.length; W++) {
      var I2 = P[W], R = O3[I2];
      if ("children" !== I2) {
        if (!o2.test(I2) && (c3 && c3.allAttributes || "key" !== I2 && "ref" !== I2 && "__self" !== I2 && "__source" !== I2)) {
          if ("defaultValue" === I2)
            I2 = "value";
          else if ("defaultChecked" === I2)
            I2 = "checked";
          else if ("defaultSelected" === I2)
            I2 = "selected";
          else if ("className" === I2) {
            if (void 0 !== O3.class)
              continue;
            I2 = "class";
          } else
            d3 && i2.test(I2) && (I2 = I2.toLowerCase().replace(/^xlink:?/, "xlink:"));
          if ("htmlFor" === I2) {
            if (O3.for)
              continue;
            I2 = "for";
          }
          "style" === I2 && R && "object" == typeof R && (R = p2(R)), "a" === I2[0] && "r" === I2[1] && "boolean" == typeof R && (R = String(R));
          var U = c3.attributeHook && c3.attributeHook(I2, R, a3, c3, j3);
          if (U || "" === U)
            N2 += U;
          else if ("dangerouslySetInnerHTML" === I2)
            D = R && R.__html;
          else if ("textarea" === C3 && "value" === I2)
            $2 = R;
          else if ((R || 0 === R || "" === R) && "function" != typeof R) {
            if (!(true !== R && "" !== R || (R = I2, c3 && c3.xml))) {
              N2 = N2 + " " + I2;
              continue;
            }
            if ("value" === I2) {
              if ("select" === C3) {
                m3 = R;
                continue;
              }
              "option" === C3 && m3 == R && void 0 === O3.selected && (N2 += " selected");
            }
            N2 = N2 + " " + I2 + '="' + l2(R) + '"';
          }
        }
      } else
        $2 = R;
    }
  }
  if (b3) {
    var V = N2.replace(/\n\s*/, " ");
    V === N2 || ~V.indexOf("\n") ? b3 && ~N2.indexOf("\n") && (N2 += "\n") : N2 = V;
  }
  if (N2 += ">", o2.test(C3))
    throw new Error(C3 + " is not a valid HTML tag name in " + N2);
  var q, z2 = n2.test(C3) || c3.voidElements && c3.voidElements.test(C3), Z = [];
  if (D)
    b3 && f2(D) && (D = "\n" + x2 + s2(D, x2)), N2 += D;
  else if (null != $2 && _2(q = [], $2).length) {
    for (var B = b3 && ~N2.indexOf("\n"), G = false, J = 0; J < q.length; J++) {
      var K = q[J];
      if (null != K && false !== K) {
        var Q = y(K, a3, c3, true, "svg" === C3 || "foreignObject" !== C3 && d3, m3);
        if (b3 && !B && f2(Q) && (B = true), Q)
          if (b3) {
            var X = Q.length > 0 && "<" != Q[0];
            G && X ? Z[Z.length - 1] += Q : Z.push(Q), G = X;
          } else
            Z.push(Q);
      }
    }
    if (b3 && B)
      for (var Y = Z.length; Y--; )
        Z[Y] = "\n" + x2 + s2(Z[Y], x2);
  }
  if (Z.length || D)
    N2 += Z.join("");
  else if (c3 && c3.xml)
    return N2.substring(0, N2.length - 1) + " />";
  return !z2 || q || D ? (b3 && ~N2.indexOf("\n") && (N2 += "\n"), N2 = N2 + "</" + C3 + ">") : N2 = N2.replace(/>$/, " />"), N2;
}
function k2(e2, r3, n3) {
  r3 = r3 || {};
  var o4, i3 = l.__s;
  return l.__s = true, o4 = n3 && (n3.pretty || n3.voidElements || n3.sortAttributes || n3.shallow || n3.allAttributes || n3.xml || n3.attributeHook) ? y(e2, r3, n3) : j2(e2, r3, false, void 0), l.__c && l.__c(e2, x), l.__s = i3, x.length = 0, o4;
}
function S(e2, t2) {
  return "className" === e2 ? "class" : "htmlFor" === e2 ? "for" : "defaultValue" === e2 ? "value" : "defaultChecked" === e2 ? "checked" : "defaultSelected" === e2 ? "selected" : t2 && i2.test(e2) ? e2.toLowerCase().replace(/^xlink:?/, "xlink:") : e2;
}
function w2(e2, t2) {
  return "style" === e2 && null != t2 && "object" == typeof t2 ? p2(t2) : "a" === e2[0] && "r" === e2[1] && "boolean" == typeof t2 ? String(t2) : t2;
}
function j2(r3, i3, a3, s3) {
  if (null == r3 || true === r3 || false === r3 || "" === r3)
    return "";
  if ("object" != typeof r3)
    return l2(r3);
  if (C2(r3)) {
    for (var f3 = "", c3 = 0; c3 < r3.length; c3++)
      f3 += j2(r3[c3], i3, a3, s3);
    return f3;
  }
  l.__b && l.__b(r3);
  var u3 = r3.type, p3 = r3.props;
  if ("function" == typeof u3) {
    if (u3 === p)
      return j2(r3.props.children, i3, a3, s3);
    var _4;
    _4 = u3.prototype && "function" == typeof u3.prototype.render ? function(e2, r4) {
      var n3 = e2.type, o4 = h(n3, r4), i4 = new n3(e2.props, o4);
      e2.__c = i4, i4.__v = e2, i4.__d = true, i4.props = e2.props, null == i4.state && (i4.state = {}), null == i4.__s && (i4.__s = i4.state), i4.context = o4, n3.getDerivedStateFromProps ? i4.state = O2({}, i4.state, n3.getDerivedStateFromProps(i4.props, i4.state)) : i4.componentWillMount && (i4.componentWillMount(), i4.state = i4.__s !== i4.state ? i4.__s : i4.state);
      var a4 = l.__r;
      return a4 && a4(e2), i4.render(i4.props, i4.state, i4.context);
    }(r3, i3) : function(e2, r4) {
      var n3, o4 = v2(e2, r4), i4 = h(e2.type, r4);
      e2.__c = o4;
      for (var a4 = l.__r, l3 = 0; o4.__d && l3++ < 25; )
        o4.__d = false, a4 && a4(e2), n3 = e2.type.call(o4, e2.props, i4);
      return n3;
    }(r3, i3);
    var d3 = r3.__c;
    d3.getChildContext && (i3 = O2({}, i3, d3.getChildContext()));
    var g3 = j2(_4, i3, a3, s3);
    return l.diffed && l.diffed(r3), g3;
  }
  var y2, m3, b3 = "<";
  if (b3 += u3, p3)
    for (var x2 in y2 = p3.children, p3) {
      var k3 = p3[x2];
      if (!("key" === x2 || "ref" === x2 || "__self" === x2 || "__source" === x2 || "children" === x2 || "className" === x2 && "class" in p3 || "htmlFor" === x2 && "for" in p3 || o2.test(x2))) {
        if (k3 = w2(x2 = S(x2, a3), k3), "dangerouslySetInnerHTML" === x2)
          m3 = k3 && k3.__html;
        else if ("textarea" === u3 && "value" === x2)
          y2 = k3;
        else if ((k3 || 0 === k3 || "" === k3) && "function" != typeof k3) {
          if (true === k3 || "" === k3) {
            k3 = x2, b3 = b3 + " " + x2;
            continue;
          }
          if ("value" === x2) {
            if ("select" === u3) {
              s3 = k3;
              continue;
            }
            "option" !== u3 || s3 != k3 || "selected" in p3 || (b3 += " selected");
          }
          b3 = b3 + " " + x2 + '="' + l2(k3) + '"';
        }
      }
    }
  var A2 = b3;
  if (b3 += ">", o2.test(u3))
    throw new Error(u3 + " is not a valid HTML tag name in " + b3);
  var F = "", H2 = false;
  if (m3)
    F += m3, H2 = true;
  else if ("string" == typeof y2)
    F += l2(y2), H2 = true;
  else if (C2(y2))
    for (var M2 = 0; M2 < y2.length; M2++) {
      var L2 = y2[M2];
      if (null != L2 && false !== L2) {
        var T2 = j2(L2, i3, "svg" === u3 || "foreignObject" !== u3 && a3, s3);
        T2 && (F += T2, H2 = true);
      }
    }
  else if (null != y2 && false !== y2 && true !== y2) {
    var E = j2(y2, i3, "svg" === u3 || "foreignObject" !== u3 && a3, s3);
    E && (F += E, H2 = true);
  }
  if (l.diffed && l.diffed(r3), H2)
    b3 += F;
  else if (n2.test(u3))
    return A2 + " />";
  return b3 + "</" + u3 + ">";
}
var r2, n2, o2, i2, a2, s2, f2, c2, u2, g2, m2, b2, x, C2, O2;
var init_dist = __esm({
  "../../node_modules/preact-render-to-string/dist/index.mjs"() {
    init_functionsRoutes_0_9412289658568613();
    init_preact_module();
    r2 = /acit|ex(?:s|g|n|p|$)|rph|grid|ows|mnc|ntw|ine[ch]|zoo|^ord|^--/i;
    n2 = /^(area|base|br|col|embed|hr|img|input|link|meta|param|source|track|wbr)$/;
    o2 = /[\s\n\\/='"\0<>]/;
    i2 = /^xlink:?./;
    a2 = /["&<]/;
    s2 = function(e2, t2) {
      return String(e2).replace(/(\n+)/g, "$1" + (t2 || "	"));
    };
    f2 = function(e2, t2, r3) {
      return String(e2).length > (t2 || 40) || !r3 && -1 !== String(e2).indexOf("\n") || -1 !== String(e2).indexOf("<");
    };
    c2 = {};
    u2 = /([A-Z])/g;
    g2 = [];
    m2 = { shallow: true };
    k2.render = k2;
    b2 = function(e2, t2) {
      return k2(e2, t2, m2);
    };
    x = [];
    C2 = Array.isArray;
    O2 = Object.assign;
    k2.shallowRender = b2;
  }
});

// ../../node_modules/preact/jsx-runtime/dist/jsxRuntime.module.js
function o3(o4, e2, n3, t2, f3) {
  var l3, s3, u3 = {};
  for (s3 in e2)
    "ref" == s3 ? l3 = e2[s3] : u3[s3] = e2[s3];
  var a3 = { type: o4, props: u3, key: n3, ref: l3, __k: null, __: null, __b: 0, __e: null, __d: void 0, __c: null, __h: null, constructor: void 0, __v: --_3, __source: f3, __self: t2 };
  if ("function" == typeof o4 && (l3 = o4.defaultProps))
    for (s3 in l3)
      void 0 === u3[s3] && (u3[s3] = l3[s3]);
  return l.vnode && l.vnode(a3), a3;
}
var _3;
var init_jsxRuntime_module = __esm({
  "../../node_modules/preact/jsx-runtime/dist/jsxRuntime.module.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_preact_module();
    init_preact_module();
    _3 = 0;
  }
});

// ../../node_modules/@auth/core/lib/pages/error.js
function ErrorPage(props) {
  const { url, error = "default", theme } = props;
  const signinPageUrl = `${url}/signin`;
  const errors = {
    default: {
      status: 200,
      heading: "Error",
      message: o3("p", { children: o3("a", { className: "site", href: url?.origin, children: url?.host }) })
    },
    configuration: {
      status: 500,
      heading: "Server error",
      message: o3("div", { children: [o3("p", { children: "There is a problem with the server configuration." }), o3("p", { children: "Check the server logs for more information." })] })
    },
    accessdenied: {
      status: 403,
      heading: "Access Denied",
      message: o3("div", { children: [o3("p", { children: "You do not have permission to sign in." }), o3("p", { children: o3("a", { className: "button", href: signinPageUrl, children: "Sign in" }) })] })
    },
    verification: {
      status: 403,
      heading: "Unable to sign in",
      message: o3("div", { children: [o3("p", { children: "The sign in link is no longer valid." }), o3("p", { children: "It may have been used already or it may have expired." })] }),
      signin: o3("p", { children: o3("a", { className: "button", href: signinPageUrl, children: "Sign in" }) })
    }
  };
  const { status, heading, message: message2, signin: signin2 } = errors[error.toLowerCase()] ?? errors.default;
  return {
    status,
    html: o3("div", { className: "error", children: [theme?.brandColor && o3("style", { dangerouslySetInnerHTML: {
      __html: `
        :root {
          --brand-color: ${theme?.brandColor}
        }
      `
    } }), o3("div", { className: "card", children: [theme?.logo && o3("img", { src: theme?.logo, alt: "Logo", className: "logo" }), o3("h1", { children: heading }), o3("div", { className: "message", children: message2 }), signin2] })] })
  };
}
var init_error = __esm({
  "../../node_modules/@auth/core/lib/pages/error.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_jsxRuntime_module();
  }
});

// ../../node_modules/@auth/core/lib/pages/signin.js
function SigninPage(props) {
  const { csrfToken, providers: providers2 = [], callbackUrl, theme, email: email2, error: errorType } = props;
  if (typeof document !== "undefined" && theme.brandColor) {
    document.documentElement.style.setProperty("--brand-color", theme.brandColor);
  }
  if (typeof document !== "undefined" && theme.buttonText) {
    document.documentElement.style.setProperty("--button-text-color", theme.buttonText);
  }
  const error = errorType && (signinErrors[errorType.toLowerCase()] ?? signinErrors.default);
  const logos = "https://authjs.dev/img/providers";
  return o3("div", { className: "signin", children: [theme.brandColor && o3("style", { dangerouslySetInnerHTML: {
    __html: `:root {--brand-color: ${theme.brandColor}}`
  } }), theme.buttonText && o3("style", { dangerouslySetInnerHTML: {
    __html: `
        :root {
          --button-text-color: ${theme.buttonText}
        }
      `
  } }), o3("div", { className: "card", children: [error && o3("div", { className: "error", children: o3("p", { children: error }) }), providers2.map((provider, i3) => o3("div", { className: "provider", children: [provider.type === "oauth" || provider.type === "oidc" ? o3("form", { action: provider.signinUrl, method: "POST", children: [o3("input", { type: "hidden", name: "csrfToken", value: csrfToken }), callbackUrl && o3("input", { type: "hidden", name: "callbackUrl", value: callbackUrl }), o3("button", { type: "submit", className: "button", style: {
    "--provider-bg": provider.style?.bg ?? "",
    "--provider-dark-bg": provider.style?.bgDark ?? "",
    "--provider-color": provider.style?.text ?? "",
    "--provider-dark-color": provider.style?.textDark ?? "",
    gap: 8
  }, children: [provider.style?.logo && o3("img", { loading: "lazy", height: 24, width: 24, id: "provider-logo", src: `${provider.style.logo.startsWith("/") ? logos : ""}${provider.style.logo}` }), provider.style?.logoDark && o3("img", { loading: "lazy", height: 24, width: 24, id: "provider-logo-dark", src: `${provider.style.logo.startsWith("/") ? logos : ""}${provider.style.logoDark}` }), o3("span", { children: ["Sign in with ", provider.name] })] })] }) : null, (provider.type === "email" || provider.type === "credentials") && i3 > 0 && providers2[i3 - 1].type !== "email" && providers2[i3 - 1].type !== "credentials" && o3("hr", {}), provider.type === "email" && o3("form", { action: provider.signinUrl, method: "POST", children: [o3("input", { type: "hidden", name: "csrfToken", value: csrfToken }), o3("label", { className: "section-header", htmlFor: `input-email-for-${provider.id}-provider`, children: "Email" }), o3("input", { id: `input-email-for-${provider.id}-provider`, autoFocus: true, type: "email", name: "email", value: email2, placeholder: "email@example.com", required: true }), o3("button", { type: "submit", children: ["Sign in with ", provider.name] })] }), provider.type === "credentials" && o3("form", { action: provider.callbackUrl, method: "POST", children: [o3("input", { type: "hidden", name: "csrfToken", value: csrfToken }), Object.keys(provider.credentials).map((credential) => {
    return o3("div", { children: [o3("label", { className: "section-header", htmlFor: `input-${credential}-for-${provider.id}-provider`, children: provider.credentials[credential].label ?? credential }), o3("input", { name: credential, id: `input-${credential}-for-${provider.id}-provider`, type: provider.credentials[credential].type ?? "text", placeholder: provider.credentials[credential].placeholder ?? "", ...provider.credentials[credential] })] }, `input-group-${provider.id}`);
  }), o3("button", { id: "submitButton", type: "submit", children: ["Sign in with ", provider.name] })] }), (provider.type === "email" || provider.type === "credentials") && i3 + 1 < providers2.length && o3("hr", {})] }, provider.id))] })] });
}
var signinErrors;
var init_signin = __esm({
  "../../node_modules/@auth/core/lib/pages/signin.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_jsxRuntime_module();
    signinErrors = {
      default: "Unable to sign in.",
      signin: "Try signing in with a different account.",
      oauthsignin: "Try signing in with a different account.",
      oauthcallbackerror: "Try signing in with a different account.",
      oauthcreateaccount: "Try signing in with a different account.",
      emailcreateaccount: "Try signing in with a different account.",
      callback: "Try signing in with a different account.",
      oauthaccountnotlinked: "To confirm your identity, sign in with the same account you used originally.",
      emailsignin: "The e-mail could not be sent.",
      credentialssignin: "Sign in failed. Check the details you provided are correct.",
      sessionrequired: "Please sign in to access this page."
    };
  }
});

// ../../node_modules/@auth/core/lib/pages/signout.js
function SignoutPage(props) {
  const { url, csrfToken, theme } = props;
  return o3("div", { className: "signout", children: [theme.brandColor && o3("style", { dangerouslySetInnerHTML: {
    __html: `
        :root {
          --brand-color: ${theme.brandColor}
        }
      `
  } }), theme.buttonText && o3("style", { dangerouslySetInnerHTML: {
    __html: `
        :root {
          --button-text-color: ${theme.buttonText}
        }
      `
  } }), o3("div", { className: "card", children: [theme.logo && o3("img", { src: theme.logo, alt: "Logo", className: "logo" }), o3("h1", { children: "Signout" }), o3("p", { children: "Are you sure you want to sign out?" }), o3("form", { action: `${url}/signout`, method: "POST", children: [o3("input", { type: "hidden", name: "csrfToken", value: csrfToken }), o3("button", { id: "submitButton", type: "submit", children: "Sign out" })] })] })] });
}
var init_signout = __esm({
  "../../node_modules/@auth/core/lib/pages/signout.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_jsxRuntime_module();
  }
});

// ../../node_modules/@auth/core/lib/pages/styles.js
var styles_default;
var init_styles = __esm({
  "../../node_modules/@auth/core/lib/pages/styles.js"() {
    init_functionsRoutes_0_9412289658568613();
    styles_default = `:root {
  --border-width: 1px;
  --border-radius: 0.5rem;
  --color-error: #c94b4b;
  --color-info: #157efb;
  --color-info-text: #fff;
}

.__next-auth-theme-auto,
.__next-auth-theme-light {
  --color-background: #ececec;
  --color-background-card: #fff;
  --color-text: #000;
  --color-primary: #444;
  --color-control-border: #bbb;
  --color-button-active-background: #f9f9f9;
  --color-button-active-border: #aaa;
  --color-separator: #ccc;
}

.__next-auth-theme-dark {
  --color-background: #161b22;
  --color-background-card: #0d1117;
  --color-text: #fff;
  --color-primary: #ccc;
  --color-control-border: #555;
  --color-button-active-background: #060606;
  --color-button-active-border: #666;
  --color-separator: #444;
}

@media (prefers-color-scheme: dark) {
  .__next-auth-theme-auto {
    --color-background: #161b22;
    --color-background-card: #0d1117;
    --color-text: #fff;
    --color-primary: #ccc;
    --color-control-border: #555;
    --color-button-active-background: #060606;
    --color-button-active-border: #666;
    --color-separator: #444;
  }
}

body {
  background-color: var(--color-background);
  margin: 0;
  padding: 0;
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
    "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif,
    "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol", "Noto Color Emoji";
}

h1 {
  font-weight: 400;
  margin-bottom: 1.5rem;
  padding: 0 1rem;
  color: var(--color-text);
}

p {
  color: var(--color-text);
}

form {
  margin: 0;
  padding: 0;
}

label {
  font-weight: 500;
  text-align: left;
  margin-bottom: 0.25rem;
  display: block;
  color: var(--color-text);
}

input[type] {
  box-sizing: border-box;
  display: block;
  width: 100%;
  padding: 0.5rem 1rem;
  border: var(--border-width) solid var(--color-control-border);
  background: var(--color-background-card);
  font-size: 1rem;
  border-radius: var(--border-radius);
  color: var(--color-text);
}

input[type]:focus {
    box-shadow: none;
  }

p {
  margin: 0 0 1.5rem 0;
  padding: 0 1rem;
  font-size: 1.1rem;
  line-height: 2rem;
}

a.button {
  text-decoration: none;
  line-height: 1rem;
}

a.button:link,
  a.button:visited {
    background-color: var(--color-background);
    color: var(--color-primary);
  }

button span {
  flex-grow: 1;
}

button,
a.button {
  margin: 0 0 0.75rem 0;
  padding: 0.75rem 1rem;
  color: var(--provider-color, var(--color-primary));
  background-color: var(--provider-bg, var(--color-background-card));
  font-size: 1.1rem;
  min-height: 62px;
  border-color: rgba(0, 0, 0, 0.1);
  border-radius: var(--border-radius);
  transition: all 0.1s ease-in-out;
  font-weight: 500;
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
}

@media (max-width: 450px) {

button,
a.button {
    font-size: 0.9rem
}
  }

button:hover, a.button:hover {
    cursor: pointer;
  }

button:active, a.button:active {
    cursor: pointer;
  }

button #provider-logo, a.button #provider-logo {
    width: 25px;
    display: block;
  }

button #provider-logo-dark, a.button #provider-logo-dark {
    display: none;
  }

#submitButton {
  color: var(--button-text-color, var(--color-info-text));
  background-color: var(--brand-color, var(--color-info));
  width: 100%;
}

@media (prefers-color-scheme: dark) {
  button,
  a.button {
    color: var(--provider-dark-color, var(--color-primary));
    background-color: var(--provider-dark-bg, var(--color-background));
  }
  #provider-logo {
    display: none !important;
  }
  #provider-logo-dark {
    width: 25px;
    display: block !important;
  }
}

a.site {
  color: var(--color-primary);
  text-decoration: none;
  font-size: 1rem;
  line-height: 2rem;
}

a.site:hover {
    text-decoration: underline;
  }

.page {
  position: absolute;
  width: 100%;
  height: 100%;
  display: grid;
  place-items: center;
  margin: 0;
  padding: 0;
}

.page > div {
    text-align: center;
  }

.error a.button {
    display: inline-block;
    padding-left: 2rem;
    padding-right: 2rem;
    margin-top: 0.5rem;
  }

.error .message {
    margin-bottom: 1.5rem;
  }

.signin input[type="text"] {
    margin-left: auto;
    margin-right: auto;
    display: block;
  }

.signin hr {
    display: block;
    border: 0;
    border-top: 1px solid var(--color-separator);
    margin: 2rem auto 1rem auto;
    overflow: visible;
  }

.signin hr::before {
      content: "or";
      background: var(--color-background-card);
      color: #888;
      padding: 0 0.4rem;
      position: relative;
      top: -0.7rem;
    }

.signin .error {
    background: #f5f5f5;
    font-weight: 500;
    border-radius: 0.3rem;
    background: var(--color-error);
  }

.signin .error p {
      text-align: left;
      padding: 0.5rem 1rem;
      font-size: 0.9rem;
      line-height: 1.2rem;
      color: var(--color-info-text);
    }

.signin > div,
  .signin form {
    display: block;
  }

.signin > div input[type], .signin form input[type] {
      margin-bottom: 0.5rem;
    }

.signin > div button, .signin form button {
      width: 100%;
    }

.signin > div,
  .signin form {

    max-width: 300px;
}

.logo {
  display: inline-block;
  max-width: 150px;
  margin-top: 20px;
  margin-bottom: 25px;
  max-height: 70px;
}

@media screen and (min-width: 450px) {

.card {
    width: 350px
}
  }

@media screen and (max-width: 450px) {

.card {
    width: 200px
}
  }

.card {
  margin: 20px 0 20px 0;
  background-color: var(--color-background-card);
  border-radius: 30px;
  padding: 20px 50px;
}

.card .header {
    color: var(--color-primary);
  }

.section-header {
  color: var(--color-text);
}
`;
  }
});

// ../../node_modules/@auth/core/lib/pages/verify-request.js
function VerifyRequestPage(props) {
  const { url, theme } = props;
  return o3("div", { className: "verify-request", children: [theme.brandColor && o3("style", { dangerouslySetInnerHTML: {
    __html: `
        :root {
          --brand-color: ${theme.brandColor}
        }
      `
  } }), o3("div", { className: "card", children: [theme.logo && o3("img", { src: theme.logo, alt: "Logo", className: "logo" }), o3("h1", { children: "Check your email" }), o3("p", { children: "A sign in link has been sent to your email address." }), o3("p", { children: o3("a", { className: "site", href: url.origin, children: url.host }) })] })] });
}
var init_verify_request = __esm({
  "../../node_modules/@auth/core/lib/pages/verify-request.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_jsxRuntime_module();
  }
});

// ../../node_modules/@auth/core/lib/pages/index.js
function send({ html, title, status, cookies, theme }) {
  return {
    cookies,
    status,
    headers: { "Content-Type": "text/html" },
    body: `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta http-equiv="X-UA-Compatible" content="IE=edge"><meta name="viewport" content="width=device-width, initial-scale=1.0"><style>${styles_default}</style><title>${title}</title></head><body class="__next-auth-theme-${theme?.colorScheme ?? "auto"}"><div class="page">${k2(html)}</div></body></html>`
  };
}
function renderPage(params) {
  const { url, theme, query, cookies } = params;
  return {
    signin(props) {
      return send({
        cookies,
        theme,
        html: SigninPage({
          csrfToken: params.csrfToken,
          providers: params.providers?.filter((provider) => ["email", "oauth", "oidc"].includes(provider.type) || provider.type === "credentials" && provider.credentials || false),
          callbackUrl: params.callbackUrl,
          theme,
          ...query,
          ...props
        }),
        title: "Sign In"
      });
    },
    signout(props) {
      return send({
        cookies,
        theme,
        html: SignoutPage({
          csrfToken: params.csrfToken,
          url,
          theme,
          ...props
        }),
        title: "Sign Out"
      });
    },
    verifyRequest(props) {
      return send({
        cookies,
        theme,
        html: VerifyRequestPage({ url, theme, ...props }),
        title: "Verify Request"
      });
    },
    error(props) {
      return send({
        cookies,
        theme,
        ...ErrorPage({ url, theme, ...props }),
        title: "Error"
      });
    }
  };
}
var init_pages = __esm({
  "../../node_modules/@auth/core/lib/pages/index.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_dist();
    init_error();
    init_signin();
    init_signout();
    init_styles();
    init_verify_request();
  }
});

// ../../node_modules/@auth/core/lib/utils/date.js
function fromDate(time, date = Date.now()) {
  return new Date(date + time * 1e3);
}
var init_date = __esm({
  "../../node_modules/@auth/core/lib/utils/date.js"() {
    init_functionsRoutes_0_9412289658568613();
  }
});

// ../../node_modules/@auth/core/lib/callback-handler.js
async function handleLogin(sessionToken, _profile, _account, options) {
  if (!_account?.providerAccountId || !_account.type)
    throw new Error("Missing or invalid provider account");
  if (!["email", "oauth", "oidc"].includes(_account.type))
    throw new Error("Provider not supported");
  const { adapter, jwt: jwt2, events, session: { strategy: sessionStrategy, generateSessionToken } } = options;
  if (!adapter) {
    return { user: _profile, account: _account };
  }
  const profile = _profile;
  let account = _account;
  const { createUser, updateUser, getUser, getUserByAccount, getUserByEmail, linkAccount, createSession, getSessionAndUser, deleteSession } = adapter;
  let session2 = null;
  let user = null;
  let isNewUser = false;
  const useJwtSession = sessionStrategy === "jwt";
  if (sessionToken) {
    if (useJwtSession) {
      try {
        session2 = await jwt2.decode({ ...jwt2, token: sessionToken });
        if (session2 && "sub" in session2 && session2.sub) {
          user = await getUser(session2.sub);
        }
      } catch {
      }
    } else {
      const userAndSession = await getSessionAndUser(sessionToken);
      if (userAndSession) {
        session2 = userAndSession.session;
        user = userAndSession.user;
      }
    }
  }
  if (account.type === "email") {
    const userByEmail = await getUserByEmail(profile.email);
    if (userByEmail) {
      if (user?.id !== userByEmail.id && !useJwtSession && sessionToken) {
        await deleteSession(sessionToken);
      }
      user = await updateUser({ id: userByEmail.id, emailVerified: new Date() });
      await events.updateUser?.({ user });
    } else {
      const { id: _4, ...newUser } = { ...profile, emailVerified: new Date() };
      user = await createUser(newUser);
      await events.createUser?.({ user });
      isNewUser = true;
    }
    session2 = useJwtSession ? {} : await createSession({
      sessionToken: generateSessionToken(),
      userId: user.id,
      expires: fromDate(options.session.maxAge)
    });
    return { session: session2, user, isNewUser };
  }
  const userByAccount = await getUserByAccount({
    providerAccountId: account.providerAccountId,
    provider: account.provider
  });
  if (userByAccount) {
    if (user) {
      if (userByAccount.id === user.id) {
        return { session: session2, user, isNewUser };
      }
      throw new OAuthAccountNotLinked("The account is already associated with another user", { provider: account.provider });
    }
    session2 = useJwtSession ? {} : await createSession({
      sessionToken: generateSessionToken(),
      userId: userByAccount.id,
      expires: fromDate(options.session.maxAge)
    });
    return { session: session2, user: userByAccount, isNewUser };
  } else {
    const { provider: p3 } = options;
    const { type, provider, providerAccountId, userId, ...tokenSet } = account;
    const defaults = { providerAccountId, provider, type, userId };
    account = Object.assign(p3.account(tokenSet) ?? {}, defaults);
    if (user) {
      await linkAccount({ ...account, userId: user.id });
      await events.linkAccount?.({ user, account, profile });
      return { session: session2, user, isNewUser };
    }
    const userByEmail = profile.email ? await getUserByEmail(profile.email) : null;
    if (userByEmail) {
      const provider2 = options.provider;
      if (provider2?.allowDangerousEmailAccountLinking) {
        user = userByEmail;
      } else {
        throw new OAuthAccountNotLinked("Another account already exists with the same e-mail address", { provider: account.provider });
      }
    } else {
      const { id: _4, ...newUser } = { ...profile, emailVerified: null };
      user = await createUser(newUser);
    }
    await events.createUser?.({ user });
    await linkAccount({ ...account, userId: user.id });
    await events.linkAccount?.({ user, account, profile });
    session2 = useJwtSession ? {} : await createSession({
      sessionToken: generateSessionToken(),
      userId: user.id,
      expires: fromDate(options.session.maxAge)
    });
    return { session: session2, user, isNewUser: true };
  }
}
var init_callback_handler = __esm({
  "../../node_modules/@auth/core/lib/callback-handler.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_errors();
    init_date();
  }
});

// ../../node_modules/oauth4webapi/build/index.js
function buf(input) {
  if (typeof input === "string") {
    return encoder2.encode(input);
  }
  return decoder2.decode(input);
}
function encodeBase64Url(input) {
  if (input instanceof ArrayBuffer) {
    input = new Uint8Array(input);
  }
  const arr = [];
  for (let i3 = 0; i3 < input.byteLength; i3 += CHUNK_SIZE2) {
    arr.push(String.fromCharCode.apply(null, input.subarray(i3, i3 + CHUNK_SIZE2)));
  }
  return btoa(arr.join("")).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function decodeBase64Url(input) {
  try {
    const binary = atob(input.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, ""));
    const bytes = new Uint8Array(binary.length);
    for (let i3 = 0; i3 < binary.length; i3++) {
      bytes[i3] = binary.charCodeAt(i3);
    }
    return bytes;
  } catch {
    throw new TypeError("The input to be decoded is not correctly encoded.");
  }
}
function b64u(input) {
  if (typeof input === "string") {
    return decodeBase64Url(input);
  }
  return encodeBase64Url(input);
}
function isCryptoKey2(key) {
  return key instanceof CryptoKey;
}
function isPrivateKey(key) {
  return isCryptoKey2(key) && key.type === "private";
}
function isPublicKey(key) {
  return isCryptoKey2(key) && key.type === "public";
}
function processDpopNonce(response) {
  const url = new URL(response.url);
  if (response.headers.has("dpop-nonce")) {
    dpopNonces.set(url.origin, response.headers.get("dpop-nonce"));
  }
  return response;
}
function isJsonObject(input) {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    return false;
  }
  return true;
}
function prepareHeaders(input) {
  if (input !== void 0 && !(input instanceof Headers)) {
    throw new TypeError('"options.headers" must be an instance of Headers');
  }
  const headers = new Headers(input);
  if (USER_AGENT && !headers.has("user-agent")) {
    headers.set("user-agent", USER_AGENT);
  }
  if (headers.has("authorization")) {
    throw new TypeError('"options.headers" must not include the "authorization" header name');
  }
  if (headers.has("dpop")) {
    throw new TypeError('"options.headers" must not include the "dpop" header name');
  }
  return headers;
}
function signal(value) {
  if (typeof value === "function") {
    value = value();
  }
  if (!(value instanceof AbortSignal)) {
    throw new TypeError('"options.signal" must return or be an instance of AbortSignal');
  }
  return value;
}
async function discoveryRequest(issuerIdentifier, options) {
  if (!(issuerIdentifier instanceof URL)) {
    throw new TypeError('"issuerIdentifier" must be an instance of URL');
  }
  if (issuerIdentifier.protocol !== "https:" && issuerIdentifier.protocol !== "http:") {
    throw new TypeError('"issuer.protocol" must be "https:" or "http:"');
  }
  const url = new URL(issuerIdentifier.href);
  switch (options?.algorithm) {
    case void 0:
    case "oidc":
      url.pathname = `${url.pathname}/.well-known/openid-configuration`.replace("//", "/");
      break;
    case "oauth2":
      if (url.pathname === "/") {
        url.pathname = `.well-known/oauth-authorization-server`;
      } else {
        url.pathname = `.well-known/oauth-authorization-server/${url.pathname}`.replace("//", "/");
      }
      break;
    default:
      throw new TypeError('"options.algorithm" must be "oidc" (default), or "oauth2"');
  }
  const headers = prepareHeaders(options?.headers);
  headers.set("accept", "application/json");
  return fetch(url.href, {
    headers,
    method: "GET",
    redirect: "manual",
    signal: options?.signal ? signal(options.signal) : null
  }).then(processDpopNonce);
}
function validateString(input) {
  return typeof input === "string" && input.length !== 0;
}
async function processDiscoveryResponse(expectedIssuerIdentifier, response) {
  if (!(expectedIssuerIdentifier instanceof URL)) {
    throw new TypeError('"expectedIssuer" must be an instance of URL');
  }
  if (!(response instanceof Response)) {
    throw new TypeError('"response" must be an instance of Response');
  }
  if (response.status !== 200) {
    throw new OPE('"response" is not a conform Authorization Server Metadata response');
  }
  assertReadableResponse(response);
  let json;
  try {
    json = await response.json();
  } catch {
    throw new OPE('failed to parse "response" body as JSON');
  }
  if (!isJsonObject(json)) {
    throw new OPE('"response" body must be a top level object');
  }
  if (!validateString(json.issuer)) {
    throw new OPE('"response" body "issuer" property must be a non-empty string');
  }
  if (new URL(json.issuer).href !== expectedIssuerIdentifier.href) {
    throw new OPE('"response" body "issuer" does not match "expectedIssuer"');
  }
  return json;
}
function randomBytes() {
  return b64u(crypto.getRandomValues(new Uint8Array(32)));
}
function generateRandomCodeVerifier() {
  return randomBytes();
}
function generateRandomState() {
  return randomBytes();
}
function generateRandomNonce() {
  return randomBytes();
}
async function calculatePKCECodeChallenge(codeVerifier) {
  if (!validateString(codeVerifier)) {
    throw new TypeError('"codeVerifier" must be a non-empty string');
  }
  return b64u(await crypto.subtle.digest({ name: "SHA-256" }, buf(codeVerifier)));
}
function getKeyAndKid(input) {
  if (input instanceof CryptoKey) {
    return { key: input };
  }
  if (!(input?.key instanceof CryptoKey)) {
    return {};
  }
  if (input.kid !== void 0 && !validateString(input.kid)) {
    throw new TypeError('"kid" must be a non-empty string');
  }
  return { key: input.key, kid: input.kid };
}
function formUrlEncode(token) {
  return encodeURIComponent(token).replace(/%20/g, "+");
}
function clientSecretBasic(clientId, clientSecret) {
  const username = formUrlEncode(clientId);
  const password = formUrlEncode(clientSecret);
  const credentials = btoa(`${username}:${password}`);
  return `Basic ${credentials}`;
}
function psAlg(key) {
  switch (key.algorithm.hash.name) {
    case "SHA-256":
      return "PS256";
    case "SHA-384":
      return "PS384";
    case "SHA-512":
      return "PS512";
    default:
      throw new UnsupportedOperationError("unsupported RsaHashedKeyAlgorithm hash name");
  }
}
function rsAlg(key) {
  switch (key.algorithm.hash.name) {
    case "SHA-256":
      return "RS256";
    case "SHA-384":
      return "RS384";
    case "SHA-512":
      return "RS512";
    default:
      throw new UnsupportedOperationError("unsupported RsaHashedKeyAlgorithm hash name");
  }
}
function esAlg(key) {
  switch (key.algorithm.namedCurve) {
    case "P-256":
      return "ES256";
    case "P-384":
      return "ES384";
    case "P-521":
      return "ES512";
    default:
      throw new UnsupportedOperationError("unsupported EcKeyAlgorithm namedCurve");
  }
}
function keyToJws(key) {
  switch (key.algorithm.name) {
    case "RSA-PSS":
      return psAlg(key);
    case "RSASSA-PKCS1-v1_5":
      return rsAlg(key);
    case "ECDSA":
      return esAlg(key);
    case "Ed25519":
    case "Ed448":
      return "EdDSA";
    default:
      throw new UnsupportedOperationError("unsupported CryptoKey algorithm name");
  }
}
function getClockSkew(client) {
  if (Number.isFinite(client[clockSkew])) {
    return client[clockSkew];
  }
  return 0;
}
function getClockTolerance(client) {
  const tolerance = client[clockTolerance];
  if (Number.isFinite(tolerance) && Math.sign(tolerance) !== -1) {
    return tolerance;
  }
  return 30;
}
function epochTime() {
  return Math.floor(Date.now() / 1e3);
}
function clientAssertion(as, client) {
  const now2 = epochTime() + getClockSkew(client);
  return {
    jti: randomBytes(),
    aud: [as.issuer, as.token_endpoint],
    exp: now2 + 60,
    iat: now2,
    nbf: now2,
    iss: client.client_id,
    sub: client.client_id
  };
}
async function privateKeyJwt(as, client, key, kid) {
  return jwt({
    alg: keyToJws(key),
    kid
  }, clientAssertion(as, client), key);
}
function assertAs(as) {
  if (typeof as !== "object" || as === null) {
    throw new TypeError('"as" must be an object');
  }
  if (!validateString(as.issuer)) {
    throw new TypeError('"as.issuer" property must be a non-empty string');
  }
  return true;
}
function assertClient(client) {
  if (typeof client !== "object" || client === null) {
    throw new TypeError('"client" must be an object');
  }
  if (!validateString(client.client_id)) {
    throw new TypeError('"client.client_id" property must be a non-empty string');
  }
  return true;
}
function assertClientSecret(clientSecret) {
  if (!validateString(clientSecret)) {
    throw new TypeError('"client.client_secret" property must be a non-empty string');
  }
  return clientSecret;
}
function assertNoClientPrivateKey(clientAuthMethod, clientPrivateKey) {
  if (clientPrivateKey !== void 0) {
    throw new TypeError(`"options.clientPrivateKey" property must not be provided when ${clientAuthMethod} client authentication method is used.`);
  }
}
function assertNoClientSecret(clientAuthMethod, clientSecret) {
  if (clientSecret !== void 0) {
    throw new TypeError(`"client.client_secret" property must not be provided when ${clientAuthMethod} client authentication method is used.`);
  }
}
async function clientAuthentication(as, client, body, headers, clientPrivateKey) {
  body.delete("client_secret");
  body.delete("client_assertion_type");
  body.delete("client_assertion");
  switch (client.token_endpoint_auth_method) {
    case void 0:
    case "client_secret_basic": {
      assertNoClientPrivateKey("client_secret_basic", clientPrivateKey);
      headers.set("authorization", clientSecretBasic(client.client_id, assertClientSecret(client.client_secret)));
      break;
    }
    case "client_secret_post": {
      assertNoClientPrivateKey("client_secret_post", clientPrivateKey);
      body.set("client_id", client.client_id);
      body.set("client_secret", assertClientSecret(client.client_secret));
      break;
    }
    case "private_key_jwt": {
      assertNoClientSecret("private_key_jwt", client.client_secret);
      if (clientPrivateKey === void 0) {
        throw new TypeError('"options.clientPrivateKey" must be provided when "client.token_endpoint_auth_method" is "private_key_jwt"');
      }
      const { key, kid } = getKeyAndKid(clientPrivateKey);
      if (!isPrivateKey(key)) {
        throw new TypeError('"options.clientPrivateKey.key" must be a private CryptoKey');
      }
      body.set("client_id", client.client_id);
      body.set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
      body.set("client_assertion", await privateKeyJwt(as, client, key, kid));
      break;
    }
    case "none": {
      assertNoClientSecret("none", client.client_secret);
      assertNoClientPrivateKey("none", clientPrivateKey);
      body.set("client_id", client.client_id);
      break;
    }
    default:
      throw new UnsupportedOperationError("unsupported client token_endpoint_auth_method");
  }
}
async function jwt(header, claimsSet, key) {
  if (!key.usages.includes("sign")) {
    throw new TypeError('CryptoKey instances used for signing assertions must include "sign" in their "usages"');
  }
  const input = `${b64u(buf(JSON.stringify(header)))}.${b64u(buf(JSON.stringify(claimsSet)))}`;
  const signature = b64u(await crypto.subtle.sign(keyToSubtle(key), key, buf(input)));
  return `${input}.${signature}`;
}
async function dpopProofJwt(headers, options, url, htm, clockSkew2, accessToken) {
  const { privateKey, publicKey, nonce: nonce2 = dpopNonces.get(url.origin) } = options;
  if (!isPrivateKey(privateKey)) {
    throw new TypeError('"DPoP.privateKey" must be a private CryptoKey');
  }
  if (!isPublicKey(publicKey)) {
    throw new TypeError('"DPoP.publicKey" must be a public CryptoKey');
  }
  if (nonce2 !== void 0 && !validateString(nonce2)) {
    throw new TypeError('"DPoP.nonce" must be a non-empty string or undefined');
  }
  if (!publicKey.extractable) {
    throw new TypeError('"DPoP.publicKey.extractable" must be true');
  }
  const now2 = epochTime() + clockSkew2;
  const proof = await jwt({
    alg: keyToJws(privateKey),
    typ: "dpop+jwt",
    jwk: await publicJwk(publicKey)
  }, {
    iat: now2,
    jti: randomBytes(),
    htm,
    nonce: nonce2,
    htu: `${url.origin}${url.pathname}`,
    ath: accessToken ? b64u(await crypto.subtle.digest({ name: "SHA-256" }, buf(accessToken))) : void 0
  }, privateKey);
  headers.set("dpop", proof);
}
async function publicJwk(key) {
  jwkCache || (jwkCache = /* @__PURE__ */ new WeakMap());
  if (jwkCache.has(key)) {
    return jwkCache.get(key);
  }
  const { kty, e: e2, n: n3, x: x2, y: y2, crv } = await crypto.subtle.exportKey("jwk", key);
  const jwk = { kty, e: e2, n: n3, x: x2, y: y2, crv };
  jwkCache.set(key, jwk);
  return jwk;
}
function isOAuth2Error(input) {
  const value = input;
  if (typeof value !== "object" || Array.isArray(value) || value === null) {
    return false;
  }
  return value.error !== void 0;
}
function unquote(value) {
  if (value.length >= 2 && value[0] === '"' && value[value.length - 1] === '"') {
    return value.slice(1, -1);
  }
  return value;
}
function wwwAuth(scheme, params) {
  const arr = params.split(SPLIT_REGEXP).slice(1);
  if (!arr.length) {
    return { scheme: scheme.toLowerCase(), parameters: {} };
  }
  arr[arr.length - 1] = arr[arr.length - 1].replace(/,$/, "");
  const parameters = {};
  for (let i3 = 1; i3 < arr.length; i3 += 2) {
    const idx = i3;
    if (arr[idx][0] === '"') {
      while (arr[idx].slice(-1) !== '"' && ++i3 < arr.length) {
        arr[idx] += arr[i3];
      }
    }
    const key = arr[idx - 1].replace(/^(?:, ?)|=$/g, "").toLowerCase();
    parameters[key] = unquote(arr[idx]);
  }
  return {
    scheme: scheme.toLowerCase(),
    parameters
  };
}
function parseWwwAuthenticateChallenges(response) {
  if (!(response instanceof Response)) {
    throw new TypeError('"response" must be an instance of Response');
  }
  if (!response.headers.has("www-authenticate")) {
    return void 0;
  }
  const header = response.headers.get("www-authenticate");
  const result = [];
  for (const { 1: scheme, index } of header.matchAll(SCHEMES_REGEXP)) {
    result.push([scheme, index]);
  }
  if (!result.length) {
    return void 0;
  }
  const challenges = result.map(([scheme, indexOf], i3, others) => {
    const next = others[i3 + 1];
    let parameters;
    if (next) {
      parameters = header.slice(indexOf, next[1]);
    } else {
      parameters = header.slice(indexOf);
    }
    return wwwAuth(scheme, parameters);
  });
  return challenges;
}
async function protectedResourceRequest(accessToken, method, url, headers, body, options) {
  if (!validateString(accessToken)) {
    throw new TypeError('"accessToken" must be a non-empty string');
  }
  if (!(url instanceof URL)) {
    throw new TypeError('"url" must be an instance of URL');
  }
  headers = prepareHeaders(headers);
  if (options?.DPoP === void 0) {
    headers.set("authorization", `Bearer ${accessToken}`);
  } else {
    await dpopProofJwt(headers, options.DPoP, url, "GET", getClockSkew({ [clockSkew]: options?.clockSkew }), accessToken);
    headers.set("authorization", `DPoP ${accessToken}`);
  }
  return fetch(url.href, {
    body,
    headers,
    method,
    redirect: "manual",
    signal: options?.signal ? signal(options.signal) : null
  }).then(processDpopNonce);
}
async function userInfoRequest(as, client, accessToken, options) {
  assertAs(as);
  assertClient(client);
  if (typeof as.userinfo_endpoint !== "string") {
    throw new TypeError('"as.userinfo_endpoint" must be a string');
  }
  const url = new URL(as.userinfo_endpoint);
  const headers = prepareHeaders(options?.headers);
  if (client.userinfo_signed_response_alg) {
    headers.set("accept", "application/jwt");
  } else {
    headers.set("accept", "application/json");
    headers.append("accept", "application/jwt");
  }
  return protectedResourceRequest(accessToken, "GET", url, headers, null, {
    ...options,
    clockSkew: getClockSkew(client)
  });
}
async function authenticatedRequest(as, client, method, url, body, headers, options) {
  await clientAuthentication(as, client, body, headers, options?.clientPrivateKey);
  headers.set("content-type", "application/x-www-form-urlencoded;charset=UTF-8");
  return fetch(url.href, {
    body,
    headers,
    method,
    redirect: "manual",
    signal: options?.signal ? signal(options.signal) : null
  }).then(processDpopNonce);
}
async function tokenEndpointRequest(as, client, grantType, parameters, options) {
  if (typeof as.token_endpoint !== "string") {
    throw new TypeError('"as.token_endpoint" must be a string');
  }
  const url = new URL(as.token_endpoint);
  parameters.set("grant_type", grantType);
  const headers = prepareHeaders(options?.headers);
  headers.set("accept", "application/json");
  if (options?.DPoP !== void 0) {
    await dpopProofJwt(headers, options.DPoP, url, "POST", getClockSkew(client));
  }
  return authenticatedRequest(as, client, "POST", url, parameters, headers, options);
}
function getValidatedIdTokenClaims(ref) {
  if (!ref.id_token) {
    return void 0;
  }
  const claims = idTokenClaims.get(ref);
  if (!claims) {
    throw new TypeError('"ref" was already garbage collected or did not resolve from the proper sources');
  }
  return claims;
}
async function processGenericAccessTokenResponse(as, client, response, ignoreIdToken = false, ignoreRefreshToken = false) {
  assertAs(as);
  assertClient(client);
  if (!(response instanceof Response)) {
    throw new TypeError('"response" must be an instance of Response');
  }
  if (response.status !== 200) {
    let err;
    if (err = await handleOAuthBodyError(response)) {
      return err;
    }
    throw new OPE('"response" is not a conform Token Endpoint response');
  }
  assertReadableResponse(response);
  let json;
  try {
    json = await response.json();
  } catch {
    throw new OPE('failed to parse "response" body as JSON');
  }
  if (!isJsonObject(json)) {
    throw new OPE('"response" body must be a top level object');
  }
  if (!validateString(json.access_token)) {
    throw new OPE('"response" body "access_token" property must be a non-empty string');
  }
  if (!validateString(json.token_type)) {
    throw new OPE('"response" body "token_type" property must be a non-empty string');
  }
  json.token_type = json.token_type.toLowerCase();
  if (json.token_type !== "dpop" && json.token_type !== "bearer") {
    throw new UnsupportedOperationError("unsupported `token_type` value");
  }
  if (json.expires_in !== void 0 && (typeof json.expires_in !== "number" || json.expires_in <= 0)) {
    throw new OPE('"response" body "expires_in" property must be a positive number');
  }
  if (!ignoreRefreshToken && json.refresh_token !== void 0 && !validateString(json.refresh_token)) {
    throw new OPE('"response" body "refresh_token" property must be a non-empty string');
  }
  if (json.scope !== void 0 && typeof json.scope !== "string") {
    throw new OPE('"response" body "scope" property must be a string');
  }
  if (!ignoreIdToken) {
    if (json.id_token !== void 0 && !validateString(json.id_token)) {
      throw new OPE('"response" body "id_token" property must be a non-empty string');
    }
    if (json.id_token) {
      const { claims } = await validateJwt(json.id_token, checkSigningAlgorithm.bind(void 0, client.id_token_signed_response_alg, as.id_token_signing_alg_values_supported), noSignatureCheck, getClockSkew(client), getClockTolerance(client)).then(validatePresence.bind(void 0, ["aud", "exp", "iat", "iss", "sub"])).then(validateIssuer.bind(void 0, as.issuer)).then(validateAudience.bind(void 0, client.client_id));
      if (Array.isArray(claims.aud) && claims.aud.length !== 1 && claims.azp !== client.client_id) {
        throw new OPE('unexpected ID Token "azp" (authorized party) claim value');
      }
      if (client.require_auth_time && typeof claims.auth_time !== "number") {
        throw new OPE('unexpected ID Token "auth_time" (authentication time) claim value');
      }
      idTokenClaims.set(json, claims);
    }
  }
  return json;
}
function validateAudience(expected, result) {
  if (Array.isArray(result.claims.aud)) {
    if (!result.claims.aud.includes(expected)) {
      throw new OPE('unexpected JWT "aud" (audience) claim value');
    }
  } else if (result.claims.aud !== expected) {
    throw new OPE('unexpected JWT "aud" (audience) claim value');
  }
  return result;
}
function validateIssuer(expected, result) {
  if (result.claims.iss !== expected) {
    throw new OPE('unexpected JWT "iss" (issuer) claim value');
  }
  return result;
}
function brand(searchParams) {
  branded.add(searchParams);
  return searchParams;
}
async function authorizationCodeGrantRequest(as, client, callbackParameters, redirectUri, codeVerifier, options) {
  assertAs(as);
  assertClient(client);
  if (!branded.has(callbackParameters)) {
    throw new TypeError('"callbackParameters" must be an instance of URLSearchParams obtained from "validateAuthResponse()", or "validateJwtAuthResponse()');
  }
  if (!validateString(redirectUri)) {
    throw new TypeError('"redirectUri" must be a non-empty string');
  }
  if (!validateString(codeVerifier)) {
    throw new TypeError('"codeVerifier" must be a non-empty string');
  }
  const code = getURLSearchParameter(callbackParameters, "code");
  if (!code) {
    throw new OPE('no authorization code in "callbackParameters"');
  }
  const parameters = new URLSearchParams(options?.additionalParameters);
  parameters.set("redirect_uri", redirectUri);
  parameters.set("code_verifier", codeVerifier);
  parameters.set("code", code);
  return tokenEndpointRequest(as, client, "authorization_code", parameters, options);
}
function validatePresence(required, result) {
  for (const claim of required) {
    if (result.claims[claim] === void 0) {
      throw new OPE(`JWT "${claim}" (${claimNames[claim]}) claim missing`);
    }
  }
  return result;
}
async function processAuthorizationCodeOpenIDResponse(as, client, response, expectedNonce, maxAge) {
  const result = await processGenericAccessTokenResponse(as, client, response);
  if (isOAuth2Error(result)) {
    return result;
  }
  if (!validateString(result.id_token)) {
    throw new OPE('"response" body "id_token" property must be a non-empty string');
  }
  maxAge ?? (maxAge = client.default_max_age ?? skipAuthTimeCheck);
  const claims = getValidatedIdTokenClaims(result);
  if ((client.require_auth_time || maxAge !== skipAuthTimeCheck) && claims.auth_time === void 0) {
    throw new OPE('ID Token "auth_time" (authentication time) claim missing');
  }
  if (maxAge !== skipAuthTimeCheck) {
    if (typeof maxAge !== "number" || maxAge < 0) {
      throw new TypeError('"options.max_age" must be a non-negative number');
    }
    const now2 = epochTime() + getClockSkew(client);
    const tolerance = getClockTolerance(client);
    if (claims.auth_time + maxAge < now2 - tolerance) {
      throw new OPE("too much time has elapsed since the last End-User authentication");
    }
  }
  switch (expectedNonce) {
    case void 0:
    case expectNoNonce:
      if (claims.nonce !== void 0) {
        throw new OPE('unexpected ID Token "nonce" claim value');
      }
      break;
    default:
      if (!validateString(expectedNonce)) {
        throw new TypeError('"expectedNonce" must be a non-empty string');
      }
      if (claims.nonce === void 0) {
        throw new OPE('ID Token "nonce" claim missing');
      }
      if (claims.nonce !== expectedNonce) {
        throw new OPE('unexpected ID Token "nonce" claim value');
      }
  }
  return result;
}
async function processAuthorizationCodeOAuth2Response(as, client, response) {
  const result = await processGenericAccessTokenResponse(as, client, response, true);
  if (isOAuth2Error(result)) {
    return result;
  }
  if (result.id_token !== void 0) {
    if (typeof result.id_token === "string" && result.id_token.length) {
      throw new OPE("Unexpected ID Token returned, use processAuthorizationCodeOpenIDResponse() for OpenID Connect callback processing");
    }
    delete result.id_token;
  }
  return result;
}
function assertReadableResponse(response) {
  if (response.bodyUsed) {
    throw new TypeError('"response" body has been used already');
  }
}
async function handleOAuthBodyError(response) {
  if (response.status > 399 && response.status < 500) {
    assertReadableResponse(response);
    try {
      const json = await response.json();
      if (isJsonObject(json) && typeof json.error === "string" && json.error.length) {
        if (json.error_description !== void 0 && typeof json.error_description !== "string") {
          delete json.error_description;
        }
        if (json.error_uri !== void 0 && typeof json.error_uri !== "string") {
          delete json.error_uri;
        }
        if (json.algs !== void 0 && typeof json.algs !== "string") {
          delete json.algs;
        }
        if (json.scope !== void 0 && typeof json.scope !== "string") {
          delete json.scope;
        }
        return json;
      }
    } catch {
    }
  }
  return void 0;
}
function checkRsaKeyAlgorithm(algorithm) {
  if (typeof algorithm.modulusLength !== "number" || algorithm.modulusLength < 2048) {
    throw new OPE(`${algorithm.name} modulusLength must be at least 2048 bits`);
  }
}
function ecdsaHashName(namedCurve) {
  switch (namedCurve) {
    case "P-256":
      return "SHA-256";
    case "P-384":
      return "SHA-384";
    case "P-521":
      return "SHA-512";
    default:
      throw new UnsupportedOperationError();
  }
}
function keyToSubtle(key) {
  switch (key.algorithm.name) {
    case "ECDSA":
      return {
        name: key.algorithm.name,
        hash: { name: ecdsaHashName(key.algorithm.namedCurve) }
      };
    case "RSA-PSS": {
      checkRsaKeyAlgorithm(key.algorithm);
      switch (key.algorithm.hash.name) {
        case "SHA-256":
        case "SHA-384":
        case "SHA-512":
          return {
            name: key.algorithm.name,
            saltLength: parseInt(key.algorithm.hash.name.slice(-3), 10) >> 3
          };
        default:
          throw new UnsupportedOperationError();
      }
    }
    case "RSASSA-PKCS1-v1_5":
      checkRsaKeyAlgorithm(key.algorithm);
      return { name: key.algorithm.name };
    case "Ed448":
    case "Ed25519":
      return { name: key.algorithm.name };
  }
  throw new UnsupportedOperationError();
}
async function validateJwt(jws, checkAlg, getKey, clockSkew2, clockTolerance2) {
  const { 0: protectedHeader, 1: payload, 2: encodedSignature, length } = jws.split(".");
  if (length === 5) {
    throw new UnsupportedOperationError("JWE structure JWTs are not supported");
  }
  if (length !== 3) {
    throw new OPE("Invalid JWT");
  }
  let header;
  try {
    header = JSON.parse(buf(b64u(protectedHeader)));
  } catch {
    throw new OPE("failed to parse JWT Header body as base64url encoded JSON");
  }
  if (!isJsonObject(header)) {
    throw new OPE("JWT Header must be a top level object");
  }
  checkAlg(header);
  if (header.crit !== void 0) {
    throw new OPE('unexpected JWT "crit" header parameter');
  }
  const signature = b64u(encodedSignature);
  if (getKey !== noSignatureCheck) {
    const key = await getKey(header);
    const input = `${protectedHeader}.${payload}`;
    const verified = await crypto.subtle.verify(keyToSubtle(key), key, signature, buf(input));
    if (!verified) {
      throw new OPE("JWT signature verification failed");
    }
  }
  let claims;
  try {
    claims = JSON.parse(buf(b64u(payload)));
  } catch {
    throw new OPE("failed to parse JWT Payload body as base64url encoded JSON");
  }
  if (!isJsonObject(claims)) {
    throw new OPE("JWT Payload must be a top level object");
  }
  const now2 = epochTime() + clockSkew2;
  if (claims.exp !== void 0) {
    if (typeof claims.exp !== "number") {
      throw new OPE('unexpected JWT "exp" (expiration time) claim type');
    }
    if (claims.exp <= now2 - clockTolerance2) {
      throw new OPE('unexpected JWT "exp" (expiration time) claim value, timestamp is <= now()');
    }
  }
  if (claims.iat !== void 0) {
    if (typeof claims.iat !== "number") {
      throw new OPE('unexpected JWT "iat" (issued at) claim type');
    }
  }
  if (claims.iss !== void 0) {
    if (typeof claims.iss !== "string") {
      throw new OPE('unexpected JWT "iss" (issuer) claim type');
    }
  }
  if (claims.nbf !== void 0) {
    if (typeof claims.nbf !== "number") {
      throw new OPE('unexpected JWT "nbf" (not before) claim type');
    }
    if (claims.nbf > now2 + clockTolerance2) {
      throw new OPE('unexpected JWT "nbf" (not before) claim value, timestamp is > now()');
    }
  }
  if (claims.aud !== void 0) {
    if (typeof claims.aud !== "string" && !Array.isArray(claims.aud)) {
      throw new OPE('unexpected JWT "aud" (audience) claim type');
    }
  }
  return { header, claims, signature };
}
function checkSigningAlgorithm(client, issuer, header) {
  if (client !== void 0) {
    if (header.alg !== client) {
      throw new OPE('unexpected JWT "alg" header parameter');
    }
    return;
  }
  if (Array.isArray(issuer)) {
    if (!issuer.includes(header.alg)) {
      throw new OPE('unexpected JWT "alg" header parameter');
    }
    return;
  }
  if (header.alg !== "RS256") {
    throw new OPE('unexpected JWT "alg" header parameter');
  }
}
function getURLSearchParameter(parameters, name) {
  const { 0: value, length } = parameters.getAll(name);
  if (length > 1) {
    throw new OPE(`"${name}" parameter must be provided only once`);
  }
  return value;
}
function validateAuthResponse(as, client, parameters, expectedState) {
  assertAs(as);
  assertClient(client);
  if (parameters instanceof URL) {
    parameters = parameters.searchParams;
  }
  if (!(parameters instanceof URLSearchParams)) {
    throw new TypeError('"parameters" must be an instance of URLSearchParams, or URL');
  }
  if (getURLSearchParameter(parameters, "response")) {
    throw new OPE('"parameters" contains a JARM response, use validateJwtAuthResponse() instead of validateAuthResponse()');
  }
  const iss = getURLSearchParameter(parameters, "iss");
  const state2 = getURLSearchParameter(parameters, "state");
  if (!iss && as.authorization_response_iss_parameter_supported) {
    throw new OPE('response parameter "iss" (issuer) missing');
  }
  if (iss && iss !== as.issuer) {
    throw new OPE('unexpected "iss" (issuer) response parameter value');
  }
  switch (expectedState) {
    case void 0:
    case expectNoState:
      if (state2 !== void 0) {
        throw new OPE('unexpected "state" response parameter encountered');
      }
      break;
    case skipStateCheck:
      break;
    default:
      if (!validateString(expectedState)) {
        throw new OPE('"expectedState" must be a non-empty string');
      }
      if (state2 === void 0) {
        throw new OPE('response parameter "state" missing');
      }
      if (state2 !== expectedState) {
        throw new OPE('unexpected "state" response parameter value');
      }
  }
  const error = getURLSearchParameter(parameters, "error");
  if (error) {
    return {
      error,
      error_description: getURLSearchParameter(parameters, "error_description"),
      error_uri: getURLSearchParameter(parameters, "error_uri")
    };
  }
  const id_token = getURLSearchParameter(parameters, "id_token");
  const token = getURLSearchParameter(parameters, "token");
  if (id_token !== void 0 || token !== void 0) {
    throw new UnsupportedOperationError("implicit and hybrid flows are not supported");
  }
  return brand(new URLSearchParams(parameters));
}
var USER_AGENT, clockSkew, clockTolerance, encoder2, decoder2, CHUNK_SIZE2, LRU, UnsupportedOperationError, OperationProcessingError, OPE, dpopNonces, jwkCache, SPLIT_REGEXP, SCHEMES_REGEXP, skipSubjectCheck, idTokenClaims, branded, claimNames, expectNoNonce, skipAuthTimeCheck, noSignatureCheck, skipStateCheck, expectNoState;
var init_build = __esm({
  "../../node_modules/oauth4webapi/build/index.js"() {
    init_functionsRoutes_0_9412289658568613();
    if (typeof navigator === "undefined" || !navigator.userAgent?.startsWith?.("Mozilla/5.0 ")) {
      const NAME = "oauth4webapi";
      const VERSION = "v2.3.0";
      USER_AGENT = `${NAME}/${VERSION}`;
    }
    clockSkew = Symbol();
    clockTolerance = Symbol();
    encoder2 = new TextEncoder();
    decoder2 = new TextDecoder();
    CHUNK_SIZE2 = 32768;
    LRU = class {
      constructor(maxSize) {
        this.cache = /* @__PURE__ */ new Map();
        this._cache = /* @__PURE__ */ new Map();
        this.maxSize = maxSize;
      }
      get(key) {
        let v3 = this.cache.get(key);
        if (v3) {
          return v3;
        }
        if (v3 = this._cache.get(key)) {
          this.update(key, v3);
          return v3;
        }
        return void 0;
      }
      has(key) {
        return this.cache.has(key) || this._cache.has(key);
      }
      set(key, value) {
        if (this.cache.has(key)) {
          this.cache.set(key, value);
        } else {
          this.update(key, value);
        }
        return this;
      }
      delete(key) {
        if (this.cache.has(key)) {
          return this.cache.delete(key);
        }
        if (this._cache.has(key)) {
          return this._cache.delete(key);
        }
        return false;
      }
      update(key, value) {
        this.cache.set(key, value);
        if (this.cache.size >= this.maxSize) {
          this._cache = this.cache;
          this.cache = /* @__PURE__ */ new Map();
        }
      }
    };
    UnsupportedOperationError = class extends Error {
      constructor(message2) {
        super(message2 ?? "operation not supported");
        this.name = this.constructor.name;
        Error.captureStackTrace?.(this, this.constructor);
      }
    };
    OperationProcessingError = class extends Error {
      constructor(message2) {
        super(message2);
        this.name = this.constructor.name;
        Error.captureStackTrace?.(this, this.constructor);
      }
    };
    OPE = OperationProcessingError;
    dpopNonces = new LRU(100);
    SPLIT_REGEXP = /((?:,|, )?[0-9a-zA-Z!#$%&'*+-.^_`|~]+=)/;
    SCHEMES_REGEXP = /(?:^|, ?)([0-9a-zA-Z!#$%&'*+\-.^_`|~]+)(?=$|[ ,])/g;
    skipSubjectCheck = Symbol();
    idTokenClaims = /* @__PURE__ */ new WeakMap();
    branded = /* @__PURE__ */ new WeakSet();
    claimNames = {
      aud: "audience",
      exp: "expiration time",
      iat: "issued at",
      iss: "issuer",
      sub: "subject"
    };
    expectNoNonce = Symbol();
    skipAuthTimeCheck = Symbol();
    noSignatureCheck = Symbol();
    skipStateCheck = Symbol();
    expectNoState = Symbol();
  }
});

// ../../node_modules/@auth/core/lib/oauth/checks.js
async function signCookie(type, value, maxAge, options, data) {
  const { cookies, logger: logger2 } = options;
  logger2.debug(`CREATE_${type.toUpperCase()}`, { value, maxAge });
  const expires = new Date();
  expires.setTime(expires.getTime() + maxAge * 1e3);
  const token = { value };
  if (type === "state" && data)
    token.data = data;
  return {
    name: cookies[type].name,
    value: await encode3({ ...options.jwt, maxAge, token }),
    options: { ...cookies[type].options, expires }
  };
}
function decodeState(value) {
  try {
    const decoder3 = new TextDecoder();
    return JSON.parse(decoder3.decode(base64url_exports2.decode(value)));
  } catch {
  }
}
var PKCE_MAX_AGE, pkce, STATE_MAX_AGE, state, NONCE_MAX_AGE, nonce;
var init_checks = __esm({
  "../../node_modules/@auth/core/lib/oauth/checks.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_browser();
    init_build();
    init_errors();
    init_jwt();
    PKCE_MAX_AGE = 60 * 15;
    pkce = {
      async create(options) {
        const code_verifier = generateRandomCodeVerifier();
        const value = await calculatePKCECodeChallenge(code_verifier);
        const maxAge = PKCE_MAX_AGE;
        const cookie = await signCookie("pkceCodeVerifier", code_verifier, maxAge, options);
        return { cookie, value };
      },
      async use(cookies, resCookies, options) {
        const { provider } = options;
        if (!provider?.checks?.includes("pkce"))
          return;
        const codeVerifier = cookies?.[options.cookies.pkceCodeVerifier.name];
        if (!codeVerifier)
          throw new InvalidCheck("PKCE code_verifier cookie was missing.");
        const value = await decode3({
          ...options.jwt,
          token: codeVerifier
        });
        if (!value?.value)
          throw new InvalidCheck("PKCE code_verifier value could not be parsed.");
        resCookies.push({
          name: options.cookies.pkceCodeVerifier.name,
          value: "",
          options: { ...options.cookies.pkceCodeVerifier.options, maxAge: 0 }
        });
        return value.value;
      }
    };
    STATE_MAX_AGE = 60 * 15;
    state = {
      async create(options, data) {
        const { provider } = options;
        if (!provider.checks.includes("state")) {
          if (data) {
            throw new InvalidCheck("State data was provided but the provider is not configured to use state.");
          }
          return;
        }
        const encodedState = base64url_exports2.encode(JSON.stringify({ ...data, random: generateRandomState() }));
        const maxAge = STATE_MAX_AGE;
        const cookie = await signCookie("state", encodedState, maxAge, options, data);
        return { cookie, value: encodedState };
      },
      async use(cookies, resCookies, options, paramRandom) {
        const { provider } = options;
        if (!provider.checks.includes("state"))
          return;
        const state2 = cookies?.[options.cookies.state.name];
        if (!state2)
          throw new InvalidCheck("State cookie was missing.");
        const encodedState = await decode3({
          ...options.jwt,
          token: state2
        });
        if (!encodedState?.value)
          throw new InvalidCheck("State (cookie) value could not be parsed.");
        const decodedState = decodeState(encodedState.value);
        if (!decodedState)
          throw new InvalidCheck("State (encoded) value could not be parsed.");
        if (decodedState.random !== paramRandom)
          throw new InvalidCheck(`Random state values did not match. Expected: ${decodedState.random}. Got: ${paramRandom}`);
        resCookies.push({
          name: options.cookies.state.name,
          value: "",
          options: { ...options.cookies.state.options, maxAge: 0 }
        });
        return encodedState.value;
      }
    };
    NONCE_MAX_AGE = 60 * 15;
    nonce = {
      async create(options) {
        if (!options.provider.checks.includes("nonce"))
          return;
        const value = generateRandomNonce();
        const maxAge = NONCE_MAX_AGE;
        const cookie = await signCookie("nonce", value, maxAge, options);
        return { cookie, value };
      },
      async use(cookies, resCookies, options) {
        const { provider } = options;
        if (!provider?.checks?.includes("nonce"))
          return;
        const nonce2 = cookies?.[options.cookies.nonce.name];
        if (!nonce2)
          throw new InvalidCheck("Nonce cookie was missing.");
        const value = await decode3({ ...options.jwt, token: nonce2 });
        if (!value?.value)
          throw new InvalidCheck("Nonce value could not be parsed.");
        resCookies.push({
          name: options.cookies.nonce.name,
          value: "",
          options: { ...options.cookies.nonce.options, maxAge: 0 }
        });
        return value.value;
      }
    };
  }
});

// ../../node_modules/@auth/core/lib/oauth/callback.js
async function handleOAuth(query, cookies, options, randomState) {
  const { logger: logger2, provider } = options;
  let as;
  const { token, userinfo } = provider;
  if ((!token?.url || token.url.host === "authjs.dev") && (!userinfo?.url || userinfo.url.host === "authjs.dev")) {
    const issuer = new URL(provider.issuer);
    const discoveryResponse = await discoveryRequest(issuer);
    const discoveredAs = await processDiscoveryResponse(issuer, discoveryResponse);
    if (!discoveredAs.token_endpoint)
      throw new TypeError("TODO: Authorization server did not provide a token endpoint.");
    if (!discoveredAs.userinfo_endpoint)
      throw new TypeError("TODO: Authorization server did not provide a userinfo endpoint.");
    as = discoveredAs;
  } else {
    as = {
      issuer: provider.issuer ?? "https://authjs.dev",
      token_endpoint: token?.url.toString(),
      userinfo_endpoint: userinfo?.url.toString()
    };
  }
  const client = {
    client_id: provider.clientId,
    client_secret: provider.clientSecret,
    ...provider.client
  };
  const resCookies = [];
  const state2 = await state.use(cookies, resCookies, options, randomState);
  const codeGrantParams = validateAuthResponse(as, client, new URLSearchParams(query), provider.checks.includes("state") ? state2 : skipStateCheck);
  if (isOAuth2Error(codeGrantParams)) {
    const cause = { providerId: provider.id, ...codeGrantParams };
    logger2.debug("OAuthCallbackError", cause);
    throw new OAuthCallbackError("OAuth Provider returned an error", cause);
  }
  const codeVerifier = await pkce.use(cookies, resCookies, options);
  let redirect_uri = provider.callbackUrl;
  if (!options.isOnRedirectProxy && provider.redirectProxyUrl) {
    redirect_uri = provider.redirectProxyUrl;
  }
  let codeGrantResponse = await authorizationCodeGrantRequest(
    as,
    client,
    codeGrantParams,
    redirect_uri,
    codeVerifier ?? "auth"
  );
  if (provider.token?.conform) {
    codeGrantResponse = await provider.token.conform(codeGrantResponse.clone()) ?? codeGrantResponse;
  }
  let challenges;
  if (challenges = parseWwwAuthenticateChallenges(codeGrantResponse)) {
    for (const challenge of challenges) {
      console.log("challenge", challenge);
    }
    throw new Error("TODO: Handle www-authenticate challenges as needed");
  }
  let profile;
  let tokens;
  if (provider.type === "oidc") {
    const nonce2 = await nonce.use(cookies, resCookies, options);
    const result = await processAuthorizationCodeOpenIDResponse(as, client, codeGrantResponse, nonce2 ?? expectNoNonce);
    if (isOAuth2Error(result)) {
      console.log("error", result);
      throw new Error("TODO: Handle OIDC response body error");
    }
    profile = getValidatedIdTokenClaims(result);
    tokens = result;
  } else {
    tokens = await processAuthorizationCodeOAuth2Response(as, client, codeGrantResponse);
    if (isOAuth2Error(tokens)) {
      console.log("error", tokens);
      throw new Error("TODO: Handle OAuth 2.0 response body error");
    }
    if (userinfo?.request) {
      profile = await userinfo.request({ tokens, provider });
    } else if (userinfo?.url) {
      const userinfoResponse = await userInfoRequest(as, client, tokens.access_token);
      profile = await userinfoResponse.json();
    } else {
      throw new TypeError("No userinfo endpoint configured");
    }
  }
  if (tokens.expires_in) {
    tokens.expires_at = Math.floor(Date.now() / 1e3) + Number(tokens.expires_in);
  }
  const profileResult = await getUserAndAccount(profile, provider, tokens, logger2);
  return { ...profileResult, profile, cookies: resCookies };
}
async function getUserAndAccount(OAuthProfile, provider, tokens, logger2) {
  try {
    const user = await provider.profile(OAuthProfile, tokens);
    user.email = user.email?.toLowerCase();
    if (!user.id) {
      throw new TypeError(`User id is missing in ${provider.name} OAuth profile response`);
    }
    return {
      user,
      account: {
        provider: provider.id,
        type: provider.type,
        providerAccountId: user.id.toString(),
        ...tokens
      }
    };
  } catch (e2) {
    logger2.debug("getProfile error details", OAuthProfile);
    logger2.error(new OAuthProfileParseError(e2, { provider: provider.id }));
  }
}
var init_callback = __esm({
  "../../node_modules/@auth/core/lib/oauth/callback.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_checks();
    init_build();
    init_errors();
  }
});

// ../../node_modules/@auth/core/lib/oauth/handle-state.js
function handleState(query, provider, isOnRedirectProxy) {
  let randomState;
  let proxyRedirect;
  if (provider.redirectProxyUrl && !query?.state) {
    throw new InvalidCheck("Missing state in query, but required for redirect proxy");
  }
  const state2 = decodeState(query?.state);
  randomState = state2?.random;
  if (isOnRedirectProxy) {
    if (!state2?.origin)
      return { randomState };
    proxyRedirect = `${state2.origin}?${new URLSearchParams(query)}`;
  }
  return { randomState, proxyRedirect };
}
var init_handle_state = __esm({
  "../../node_modules/@auth/core/lib/oauth/handle-state.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_errors();
    init_checks();
  }
});

// ../../node_modules/@auth/core/lib/routes/shared.js
async function handleAuthorized(params, { url, logger: logger2, callbacks: { signIn } }) {
  try {
    const authorized = await signIn(params);
    if (!authorized) {
      url.pathname += "/error";
      logger2.debug("User not authorized", params);
      url.searchParams.set("error", "AccessDenied");
      return { status: 403, redirect: url.toString() };
    }
  } catch (e2) {
    url.pathname += "/error";
    const error = new AuthorizedCallbackError(e2);
    logger2.error(error);
    url.searchParams.set("error", "Configuration");
    return { status: 500, redirect: url.toString() };
  }
}
var init_shared = __esm({
  "../../node_modules/@auth/core/lib/routes/shared.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_errors();
  }
});

// ../../node_modules/@auth/core/lib/routes/callback.js
async function callback(params) {
  const { options, query, body, method, headers, sessionStore } = params;
  const { provider, adapter, url, callbackUrl, pages, jwt: jwt2, events, callbacks, session: { strategy: sessionStrategy, maxAge: sessionMaxAge }, logger: logger2 } = options;
  const cookies = [];
  const useJwtSession = sessionStrategy === "jwt";
  try {
    if (provider.type === "oauth" || provider.type === "oidc") {
      const { proxyRedirect, randomState } = handleState(query, provider, options.isOnRedirectProxy);
      if (proxyRedirect) {
        logger2.debug("proxy redirect", { proxyRedirect, randomState });
        return { redirect: proxyRedirect };
      }
      const authorizationResult = await handleOAuth(query, params.cookies, options, randomState);
      if (authorizationResult.cookies.length) {
        cookies.push(...authorizationResult.cookies);
      }
      logger2.debug("authorization result", authorizationResult);
      const { user: userFromProvider, account, profile: OAuthProfile } = authorizationResult;
      if (!userFromProvider || !account || !OAuthProfile) {
        return { redirect: `${url}/signin`, cookies };
      }
      let userByAccountOrFromProvider;
      if (adapter) {
        const { getUserByAccount } = adapter;
        const userByAccount = await getUserByAccount({
          providerAccountId: account.providerAccountId,
          provider: provider.id
        });
        if (userByAccount)
          userByAccountOrFromProvider = userByAccount;
      }
      const unauthorizedOrError = await handleAuthorized({
        user: userByAccountOrFromProvider,
        account,
        profile: OAuthProfile
      }, options);
      if (unauthorizedOrError)
        return { ...unauthorizedOrError, cookies };
      const { user, session: session2, isNewUser } = await handleLogin(sessionStore.value, userFromProvider, account, options);
      if (useJwtSession) {
        const defaultToken = {
          name: user.name,
          email: user.email,
          picture: user.image,
          sub: user.id?.toString()
        };
        const token = await callbacks.jwt({
          token: defaultToken,
          user,
          account,
          profile: OAuthProfile,
          isNewUser,
          trigger: isNewUser ? "signUp" : "signIn"
        });
        if (token === null) {
          cookies.push(...sessionStore.clean());
        } else {
          const newToken = await jwt2.encode({ ...jwt2, token });
          const cookieExpires = new Date();
          cookieExpires.setTime(cookieExpires.getTime() + sessionMaxAge * 1e3);
          const sessionCookies = sessionStore.chunk(newToken, {
            expires: cookieExpires
          });
          cookies.push(...sessionCookies);
        }
      } else {
        cookies.push({
          name: options.cookies.sessionToken.name,
          value: session2.sessionToken,
          options: {
            ...options.cookies.sessionToken.options,
            expires: session2.expires
          }
        });
      }
      await events.signIn?.({ user, account, profile: OAuthProfile, isNewUser });
      if (isNewUser && pages.newUser) {
        return {
          redirect: `${pages.newUser}${pages.newUser.includes("?") ? "&" : "?"}${new URLSearchParams({ callbackUrl })}`,
          cookies
        };
      }
      return { redirect: callbackUrl, cookies };
    } else if (provider.type === "email") {
      const token = query?.token;
      const identifier = query?.email;
      if (!token || !identifier) {
        const e2 = new TypeError("Missing token or email. The sign-in URL was manually opened without token/identifier or the link was not sent correctly in the email.", { cause: { hasToken: !!token, hasEmail: !!identifier } });
        e2.name = "Configuration";
        throw e2;
      }
      const secret = provider.secret ?? options.secret;
      const invite = await adapter.useVerificationToken({
        identifier,
        token: await createHash(`${token}${secret}`)
      });
      const hasInvite = !!invite;
      const expired = invite ? invite.expires.valueOf() < Date.now() : void 0;
      const invalidInvite = !hasInvite || expired;
      if (invalidInvite)
        throw new Verification({ hasInvite, expired });
      const user = await adapter.getUserByEmail(identifier) ?? {
        id: identifier,
        email: identifier,
        emailVerified: null
      };
      const account = {
        providerAccountId: user.email,
        userId: user.id,
        type: "email",
        provider: provider.id
      };
      const unauthorizedOrError = await handleAuthorized({ user, account }, options);
      if (unauthorizedOrError)
        return { ...unauthorizedOrError, cookies };
      const { user: loggedInUser, session: session2, isNewUser } = await handleLogin(sessionStore.value, user, account, options);
      if (useJwtSession) {
        const defaultToken = {
          name: loggedInUser.name,
          email: loggedInUser.email,
          picture: loggedInUser.image,
          sub: loggedInUser.id?.toString()
        };
        const token2 = await callbacks.jwt({
          token: defaultToken,
          user: loggedInUser,
          account,
          isNewUser,
          trigger: isNewUser ? "signUp" : "signIn"
        });
        if (token2 === null) {
          cookies.push(...sessionStore.clean());
        } else {
          const newToken = await jwt2.encode({ ...jwt2, token: token2 });
          const cookieExpires = new Date();
          cookieExpires.setTime(cookieExpires.getTime() + sessionMaxAge * 1e3);
          const sessionCookies = sessionStore.chunk(newToken, {
            expires: cookieExpires
          });
          cookies.push(...sessionCookies);
        }
      } else {
        cookies.push({
          name: options.cookies.sessionToken.name,
          value: session2.sessionToken,
          options: {
            ...options.cookies.sessionToken.options,
            expires: session2.expires
          }
        });
      }
      await events.signIn?.({ user: loggedInUser, account, isNewUser });
      if (isNewUser && pages.newUser) {
        return {
          redirect: `${pages.newUser}${pages.newUser.includes("?") ? "&" : "?"}${new URLSearchParams({ callbackUrl })}`,
          cookies
        };
      }
      return { redirect: callbackUrl, cookies };
    } else if (provider.type === "credentials" && method === "POST") {
      const credentials = body ?? {};
      Object.entries(query ?? {}).forEach(([k3, v3]) => url.searchParams.set(k3, v3));
      const user = await provider.authorize(
        credentials,
        new Request(url, { headers, method, body: JSON.stringify(body) })
      );
      if (!user) {
        return {
          status: 401,
          redirect: `${url}/error?${new URLSearchParams({
            error: "CredentialsSignin",
            provider: provider.id
          })}`,
          cookies
        };
      }
      const account = {
        providerAccountId: user.id,
        type: "credentials",
        provider: provider.id
      };
      const unauthorizedOrError = await handleAuthorized({ user, account, credentials }, options);
      if (unauthorizedOrError)
        return { ...unauthorizedOrError, cookies };
      const defaultToken = {
        name: user.name,
        email: user.email,
        picture: user.image,
        sub: user.id?.toString()
      };
      const token = await callbacks.jwt({
        token: defaultToken,
        user,
        account,
        isNewUser: false,
        trigger: "signIn"
      });
      if (token === null) {
        cookies.push(...sessionStore.clean());
      } else {
        const newToken = await jwt2.encode({ ...jwt2, token });
        const cookieExpires = new Date();
        cookieExpires.setTime(cookieExpires.getTime() + sessionMaxAge * 1e3);
        const sessionCookies = sessionStore.chunk(newToken, {
          expires: cookieExpires
        });
        cookies.push(...sessionCookies);
      }
      await events.signIn?.({ user, account });
      return { redirect: callbackUrl, cookies };
    }
    return {
      status: 500,
      body: `Error: Callback for provider type ${provider.type} not supported`,
      cookies
    };
  } catch (e2) {
    if (e2 instanceof OAuthCallbackError) {
      logger2.error(e2);
      url.searchParams.set("error", OAuthCallbackError.name);
      url.pathname += "/signin";
      return { redirect: url.toString(), cookies };
    }
    const error = new CallbackRouteError(e2, { provider: provider.id });
    logger2.debug("callback route error details", { method, query, body });
    logger2.error(error);
    url.searchParams.set("error", CallbackRouteError.name);
    url.pathname += "/error";
    return { redirect: url.toString(), cookies };
  }
}
var init_callback2 = __esm({
  "../../node_modules/@auth/core/lib/routes/callback.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_errors();
    init_callback_handler();
    init_callback();
    init_handle_state();
    init_web2();
    init_shared();
  }
});

// ../../node_modules/@auth/core/lib/routes/providers.js
function providers(providers2) {
  return {
    headers: { "Content-Type": "application/json" },
    body: providers2.reduce((acc, { id, name, type, signinUrl, callbackUrl }) => {
      acc[id] = { id, name, type, signinUrl, callbackUrl };
      return acc;
    }, {})
  };
}
var init_providers2 = __esm({
  "../../node_modules/@auth/core/lib/routes/providers.js"() {
    init_functionsRoutes_0_9412289658568613();
  }
});

// ../../node_modules/@auth/core/lib/routes/session.js
async function session(params) {
  const { options, sessionStore, newSession, isUpdate } = params;
  const { adapter, jwt: jwt2, events, callbacks, logger: logger2, session: { strategy: sessionStrategy, maxAge: sessionMaxAge } } = options;
  const response = {
    body: null,
    headers: { "Content-Type": "application/json" },
    cookies: []
  };
  const sessionToken = sessionStore.value;
  if (!sessionToken)
    return response;
  if (sessionStrategy === "jwt") {
    try {
      const decodedToken = await jwt2.decode({ ...jwt2, token: sessionToken });
      if (!decodedToken)
        throw new Error("Invalid JWT");
      const token = await callbacks.jwt({
        token: decodedToken,
        ...isUpdate && { trigger: "update" },
        session: newSession
      });
      const newExpires = fromDate(sessionMaxAge);
      if (token !== null) {
        const session2 = {
          user: { name: token.name, email: token.email, image: token.picture },
          expires: newExpires.toISOString()
        };
        const newSession2 = await callbacks.session({ session: session2, token });
        response.body = newSession2;
        const newToken = await jwt2.encode({
          ...jwt2,
          token
        });
        const sessionCookies = sessionStore.chunk(newToken, {
          expires: newExpires
        });
        response.cookies?.push(...sessionCookies);
        await events.session?.({ session: newSession2, token });
      } else {
        response.cookies?.push(...sessionStore.clean());
      }
    } catch (e2) {
      logger2.error(new JWTSessionError(e2));
      response.cookies?.push(...sessionStore.clean());
    }
    return response;
  }
  try {
    const { getSessionAndUser, deleteSession, updateSession } = adapter;
    let userAndSession = await getSessionAndUser(sessionToken);
    if (userAndSession && userAndSession.session.expires.valueOf() < Date.now()) {
      await deleteSession(sessionToken);
      userAndSession = null;
    }
    if (userAndSession) {
      const { user, session: session2 } = userAndSession;
      const sessionUpdateAge = options.session.updateAge;
      const sessionIsDueToBeUpdatedDate = session2.expires.valueOf() - sessionMaxAge * 1e3 + sessionUpdateAge * 1e3;
      const newExpires = fromDate(sessionMaxAge);
      if (sessionIsDueToBeUpdatedDate <= Date.now()) {
        await updateSession({
          sessionToken,
          expires: newExpires
        });
      }
      const sessionPayload = await callbacks.session({
        session: {
          user: { name: user.name, email: user.email, image: user.image },
          expires: session2.expires.toISOString()
        },
        user,
        newSession,
        ...isUpdate ? { trigger: "update" } : {}
      });
      response.body = sessionPayload;
      response.cookies?.push({
        name: options.cookies.sessionToken.name,
        value: sessionToken,
        options: {
          ...options.cookies.sessionToken.options,
          expires: newExpires
        }
      });
      await events.session?.({ session: sessionPayload });
    } else if (sessionToken) {
      response.cookies?.push(...sessionStore.clean());
    }
  } catch (e2) {
    logger2.error(new SessionTokenError(e2));
  }
  return response;
}
var init_session = __esm({
  "../../node_modules/@auth/core/lib/routes/session.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_errors();
    init_date();
  }
});

// ../../node_modules/@auth/core/lib/email/signin.js
async function email(identifier, options) {
  const { url, adapter, provider, callbackUrl, theme } = options;
  const token = await provider.generateVerificationToken?.() ?? randomString(32);
  const ONE_DAY_IN_SECONDS = 86400;
  const expires = new Date(Date.now() + (provider.maxAge ?? ONE_DAY_IN_SECONDS) * 1e3);
  const params = new URLSearchParams({ callbackUrl, token, email: identifier });
  const _url = `${url}/callback/${provider.id}?${params}`;
  const secret = provider.secret ?? options.secret;
  await Promise.all([
    provider.sendVerificationRequest({
      identifier,
      token,
      expires,
      url: _url,
      provider,
      theme
    }),
    adapter.createVerificationToken?.({
      identifier,
      token: await createHash(`${token}${secret}`),
      expires
    })
  ]);
  return `${url}/verify-request?${new URLSearchParams({
    provider: provider.id,
    type: provider.type
  })}`;
}
var init_signin2 = __esm({
  "../../node_modules/@auth/core/lib/email/signin.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_web2();
  }
});

// ../../node_modules/@auth/core/lib/oauth/authorization-url.js
async function getAuthorizationUrl(query, options) {
  const { logger: logger2, provider } = options;
  let url = provider.authorization?.url;
  let as;
  if (!url || url.host === "authjs.dev") {
    const issuer = new URL(provider.issuer);
    const discoveryResponse = await discoveryRequest(issuer);
    const as2 = await processDiscoveryResponse(issuer, discoveryResponse);
    if (!as2.authorization_endpoint) {
      throw new TypeError("Authorization server did not provide an authorization endpoint.");
    }
    url = new URL(as2.authorization_endpoint);
  }
  const authParams = url.searchParams;
  let redirect_uri = provider.callbackUrl;
  let data;
  if (!options.isOnRedirectProxy && provider.redirectProxyUrl) {
    redirect_uri = provider.redirectProxyUrl;
    data = { origin: provider.callbackUrl };
    logger2.debug("using redirect proxy", { redirect_uri, data });
  }
  const params = Object.assign({
    response_type: "code",
    client_id: provider.clientId,
    redirect_uri,
    ...provider.authorization?.params
  }, Object.fromEntries(provider.authorization?.url.searchParams ?? []), query);
  for (const k3 in params)
    authParams.set(k3, params[k3]);
  const cookies = [];
  const state2 = await state.create(options, data);
  if (state2) {
    authParams.set("state", state2.value);
    cookies.push(state2.cookie);
  }
  if (provider.checks?.includes("pkce")) {
    if (as && !as.code_challenge_methods_supported?.includes("S256")) {
      if (provider.type === "oidc")
        provider.checks = ["nonce"];
    } else {
      const { value, cookie } = await pkce.create(options);
      authParams.set("code_challenge", value);
      authParams.set("code_challenge_method", "S256");
      cookies.push(cookie);
    }
  }
  const nonce2 = await nonce.create(options);
  if (nonce2) {
    authParams.set("nonce", nonce2.value);
    cookies.push(nonce2.cookie);
  }
  if (provider.type === "oidc" && !url.searchParams.has("scope")) {
    url.searchParams.set("scope", "openid profile email");
  }
  logger2.debug("authorization url is ready", { url, cookies, provider });
  return { redirect: url.toString(), cookies };
}
var init_authorization_url = __esm({
  "../../node_modules/@auth/core/lib/oauth/authorization-url.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_checks();
    init_build();
  }
});

// ../../node_modules/@auth/core/lib/routes/signin.js
async function signin(query, body, options) {
  const { url, logger: logger2, provider } = options;
  try {
    if (provider.type === "oauth" || provider.type === "oidc") {
      return await getAuthorizationUrl(query, options);
    } else if (provider.type === "email") {
      const normalizer = provider.normalizeIdentifier ?? defaultNormalizer;
      const email2 = normalizer(body?.email);
      const user = await options.adapter.getUserByEmail(email2) ?? {
        id: email2,
        email: email2,
        emailVerified: null
      };
      const account = {
        providerAccountId: email2,
        userId: user.id,
        type: "email",
        provider: provider.id
      };
      const unauthorizedOrError = await handleAuthorized({ user, account, email: { verificationRequest: true } }, options);
      if (unauthorizedOrError)
        return unauthorizedOrError;
      const redirect = await email(email2, options);
      return { redirect };
    }
    return { redirect: `${url}/signin` };
  } catch (e2) {
    const error = new SignInError(e2, { provider: provider.id });
    logger2.error(error);
    const code = provider.type === "email" ? "EmailSignin" : "OAuthSignin";
    url.searchParams.set("error", code);
    url.pathname += "/signin";
    return { redirect: url.toString() };
  }
}
function defaultNormalizer(email2) {
  if (!email2)
    throw new Error("Missing email from request body.");
  let [local, domain] = email2.toLowerCase().trim().split("@");
  domain = domain.split(",")[0];
  return `${local}@${domain}`;
}
var init_signin3 = __esm({
  "../../node_modules/@auth/core/lib/routes/signin.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_signin2();
    init_errors();
    init_authorization_url();
    init_shared();
  }
});

// ../../node_modules/@auth/core/lib/routes/signout.js
async function signout(sessionStore, options) {
  const { jwt: jwt2, events, callbackUrl: redirect, logger: logger2, session: session2 } = options;
  const sessionToken = sessionStore.value;
  if (!sessionToken)
    return { redirect };
  try {
    if (session2.strategy === "jwt") {
      const token = await jwt2.decode({ ...jwt2, token: sessionToken });
      await events.signOut?.({ token });
    } else {
      const session3 = await options.adapter?.deleteSession(sessionToken);
      await events.signOut?.({ session: session3 });
    }
  } catch (e2) {
    logger2.error(new SignOutError(e2));
  }
  return { redirect, cookies: sessionStore.clean() };
}
var init_signout2 = __esm({
  "../../node_modules/@auth/core/lib/routes/signout.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_errors();
  }
});

// ../../node_modules/@auth/core/lib/routes/index.js
var init_routes = __esm({
  "../../node_modules/@auth/core/lib/routes/index.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_callback2();
    init_providers2();
    init_session();
    init_signin3();
    init_signout2();
  }
});

// ../../node_modules/@auth/core/lib/index.js
async function AuthInternal(request, authOptions) {
  const { action, providerId, error, method } = request;
  const csrfDisabled = authOptions.skipCSRFCheck === skipCSRFCheck;
  const { options, cookies } = await init({
    authOptions,
    action,
    providerId,
    url: request.url,
    callbackUrl: request.body?.callbackUrl ?? request.query?.callbackUrl,
    csrfToken: request.body?.csrfToken,
    cookies: request.cookies,
    isPost: method === "POST",
    csrfDisabled
  });
  const sessionStore = new SessionStore(options.cookies.sessionToken, request, options.logger);
  if (method === "GET") {
    const render = renderPage({ ...options, query: request.query, cookies });
    const { pages } = options;
    switch (action) {
      case "providers":
        return await providers(options.providers);
      case "session": {
        const session2 = await session({ sessionStore, options });
        if (session2.cookies)
          cookies.push(...session2.cookies);
        return { ...session2, cookies };
      }
      case "csrf": {
        if (csrfDisabled) {
          options.logger.warn("csrf-disabled");
          cookies.push({
            name: options.cookies.csrfToken.name,
            value: "",
            options: { ...options.cookies.csrfToken.options, maxAge: 0 }
          });
          return { status: 404, cookies };
        }
        return {
          headers: { "Content-Type": "application/json" },
          body: { csrfToken: options.csrfToken },
          cookies
        };
      }
      case "signin":
        if (pages.signIn) {
          let signinUrl = `${pages.signIn}${pages.signIn.includes("?") ? "&" : "?"}${new URLSearchParams({ callbackUrl: options.callbackUrl })}`;
          if (error)
            signinUrl = `${signinUrl}&${new URLSearchParams({ error })}`;
          return { redirect: signinUrl, cookies };
        }
        return render.signin();
      case "signout":
        if (pages.signOut)
          return { redirect: pages.signOut, cookies };
        return render.signout();
      case "callback":
        if (options.provider) {
          const callback2 = await callback({
            body: request.body,
            query: request.query,
            headers: request.headers,
            cookies: request.cookies,
            method,
            options,
            sessionStore
          });
          if (callback2.cookies)
            cookies.push(...callback2.cookies);
          return { ...callback2, cookies };
        }
        break;
      case "verify-request":
        if (pages.verifyRequest) {
          return { redirect: pages.verifyRequest, cookies };
        }
        return render.verifyRequest();
      case "error":
        if ([
          "Signin",
          "OAuthCreateAccount",
          "EmailCreateAccount",
          "Callback",
          "OAuthAccountNotLinked",
          "SessionRequired"
        ].includes(error)) {
          return { redirect: `${options.url}/signin?error=${error}`, cookies };
        }
        if (pages.error) {
          return {
            redirect: `${pages.error}${pages.error.includes("?") ? "&" : "?"}error=${error}`,
            cookies
          };
        }
        return render.error({ error });
      default:
    }
  } else {
    switch (action) {
      case "signin":
        if ((csrfDisabled || options.csrfTokenVerified) && options.provider) {
          const signin2 = await signin(request.query, request.body, options);
          if (signin2.cookies)
            cookies.push(...signin2.cookies);
          return { ...signin2, cookies };
        }
        return { redirect: `${options.url}/signin?csrf=true`, cookies };
      case "signout":
        if (csrfDisabled || options.csrfTokenVerified) {
          const signout2 = await signout(sessionStore, options);
          if (signout2.cookies)
            cookies.push(...signout2.cookies);
          return { ...signout2, cookies };
        }
        return { redirect: `${options.url}/signout?csrf=true`, cookies };
      case "callback":
        if (options.provider) {
          if (options.provider.type === "credentials" && !csrfDisabled && !options.csrfTokenVerified) {
            return { redirect: `${options.url}/signin?csrf=true`, cookies };
          }
          const callback2 = await callback({
            body: request.body,
            query: request.query,
            headers: request.headers,
            cookies: request.cookies,
            method,
            options,
            sessionStore
          });
          if (callback2.cookies)
            cookies.push(...callback2.cookies);
          return { ...callback2, cookies };
        }
        break;
      case "session": {
        if (options.csrfTokenVerified) {
          const session2 = await session({
            options,
            sessionStore,
            newSession: request.body?.data,
            isUpdate: true
          });
          if (session2.cookies)
            cookies.push(...session2.cookies);
          return { ...session2, cookies };
        }
        return { status: 400, cookies };
      }
      default:
    }
  }
  throw new UnknownAction(`Cannot handle action: ${action}`);
}
var skipCSRFCheck;
var init_lib = __esm({
  "../../node_modules/@auth/core/lib/index.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_errors();
    init_cookie();
    init_init();
    init_pages();
    init_routes();
    skipCSRFCheck = Symbol("skip-csrf-check");
  }
});

// ../../node_modules/@auth/core/index.js
async function Auth(request, config) {
  setLogger(config.logger, config.debug);
  const internalRequest = await toInternalRequest(request);
  if (internalRequest instanceof Error) {
    logger.error(internalRequest);
    return new Response(`Error: This action with HTTP ${request.method} is not supported.`, { status: 400 });
  }
  const assertionResult = assertConfig(internalRequest, config);
  if (Array.isArray(assertionResult)) {
    assertionResult.forEach(logger.warn);
  } else if (assertionResult instanceof Error) {
    logger.error(assertionResult);
    const htmlPages = ["signin", "signout", "error", "verify-request"];
    if (!htmlPages.includes(internalRequest.action) || internalRequest.method !== "GET") {
      return new Response(JSON.stringify({
        message: "There was a problem with the server configuration. Check the server logs for more information.",
        code: assertionResult.name
      }), { status: 500, headers: { "Content-Type": "application/json" } });
    }
    const { pages, theme } = config;
    const authOnErrorPage = pages?.error && internalRequest.url.searchParams.get("callbackUrl")?.startsWith(pages.error);
    if (!pages?.error || authOnErrorPage) {
      if (authOnErrorPage) {
        logger.error(new ErrorPageLoop(`The error page ${pages?.error} should not require authentication`));
      }
      const render = renderPage({ theme });
      const page = render.error({ error: "Configuration" });
      return toResponse(page);
    }
    return Response.redirect(`${pages.error}?error=Configuration`);
  }
  const internalResponse = await AuthInternal(internalRequest, config);
  const response = await toResponse(internalResponse);
  const redirect = response.headers.get("Location");
  if (request.headers.has("X-Auth-Return-Redirect") && redirect) {
    response.headers.delete("Location");
    response.headers.set("Content-Type", "application/json");
    return new Response(JSON.stringify({ url: redirect }), {
      headers: response.headers
    });
  }
  return response;
}
var init_core = __esm({
  "../../node_modules/@auth/core/index.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_assert();
    init_errors();
    init_lib();
    init_pages();
    init_logger();
    init_web2();
  }
});

// src/auth.js
var actions2, getAuthOptions;
var init_auth = __esm({
  "src/auth.js"() {
    init_functionsRoutes_0_9412289658568613();
    actions2 = [
      "providers",
      "session",
      "csrf",
      "signin",
      "signout",
      "callback",
      "verify-request",
      "error"
    ];
    getAuthOptions = async (paramAuthOptions, context) => {
      const authOptions = typeof paramAuthOptions === "object" ? paramAuthOptions : await paramAuthOptions(context);
      authOptions.secret ??= context.env.AUTH_SECRET;
      authOptions.trustHost ??= context.env.xxx;
      return authOptions;
    };
  }
});

// functions/_middleware.js
var onRequest;
var init_middleware = __esm({
  "functions/_middleware.js"() {
    init_functionsRoutes_0_9412289658568613();
    init_core();
    init_auth();
    onRequest = async (context) => {
      const { next, request, pluginArgs } = context;
      const url = new URL(request.url);
      const authOptions = await getAuthOptions(pluginArgs, context);
      const { prefix = "/auth" } = authOptions;
      const action = url.pathname.slice(prefix.length + 1).split("/")[0];
      if (!actions2.includes(action) || !url.pathname.startsWith(prefix + "/")) {
        return next();
      }
      const resp = await Auth(request, authOptions);
      return resp;
    };
  }
});

// ../../../../../../../../tmp/functionsRoutes-0.9412289658568613.mjs
var routes;
var init_functionsRoutes_0_9412289658568613 = __esm({
  "../../../../../../../../tmp/functionsRoutes-0.9412289658568613.mjs"() {
    init_middleware();
    routes = [
      {
        routePath: "/",
        mountPath: "/",
        method: "",
        middlewares: [onRequest],
        modules: []
      }
    ];
  }
});

// ../../../../../../../../home/kjartanm/.nvm/versions/node/v16.18.0/lib/node_modules/wrangler/templates/pages-template-plugin.ts
init_functionsRoutes_0_9412289658568613();

// ../../../../../../../../home/kjartanm/.nvm/versions/node/v16.18.0/lib/node_modules/wrangler/node_modules/path-to-regexp/dist.es2015/index.js
init_functionsRoutes_0_9412289658568613();
function lexer(str) {
  var tokens = [];
  var i3 = 0;
  while (i3 < str.length) {
    var char = str[i3];
    if (char === "*" || char === "+" || char === "?") {
      tokens.push({ type: "MODIFIER", index: i3, value: str[i3++] });
      continue;
    }
    if (char === "\\") {
      tokens.push({ type: "ESCAPED_CHAR", index: i3++, value: str[i3++] });
      continue;
    }
    if (char === "{") {
      tokens.push({ type: "OPEN", index: i3, value: str[i3++] });
      continue;
    }
    if (char === "}") {
      tokens.push({ type: "CLOSE", index: i3, value: str[i3++] });
      continue;
    }
    if (char === ":") {
      var name = "";
      var j3 = i3 + 1;
      while (j3 < str.length) {
        var code = str.charCodeAt(j3);
        if (code >= 48 && code <= 57 || code >= 65 && code <= 90 || code >= 97 && code <= 122 || code === 95) {
          name += str[j3++];
          continue;
        }
        break;
      }
      if (!name)
        throw new TypeError("Missing parameter name at ".concat(i3));
      tokens.push({ type: "NAME", index: i3, value: name });
      i3 = j3;
      continue;
    }
    if (char === "(") {
      var count = 1;
      var pattern = "";
      var j3 = i3 + 1;
      if (str[j3] === "?") {
        throw new TypeError('Pattern cannot start with "?" at '.concat(j3));
      }
      while (j3 < str.length) {
        if (str[j3] === "\\") {
          pattern += str[j3++] + str[j3++];
          continue;
        }
        if (str[j3] === ")") {
          count--;
          if (count === 0) {
            j3++;
            break;
          }
        } else if (str[j3] === "(") {
          count++;
          if (str[j3 + 1] !== "?") {
            throw new TypeError("Capturing groups are not allowed at ".concat(j3));
          }
        }
        pattern += str[j3++];
      }
      if (count)
        throw new TypeError("Unbalanced pattern at ".concat(i3));
      if (!pattern)
        throw new TypeError("Missing pattern at ".concat(i3));
      tokens.push({ type: "PATTERN", index: i3, value: pattern });
      i3 = j3;
      continue;
    }
    tokens.push({ type: "CHAR", index: i3, value: str[i3++] });
  }
  tokens.push({ type: "END", index: i3, value: "" });
  return tokens;
}
function parse2(str, options) {
  if (options === void 0) {
    options = {};
  }
  var tokens = lexer(str);
  var _a = options.prefixes, prefixes = _a === void 0 ? "./" : _a;
  var defaultPattern = "[^".concat(escapeString(options.delimiter || "/#?"), "]+?");
  var result = [];
  var key = 0;
  var i3 = 0;
  var path = "";
  var tryConsume = function(type) {
    if (i3 < tokens.length && tokens[i3].type === type)
      return tokens[i3++].value;
  };
  var mustConsume = function(type) {
    var value2 = tryConsume(type);
    if (value2 !== void 0)
      return value2;
    var _a2 = tokens[i3], nextType = _a2.type, index = _a2.index;
    throw new TypeError("Unexpected ".concat(nextType, " at ").concat(index, ", expected ").concat(type));
  };
  var consumeText = function() {
    var result2 = "";
    var value2;
    while (value2 = tryConsume("CHAR") || tryConsume("ESCAPED_CHAR")) {
      result2 += value2;
    }
    return result2;
  };
  while (i3 < tokens.length) {
    var char = tryConsume("CHAR");
    var name = tryConsume("NAME");
    var pattern = tryConsume("PATTERN");
    if (name || pattern) {
      var prefix = char || "";
      if (prefixes.indexOf(prefix) === -1) {
        path += prefix;
        prefix = "";
      }
      if (path) {
        result.push(path);
        path = "";
      }
      result.push({
        name: name || key++,
        prefix,
        suffix: "",
        pattern: pattern || defaultPattern,
        modifier: tryConsume("MODIFIER") || ""
      });
      continue;
    }
    var value = char || tryConsume("ESCAPED_CHAR");
    if (value) {
      path += value;
      continue;
    }
    if (path) {
      result.push(path);
      path = "";
    }
    var open = tryConsume("OPEN");
    if (open) {
      var prefix = consumeText();
      var name_1 = tryConsume("NAME") || "";
      var pattern_1 = tryConsume("PATTERN") || "";
      var suffix = consumeText();
      mustConsume("CLOSE");
      result.push({
        name: name_1 || (pattern_1 ? key++ : ""),
        pattern: name_1 && !pattern_1 ? defaultPattern : pattern_1,
        prefix,
        suffix,
        modifier: tryConsume("MODIFIER") || ""
      });
      continue;
    }
    mustConsume("END");
  }
  return result;
}
function match(str, options) {
  var keys = [];
  var re = pathToRegexp(str, keys, options);
  return regexpToFunction(re, keys, options);
}
function regexpToFunction(re, keys, options) {
  if (options === void 0) {
    options = {};
  }
  var _a = options.decode, decode4 = _a === void 0 ? function(x2) {
    return x2;
  } : _a;
  return function(pathname) {
    var m3 = re.exec(pathname);
    if (!m3)
      return false;
    var path = m3[0], index = m3.index;
    var params = /* @__PURE__ */ Object.create(null);
    var _loop_1 = function(i4) {
      if (m3[i4] === void 0)
        return "continue";
      var key = keys[i4 - 1];
      if (key.modifier === "*" || key.modifier === "+") {
        params[key.name] = m3[i4].split(key.prefix + key.suffix).map(function(value) {
          return decode4(value, key);
        });
      } else {
        params[key.name] = decode4(m3[i4], key);
      }
    };
    for (var i3 = 1; i3 < m3.length; i3++) {
      _loop_1(i3);
    }
    return { path, index, params };
  };
}
function escapeString(str) {
  return str.replace(/([.+*?=^!:${}()[\]|/\\])/g, "\\$1");
}
function flags(options) {
  return options && options.sensitive ? "" : "i";
}
function regexpToRegexp(path, keys) {
  if (!keys)
    return path;
  var groupsRegex = /\((?:\?<(.*?)>)?(?!\?)/g;
  var index = 0;
  var execResult = groupsRegex.exec(path.source);
  while (execResult) {
    keys.push({
      name: execResult[1] || index++,
      prefix: "",
      suffix: "",
      modifier: "",
      pattern: ""
    });
    execResult = groupsRegex.exec(path.source);
  }
  return path;
}
function arrayToRegexp(paths, keys, options) {
  var parts = paths.map(function(path) {
    return pathToRegexp(path, keys, options).source;
  });
  return new RegExp("(?:".concat(parts.join("|"), ")"), flags(options));
}
function stringToRegexp(path, keys, options) {
  return tokensToRegexp(parse2(path, options), keys, options);
}
function tokensToRegexp(tokens, keys, options) {
  if (options === void 0) {
    options = {};
  }
  var _a = options.strict, strict = _a === void 0 ? false : _a, _b = options.start, start = _b === void 0 ? true : _b, _c = options.end, end = _c === void 0 ? true : _c, _d = options.encode, encode4 = _d === void 0 ? function(x2) {
    return x2;
  } : _d, _e = options.delimiter, delimiter = _e === void 0 ? "/#?" : _e, _f = options.endsWith, endsWith = _f === void 0 ? "" : _f;
  var endsWithRe = "[".concat(escapeString(endsWith), "]|$");
  var delimiterRe = "[".concat(escapeString(delimiter), "]");
  var route = start ? "^" : "";
  for (var _i = 0, tokens_1 = tokens; _i < tokens_1.length; _i++) {
    var token = tokens_1[_i];
    if (typeof token === "string") {
      route += escapeString(encode4(token));
    } else {
      var prefix = escapeString(encode4(token.prefix));
      var suffix = escapeString(encode4(token.suffix));
      if (token.pattern) {
        if (keys)
          keys.push(token);
        if (prefix || suffix) {
          if (token.modifier === "+" || token.modifier === "*") {
            var mod = token.modifier === "*" ? "?" : "";
            route += "(?:".concat(prefix, "((?:").concat(token.pattern, ")(?:").concat(suffix).concat(prefix, "(?:").concat(token.pattern, "))*)").concat(suffix, ")").concat(mod);
          } else {
            route += "(?:".concat(prefix, "(").concat(token.pattern, ")").concat(suffix, ")").concat(token.modifier);
          }
        } else {
          if (token.modifier === "+" || token.modifier === "*") {
            route += "((?:".concat(token.pattern, ")").concat(token.modifier, ")");
          } else {
            route += "(".concat(token.pattern, ")").concat(token.modifier);
          }
        }
      } else {
        route += "(?:".concat(prefix).concat(suffix, ")").concat(token.modifier);
      }
    }
  }
  if (end) {
    if (!strict)
      route += "".concat(delimiterRe, "?");
    route += !options.endsWith ? "$" : "(?=".concat(endsWithRe, ")");
  } else {
    var endToken = tokens[tokens.length - 1];
    var isEndDelimited = typeof endToken === "string" ? delimiterRe.indexOf(endToken[endToken.length - 1]) > -1 : endToken === void 0;
    if (!strict) {
      route += "(?:".concat(delimiterRe, "(?=").concat(endsWithRe, "))?");
    }
    if (!isEndDelimited) {
      route += "(?=".concat(delimiterRe, "|").concat(endsWithRe, ")");
    }
  }
  return new RegExp(route, flags(options));
}
function pathToRegexp(path, keys, options) {
  if (path instanceof RegExp)
    return regexpToRegexp(path, keys);
  if (Array.isArray(path))
    return arrayToRegexp(path, keys, options);
  return stringToRegexp(path, keys, options);
}

// ../../../../../../../../home/kjartanm/.nvm/versions/node/v16.18.0/lib/node_modules/wrangler/templates/pages-template-plugin.ts
var escapeRegex = /[.+?^${}()|[\]\\]/g;
function* executeRequest(request, relativePathname) {
  for (const route of [...routes].reverse()) {
    if (route.method && route.method !== request.method) {
      continue;
    }
    const routeMatcher = match(route.routePath.replace(escapeRegex, "\\$&"), {
      end: false
    });
    const mountMatcher = match(route.mountPath.replace(escapeRegex, "\\$&"), {
      end: false
    });
    const matchResult = routeMatcher(relativePathname);
    const mountMatchResult = mountMatcher(relativePathname);
    if (matchResult && mountMatchResult) {
      for (const handler of route.middlewares.flat()) {
        yield {
          handler,
          params: matchResult.params,
          path: mountMatchResult.path
        };
      }
    }
  }
  for (const route of routes) {
    if (route.method && route.method !== request.method) {
      continue;
    }
    const routeMatcher = match(route.routePath.replace(escapeRegex, "\\$&"), {
      end: true
    });
    const mountMatcher = match(route.mountPath.replace(escapeRegex, "\\$&"), {
      end: false
    });
    const matchResult = routeMatcher(relativePathname);
    const mountMatchResult = mountMatcher(relativePathname);
    if (matchResult && mountMatchResult && route.modules.length) {
      for (const handler of route.modules.flat()) {
        yield {
          handler,
          params: matchResult.params,
          path: matchResult.path
        };
      }
      break;
    }
  }
}
function pages_template_plugin_default(pluginArgs) {
  const onRequest2 = async (workerContext) => {
    let { request } = workerContext;
    const { env, next, data } = workerContext;
    const url = new URL(request.url);
    const relativePathname = `/${url.pathname.split(workerContext.functionPath)[1] || ""}`.replace(/^\/\//, "/");
    const handlerIterator = executeRequest(request, relativePathname);
    const pluginNext = async (input, init2) => {
      if (input !== void 0) {
        request = new Request(input, init2);
      }
      const result = handlerIterator.next();
      if (result.done === false) {
        const { handler, params, path } = result.value;
        const context = {
          request,
          functionPath: workerContext.functionPath + path,
          next: pluginNext,
          params,
          data,
          pluginArgs,
          env,
          waitUntil: workerContext.waitUntil.bind(workerContext)
        };
        const response = await handler(context);
        return new Response(
          [101, 204, 205, 304].includes(response.status) ? null : response.body,
          { ...response, headers: new Headers(response.headers) }
        );
      } else {
        return next();
      }
    };
    return pluginNext();
  };
  return onRequest2;
}
export {
  pages_template_plugin_default as default
};
/*!
 * cookie
 * Copyright(c) 2012-2014 Roman Shtylman
 * Copyright(c) 2015 Douglas Christopher Wilson
 * MIT Licensed
 */
