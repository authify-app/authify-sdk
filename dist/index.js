"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseCallback = exports.buildShareUrl = exports.buildAuthUrl = exports.hasNonce = exports.addNonce = exports.generateNonce = exports.verify = exports.sign = exports.fromBase64Url = exports.toBase64Url = exports.computeSharedSecret = exports.generateEphemeralKeyPair = exports.AuthifyClient = void 0;
var AuthifyClient_1 = require("./AuthifyClient");
Object.defineProperty(exports, "AuthifyClient", { enumerable: true, get: function () { return AuthifyClient_1.AuthifyClient; } });
// Crypto utilities needed by the Authify host app (re-exported for reuse)
var keyPair_1 = require("./crypto/keyPair");
Object.defineProperty(exports, "generateEphemeralKeyPair", { enumerable: true, get: function () { return keyPair_1.generateEphemeralKeyPair; } });
Object.defineProperty(exports, "computeSharedSecret", { enumerable: true, get: function () { return keyPair_1.computeSharedSecret; } });
var encrypt_1 = require("./crypto/encrypt");
Object.defineProperty(exports, "toBase64Url", { enumerable: true, get: function () { return encrypt_1.toBase64Url; } });
Object.defineProperty(exports, "fromBase64Url", { enumerable: true, get: function () { return encrypt_1.fromBase64Url; } });
var signing_1 = require("./crypto/signing");
Object.defineProperty(exports, "sign", { enumerable: true, get: function () { return signing_1.sign; } });
Object.defineProperty(exports, "verify", { enumerable: true, get: function () { return signing_1.verify; } });
var nonceStore_1 = require("./session/nonceStore");
Object.defineProperty(exports, "generateNonce", { enumerable: true, get: function () { return nonceStore_1.generateNonce; } });
Object.defineProperty(exports, "addNonce", { enumerable: true, get: function () { return nonceStore_1.addNonce; } });
Object.defineProperty(exports, "hasNonce", { enumerable: true, get: function () { return nonceStore_1.hasNonce; } });
// Deep link helpers (for testing/advanced use)
var builder_1 = require("./deeplink/builder");
Object.defineProperty(exports, "buildAuthUrl", { enumerable: true, get: function () { return builder_1.buildAuthUrl; } });
Object.defineProperty(exports, "buildShareUrl", { enumerable: true, get: function () { return builder_1.buildShareUrl; } });
var parser_1 = require("./deeplink/parser");
Object.defineProperty(exports, "parseCallback", { enumerable: true, get: function () { return parser_1.parseCallback; } });
//# sourceMappingURL=index.js.map