/**
 * OpenSSL crypto engine
 *
 * @namespace openssl
 */

import PromiseA = require("bluebird");
import fs = require("fs-extra");
import net = require("net");
import tempfile = require("tempfile");
import { CertificateInfo, DomainNames } from "../types";

const opensslExec = require("openssl-wrapper").exec;

function openssl(...args): Promise<any> {
  return new Promise((resolve, reject) => {
    opensslExec(...args, (err, result) => (err ? reject(err) : resolve(result))).on("error", reject);
  });
}

function hexpad(str) {
  return ((str.length % 2) === 1) ? `0${str}` : str;
}


/**
 * Parse domain names from a certificate or CSR
 *
 * @private
 * @param {string} cert Certificate or CSR
 * @returns {object} {commonName, altNames}
 */

function parseDomains(cert: string): DomainNames {
  const altNames: string[] = [];
  let commonName: string = "";
  const commonNameMatch = cert.match(/Subject:.*? CN\s?=\s?([^\s,;/]+)/);
  const altNamesMatch = cert.match(/X509v3 Subject Alternative Name:\s?\n\s*([^\n]+)\n/);

  /* Subject common name */
  if (commonNameMatch) {
    commonName = commonNameMatch[1];
  }

  /* Alternative names */
  if (altNamesMatch) {
    altNamesMatch[1].split(/,\s*/).forEach((altName) => {
      if (altName.match(/^DNS:/)) {
        altNames.push(altName.replace(/^DNS:/, ""));
      }
    });
  }

  return {
    commonName,
    altNames
  };
}


/**
 * Get OpenSSL action from buffer
 *
 * @private
 * @param {buffer} key Private key, certificate or CSR
 * @returns {string} OpenSSL action
 */

function getAction(key) {
  const keyString = key.toString();

  if (keyString.match(/CERTIFICATE\sREQUEST-{5}$/m)) {
    return "req";
  } else if (keyString.match(/(PUBLIC|PRIVATE)\sKEY-{5}$/m)) {
    return "rsa";
  }

  return "x509";
}


/**
 * Check if key is public
 *
 * @private
 * @param {buffer} key
 * @returns {boolean} True if key is public
 */

function isPublic(key) {
  return !!key.toString().match(/PUBLIC\sKEY-{5}$/m);
}


/**
 * Generate a private RSA key
 *
 * @param {number} [size] Size of the key, default: `2048`
 * @returns {PromiseA<buffer>} Private RSA key
 */

export function createPrivateKey(size = 2048): Promise<Buffer> {
  const opts = {};
  opts[size] = false;

  return openssl("genrsa", opts);
}


/**
 * Generate a public RSA key
 *
 * @param {buffer|string} key PEM encoded private key
 * @returns {PromiseA<buffer>} Public RSA key
 */

export function createPublicKey(key): Promise<Buffer> {
  if (!Buffer.isBuffer(key)) {
    key = Buffer.from(key);
  }

  const action = getAction(key);
  const opts = { pubout: true };

  return openssl(action, key, opts);
}

/**
 * Get modulus
 *
 * @param {buffer|string} input PEM encoded private key, certificate or CSR
 * @returns {PromiseA<buffer>} Modulus
 */

export async function getModulus(input) {
  if (!Buffer.isBuffer(input)) {
    input = Buffer.from(input);
  }

  const action = getAction(input);
  const opts: any = { noout: true, modulus: true };

  if (isPublic(input)) {
    opts.pubin = true;
  }

  const buf = await openssl(action, input, opts);
  const modulusMatch = buf.toString().match(/^Modulus=([A-Fa-f0-9]+)$/m);

  if (!modulusMatch) {
    throw new Error("No modulus found");
  }

  return Buffer.from(modulusMatch[1], "hex");
}

/**
 * Get public exponent
 *
 * @param {buffer|string} input PEM encoded private key, certificate or CSR
 * @returns {PromiseA<buffer>} Exponent
 */

export async function getPublicExponent(input) {
  if (!Buffer.isBuffer(input)) {
    input = Buffer.from(input);
  }

  const action = getAction(input);
  const opts: any = { noout: true, text: true };

  if (isPublic(input)) {
    opts.pubin = true;
  }

  const buf = await openssl(action, input, opts);
  const exponentMatch = buf.toString().match(/xponent:.*\(0x(\d+)\)/);

  if (!exponentMatch) {
    throw new Error("No public exponent found");
  }

  /* Pad exponent hex value */
  return Buffer.from(hexpad(exponentMatch[1]), "hex");
}

/**
 * Read domains from a Certificate Signing Request
 *
 * @param {buffer|string} csr PEM encoded Certificate Signing Request
 * @returns {PromiseA<object>} {commonName, altNames}
 */

export async function readCsrDomains(csr): Promise<DomainNames> {
  if (!Buffer.isBuffer(csr)) {
    csr = Buffer.from(csr);
  }

  const opts = { noout: true, text: true };
  const buf = await openssl("req", csr, opts);

  return parseDomains(buf.toString());
}

/**
 * Read information from a certificate
 *
 * @param {buffer|string} cert PEM encoded certificate
 * @returns {PromiseA<object>} Certificate info
 */

export async function readCertificateInfo(cert): Promise<CertificateInfo> {
  if (!Buffer.isBuffer(cert)) {
    cert = Buffer.from(cert);
  }

  const opts = { noout: true, text: true };
  const buf = await openssl("x509", cert, opts);
  const bufString = buf.toString();

  const result: CertificateInfo = {
    domains: parseDomains(bufString)
  };

  const notBeforeMatch = bufString.match(/Not\sBefore\s?:\s+([^\n]*)\n/);
  const notAfterMatch = bufString.match(/Not\sAfter\s?:\s+([^\n]*)\n/);

  if (notBeforeMatch) {
    result.notBefore = new Date(notBeforeMatch[1]);
  }

  if (notAfterMatch) {
    result.notAfter = new Date(notAfterMatch[1]);
  }

  return result;
}

export interface CsrOptions {
  new: boolean;
  sha256: boolean;
  subj: string;
  extensions?: string;
  key?: string;
  config?: string;
}

/**
 * Execute Certificate Signing Request generation
 *
 * @private
 * @param {object} opts CSR options
 * @param {string} csrConfig CSR configuration file
 * @param {buffer} key CSR private key
 * @returns {PromiseA<buffer>} CSR
 */

async function generateCsr(opts: CsrOptions, csrConfig: string, key) {
  let tempConfigFilePath;

  /* Write key to disk */
  const tempKeyFilePath = tempfile();
  await fs.writeFile(tempKeyFilePath, key);
  opts.key = tempKeyFilePath;

  /* Write config to disk */
  if (csrConfig) {
    tempConfigFilePath = tempfile();
    await fs.writeFile(tempConfigFilePath, csrConfig);
    opts.config = tempConfigFilePath;
  }

  /* Create CSR */
  const result = await openssl("req", opts);

  /* Clean up */
  await fs.unlink(tempKeyFilePath);

  if (tempConfigFilePath) {
    await fs.unlink(tempConfigFilePath);
  }

  return result;
}

export interface CsrSubjectOptions {
  commonName?: string;
  country?: string;
  state?: string;
  locality?: string;
  organization?: string;
  organizationUnit?: string;
  emailAddress?: string;
}

/**
 * Create Certificate Signing Request subject
 *
 * @private
 * @param {object} opts CSR subject options
 * @returns {string} CSR subject
 */

function createCsrSubject(opts: CsrSubjectOptions): string {
  const data = {
    C: opts.country,
    ST: opts.state,
    L: opts.locality,
    O: opts.organization,
    OU: opts.organizationUnit,
    CN: opts.commonName || "localhost",
    emailAddress: opts.emailAddress
  };

  return Object.entries(data).map(([key, value]) => {
    value = (value || "").replace(/[^\w .*,@'-]+/g, " ").trim();
    return value ? `/${key}=${value}` : "";
  }).join("");
}

export interface CsrData extends CsrSubjectOptions {
  keySize?: number;
  altNames?: string[];
}


/**
 * Create a Certificate Signing Request
 *
 * @param {object} data
 * @param {number} [data.keySize] Size of newly created private key, default: `2048`
 * @param {string} [data.commonName] default: `localhost`
 * @param {array} [data.altNames] default: `[]`
 * @param {string} [data.country]
 * @param {string} [data.state]
 * @param {string} [data.locality]
 * @param {string} [data.organization]
 * @param {string} [data.organizationUnit]
 * @param {string} [data.emailAddress]
 * @param {buffer|string} [key] CSR private key
 * @returns {PromiseA<buffer[]>} [privateKey, certificateSigningRequest]
 */

export async function createCsr(data: CsrData, key?: Buffer | string) {
  if (!key) {
    key = await createPrivateKey(data.keySize);
  } else if (!Buffer.isBuffer(key)) {
    key = Buffer.from(key);
  }

  /* Create CSR options */
  const opts: CsrOptions = {
    new: true,
    sha256: true,
    subj: createCsrSubject(data)
  };

  /* Create CSR config for SAN CSR */
  let csrConfig: string = "";

  if (data.altNames && data.altNames.length) {
    opts.extensions = "v3_req";

    const altNames = Object.entries(data.altNames).map(([k, v]) => {
      const i = parseInt(k, 10) + 1;
      const prefix = net.isIP(v) ? "IP" : "DNS";
      return `${prefix}.${i}=${v}`;
    });

    csrConfig = [
      "[req]",
      "req_extensions = v3_req",
      "distinguished_name = req_distinguished_name",
      "[v3_req]",
      "subjectAltName = @alt_names",
      "[alt_names]",
      altNames.join("\n"),
      "[req_distinguished_name]",
      "commonName = Common Name",
      "commonName_max = 64"
    ].join("\n");
  }

  /* Create CSR */
  const csr = await generateCsr(opts, csrConfig, key);

  return [key, csr];
}

/**
 * Convert PEM to DER encoding
 * DEPRECATED - DO NOT USE
 *
 * @param {buffer|string} key PEM encoded private key, certificate or CSR
 * @returns {PromiseA<buffer>} DER
 */

export function pem2der(key) {
  if (!Buffer.isBuffer(key)) {
    key = Buffer.from(key);
  }

  const action = getAction(key);
  const opts: any = { outform: "der" };

  if (isPublic(key)) {
    opts.pubin = true;
  }

  return openssl(action, key, opts);
}

/**
 * Convert DER to PEM encoding
 * DEPRECATED - DO NOT USE
 *
 * @param {string} action Output action (x509, rsa, req)
 * @param {buffer|string} key DER encoded private key, certificate or CSR
 * @param {boolean} [pubIn] Result should be a public key, default: `false`
 * @returns {PromiseA<buffer>} PEM
 */

export function der2pem(action, key, pubIn = false) {
  if (!Buffer.isBuffer(key)) {
    key = Buffer.from(key);
  }

  const opts: any = { inform: "der" };

  if (pubIn) {
    opts.pubin = true;
  }

  return openssl(action, key, opts);
}
