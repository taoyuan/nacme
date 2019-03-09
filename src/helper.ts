/**
 * Utility methods
 */

import PromiseA = require("bluebird");
import Backoff = require("backo2");

const debug = require("debug")("nacme");


/**
 * Retry promise
 *
 * @param {function} fn Function returning promise that should be retried
 * @param {number} attempts Maximum number of attempts
 * @param {Backoff} backoff Backoff instance
 * @returns {PromiseA}
 */

async function retryPromise(fn, attempts, backoff) {
  let aborted = false;

  try {
    return await fn(() => aborted = true);
  } catch (e) {
    if (aborted || ((backoff.attempts + 1) >= attempts)) {
      throw e;
    }

    const duration = backoff.duration();
    debug(`PromiseA rejected attempt #${backoff.attempts}, retrying in ${duration}ms: ${e.message}`);

    await PromiseA.delay(duration);
    return retryPromise(fn, attempts, backoff);
  }
}


/**
 * Retry promise
 *
 * @param {function} fn Function returning promise that should be retried
 * @param {object} [backoffOpts] Backoff options
 * @param {number} [backoffOpts.attempts] Maximum number of attempts, default: `5`
 * @param {number} [backoffOpts.min] Minimum attempt delay in milliseconds, default: `5000`
 * @param {number} [backoffOpts.max] Maximum attempt delay in milliseconds, default: `30000`
 * @returns {PromiseA}
 */

export function retry(fn, { attempts = 5, min = 5000, max = 30000 } = {}) {
  const backoff = new Backoff({ min, max });
  return retryPromise(fn, attempts, backoff);
}


/**
 * Escape base64 encoded string
 *
 * @param {string} str Base64 encoded string
 * @returns {string} Escaped string
 */

export function b64escape(str: string): string {
  return str.replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}


/**
 * Base64 encode and escape buffer or string
 *
 * @param {buffer|string} str Buffer or string to be encoded
 * @returns {string} Escaped base64 encoded string
 */

export function b64encode(str: string | Buffer): string {
  const buf = Buffer.isBuffer(str) ? str : Buffer.from(str);
  return b64escape(buf.toString("base64"));
}


/**
 * Parse PEM body from buffer or string
 *
 * @param {buffer|string} str PEM encoded buffer or string
 * @returns {string} PEM body
 */

export function getPemBody(str: string | Buffer): string {
  const pemStr = Buffer.isBuffer(str) ? str.toString() : str;
  return pemStr.replace(/(\s*-----(BEGIN|END) ([A-Z0-9- ]+)-----|\r|\n)*/g, "");
}


/**
 * Find and format error in response object
 *
 * @param {object} resp HTTP response
 * @returns {string} Error message
 */

export function formatResponseError(resp): string {
  let result: string;

  if (resp.data.error) {
    result = resp.data.error.detail || resp.data.error;
  } else {
    result = resp.data.detail || JSON.stringify(resp.data);
  }

  return result.replace(/\n/g, "");
}

