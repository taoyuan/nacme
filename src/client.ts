/**
 * ACME client
 *
 * @namespace Client
 */

import crypto = require("crypto");
import PromiseA = require("bluebird");
import { HttpClient, HttpClientOptions } from "./http";
import { AcmeApi } from "./api";
import verify = require("./verify");
import helper = require("./helper");
import { auto } from "./auto";
import { AcmeAuthorization, AcmeChallenge, AcmeIdentifier, AcmeOrder } from "./types";

const debug = require("debug")("nacme");


export interface ClientOptions {
  directoryUrl: string;
  accountKey: Buffer;
  accountUrl?: string;
  backoffAttempts?: number;
  backoffMin?: number;
  backoffMax?: number;
  http?: HttpClientOptions;
}

export interface ClientSettings {
  directoryUrl: string;
  accountKey: Buffer;
  accountUrl?: string;
  backoffAttempts: number;
  backoffMin: number;
  backoffMax: number;
}

export interface BackoffOpts {
  attempts: number;
  min: number;
  max: number;
}

export interface AccountOptions {
  termsOfServiceAgreed?: boolean;
  contact?: string[];
  [name: string]: any;
}

export interface OrderOptions {
  identifiers: AcmeIdentifier[];
  [name: string]: any;
}

/**
 * Default options
 */

const defaultOpts = {
  directoryUrl: undefined,
  accountKey: undefined,
  accountUrl: null,
  backoffAttempts: 5,
  backoffMin: 5000,
  backoffMax: 30000
};


/**
 * AcmeClient
 *
 * @class
 * @param {object} opts
 * @param {string} opts.directoryUrl ACME directory URL
 * @param {buffer|string} opts.accountKey PEM encoded account private key
 * @param {string} [opts.accountUrl] Account URL, default: `null`
 * @param {number} [opts.backoffAttempts] Maximum number of backoff attempts, default: `5`
 * @param {number} [opts.backoffMin] Minimum backoff attempt delay in milliseconds, default: `5000`
 * @param {number} [opts.backoffMax] Maximum backoff attempt delay in milliseconds, default: `30000`
 */

export class Client {

  opts: ClientSettings;
  backoffOpts: BackoffOpts;
  http: HttpClient;
  api: AcmeApi;

  constructor(opts: ClientOptions) {
    if (!Buffer.isBuffer(opts.accountKey)) {
      opts.accountKey = Buffer.from(opts.accountKey);
    }

    this.opts = Object.assign({}, defaultOpts, opts);

    this.backoffOpts = {
      attempts: this.opts.backoffAttempts,
      min: this.opts.backoffMin,
      max: this.opts.backoffMax
    };

    this.http = new HttpClient(this.opts.directoryUrl, this.opts.accountKey, opts.http);
    this.api = new AcmeApi(this.http, this.opts.accountUrl);
  }


  /**
   * Get Terms of Service URL
   *
   * @returns {Promise<string>} ToS URL
   */

  getTermsOfServiceUrl() {
    return this.api.getTermsOfServiceUrl();
  }


  /**
   * Get current account URL
   *
   * @returns {string} Account URL
   */

  getAccountUrl() {
    return this.api.getAccountUrl();
  }


  /**
   * Create a new account
   *
   * https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md#account-creation
   *
   * @param {object} [data] Request data
   * @returns {Promise<object>} Account
   */

  async createAccount(data?: AccountOptions) {
    data = data || {};
    try {
      this.getAccountUrl();

      /* Account URL exists */
      debug("Account URL exists, returning updateAccount()");
      return this.updateAccount(data);
    } catch (e) {
      const resp = await this.api.createAccount(data);

      /* HTTP 200: Account exists */
      if (resp.status === 200) {
        debug("Account already exists (HTTP 200), returning updateAccount()");
        return this.updateAccount(data);
      }

      return resp.data;
    }
  }


  /**
   * Update existing account
   *
   * https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md#account-update
   *
   * @param {object} [data] Request data
   * @returns {Promise<object>} Account
   */

  async updateAccount(data?: AccountOptions) {
    data = data || {};
    try {
      this.api.getAccountUrl();
    } catch (e) {
      debug("No account URL found, returning createAccount()");
      return this.createAccount(data);
    }

    const resp = await this.api.updateAccount(data);
    return resp.data;
  }


  /**
   * Update account private key
   *
   * https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md#account-key-roll-over
   *
   * @param {buffer|string} newAccountKey New PEM encoded private key
   * @param {object} [data] Additional request data
   * @returns {Promise<object>} Account
   */

  async updateAccountKey(newAccountKey, data?: { [name: string]: any }) {
    if (!Buffer.isBuffer(newAccountKey)) {
      newAccountKey = Buffer.from(newAccountKey);
    }

    const accountUrl = this.api.getAccountUrl();

    /* Create new HTTP and API clients using new key */
    const newHttpClient = new HttpClient(this.opts.directoryUrl, newAccountKey);
    const newApiClient = new AcmeApi(newHttpClient, accountUrl);

    data = data || {};
    /* Get new JWK */
    data.account = accountUrl;
    data.oldKey = await this.http.getJwk();

    /* TODO: Backward-compatibility with draft-ietf-acme-12, remove this in a later release */
    data.newKey = await newHttpClient.getJwk();

    /* Get signed request body from new client */
    const url = await newHttpClient.getResourceUrl("keyChange");
    const body = await newHttpClient.createSignedBody(url, data);

    /* Change key using old client */
    const resp = await this.api.updateAccountKey(body);

    /* Replace existing HTTP and API client */
    this.http = newHttpClient;
    this.api = newApiClient;

    return resp.data;
  }


  /**
   * Create a new order
   *
   * https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md#applying-for-certificate-issuance
   *
   * @param {object} data Request data
   * @returns {Promise<AcmeOrder>} Order
   */

  async createOrder(data: OrderOptions): Promise<AcmeOrder> {
    const resp = await this.api.createOrder(data);

    if (!resp.headers.location) {
      throw new Error("Creating a new order did not return an order link");
    }

    /* Add URL to response */
    resp.data.url = resp.headers.location;
    return resp.data;
  }


  /**
   * Finalize order
   *
   * https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md#applying-for-certificate-issuance
   *
   * @param {object} order Order object
   * @param {buffer|string} csr PEM encoded Certificate Signing Request
   * @returns {Promise<object>} Order
   */

  async finalizeOrder(order, csr) {
    if (!order.finalize) {
      throw new Error("Unable to finalize order, URL not found");
    }

    if (!Buffer.isBuffer(csr)) {
      csr = Buffer.from(csr);
    }

    const body = helper.getPemBody(csr);
    const data = { csr: helper.b64escape(body) };

    const resp = await this.api.finalizeOrder(order.finalize, data);
    return resp.data;
  }


  /**
   * Get identifier authorizations from order
   *
   * https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md#identifier-authorization
   *
   * @param {object} order Order
   * @returns {Promise<object[]>} Authorizations
   */

  getAuthorizations(order: AcmeOrder): Promise<AcmeAuthorization[]> {
    // @ts-ignore
    return PromiseA.map((order.authorizations || []), async (url) => {
      const resp = await this.api.getAuthorization(url);

      /* Add URL to response */
      resp.data.url = url;
      return <AcmeAuthorization>resp.data;
    });
  }


  /**
   * Deactivate identifier authorization
   *
   * https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md#deactivating-an-authorization
   *
   * @param {object} authz Identifier authorization
   * @returns {Promise<object>} Authorization
   */

  async deactivateAuthorization(authz: AcmeAuthorization) {
    if (!authz.url) {
      throw new Error("Unable to deactivate identifier authorization, URL not found");
    }

    const data = {
      status: "deactivated"
    };

    const resp = await this.api.updateAuthorization(authz.url, data);
    return resp.data;
  }


  /**
   * Get key authorization for ACME challenge
   *
   * https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md#key-authorizations
   *
   * @param {object} challenge Challenge object returned by API
   * @returns {Promise<string>} Key authorization
   */

  async getChallengeKeyAuthorization(challenge: AcmeChallenge) {
    const jwk = await this.http.getJwk();
    const keysum = crypto.createHash("sha256").update(JSON.stringify(jwk));
    const thumbprint = helper.b64escape(keysum.digest("base64"));
    const result = `${challenge.token}.${thumbprint}`;

    if (challenge.type === "http-01") {
      /**
       * https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md#http-challenge
       */

      return result;
    } else if ((challenge.type === "dns-01") || (challenge.type === "tls-alpn-01")) {
      /**
       * https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md#dns-challenge
       * https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-01
       */

      const shasum = crypto.createHash("sha256").update(result);
      return helper.b64escape(shasum.digest("base64"));
    }

    throw new Error(`Unable to produce key authorization, unknown challenge type: ${challenge.type}`);
  }


  /**
   * Verify that ACME challenge is satisfied
   *
   * @param {object} authz Identifier authorization
   * @param {object} challenge Authorization challenge
   * @returns {Promise}
   */

  async verifyChallenge(authz: AcmeAuthorization, challenge: AcmeChallenge) {
    if (!authz.url || !challenge.url) {
      throw new Error("Unable to verify ACME challenge, URL not found");
    }

    if (typeof verify[challenge.type] === "undefined") {
      throw new Error(`Unable to verify ACME challenge, unknown type: ${challenge.type}`);
    }

    const keyAuthorization = await this.getChallengeKeyAuthorization(challenge);

    const verifyFn = async () => {
      await verify[challenge.type](authz, challenge, keyAuthorization);
    };

    debug("Waiting for ACME challenge verification", this.backoffOpts);
    return helper.retry(verifyFn, this.backoffOpts);
  }


  /**
   * Notify provider that challenge has been completed
   *
   * https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md#responding-to-challenges
   *
   * @param {object} challenge Challenge object returned by API
   * @returns {Promise<object>} Challenge
   */

  async completeChallenge(challenge: AcmeChallenge) {
    const data = {
      keyAuthorization: await this.getChallengeKeyAuthorization(challenge)
    };

    const resp = await this.api.completeChallenge(challenge.url, data);
    return resp.data;
  }


  /**
   * Wait for ACME provider to verify status on a order, authorization or challenge
   *
   * https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md#responding-to-challenges
   *
   * @param {object} item An order, authorization or challenge object
   * @returns {Promise<object>} Valid order, authorization or challenge
   */

  async waitForValidStatus(item: AcmeAuthorization | AcmeChallenge | AcmeOrder) {
    if (!item.url) {
      throw new Error("Unable to verify status of item, URL not found");
    }

    const verifyFn = async (abort) => {
      const resp = await this.api.get(item.url, [200]);

      /* Verify status */
      debug(`Item has status: ${resp.data.status}`);

      if (resp.data.status === "invalid") {
        abort();
        throw new Error(helper.formatResponseError(resp));
      } else if (resp.data.status === "pending") {
        throw new Error("Operation is pending");
      } else if (resp.data.status === "valid") {
        return resp.data;
      }

      throw new Error(`Unexpected item status: ${resp.data.status}`);
    };

    debug(`Waiting for valid status from: ${item.url}`, this.backoffOpts);
    return helper.retry(verifyFn, this.backoffOpts);
  }


  /**
   * Get certificate from ACME order
   *
   * https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md#downloading-the-certificate
   *
   * @param {object} order Order object
   * @returns {Promise<string>} Certificate
   */

  async getCertificate(order: AcmeOrder) {
    if (order.status !== "valid") {
      order = await this.waitForValidStatus(order);
    }

    if (!order.certificate) {
      throw new Error("Unable to download certificate, URL not found");
    }

    const resp = await this.http.request(order.certificate, "get", { responseType: "text" });
    return resp.data;
  }


  /**
   * Revoke certificate
   *
   * https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md#certificate-revocation
   *
   * @param {buffer|string} cert PEM encoded certificate
   * @param {object} [data] Additional request data
   * @returns {Promise}
   */

  async revokeCertificate(cert: string | Buffer, data?: { [name: string]: any }) {
    const body = helper.getPemBody(cert);
    data = data || {};
    data.certificate = helper.b64escape(body);

    const resp = await this.api.revokeCert(data);
    return resp.data;
  }


  /**
   * Auto mode
   *
   * @param {object} opts
   * @param {buffer|string} opts.csr Certificate Signing Request
   * @param {function} opts.challengeCreateFn Function returning Promise triggered before completing ACME challenge
   * @param {function} opts.challengeRemoveFn Function returning Promise triggered after completing ACME challenge
   * @param {string} [opts.email] Account email address
   * @param {boolean} [opts.termsOfServiceAgreed] Agree to Terms of Service, default: `false`
   * @param {string[]} [opts.challengePriority] Array defining challenge type priority, default: `['http-01', 'dns-01']`
   * @returns {Promise<string>} Certificate
   */

  auto(opts) {
    return auto(this, opts);
  }
}
