/**
 * ACME tests
 */
import "./setup";
import { assert } from "chai";
import PromiseA = require("bluebird");
import { AcmeAccount, AcmeAuthorization, Client, directory, forge } from "../src";

describe("client", function() {
  this.timeout(60000);

  const testDomain = "example.com";
  const testDomainWildcard = `*.${testDomain}`;

  let testClient: Client;
  let testPrivateKey: Buffer;

  before(async () => {
    testPrivateKey = await forge.createPrivateKey();
    testClient = new Client({
      directoryUrl: directory.letsencrypt.staging,
      accountKey: testPrivateKey
    });
  });


  describe("create account", () => {
    it("should produce a valid JWK", async () => {
      const jwk = await testClient.http.getJwk();
      assert.isObject(jwk);
      assert.strictEqual(jwk.e, "AQAB");
      assert.strictEqual(jwk.kty, "RSA");
    });

    it("should get Terms of Service URL", async () => {
      const tos = await testClient.getTermsOfServiceUrl();
      assert.isString(tos);
    });

    it("should refuse account creation without ToS", async () => {
      await assert.isRejected(testClient.createAccount());
    });

    it("should create an account", async () => {
      const account = await testClient.createAccount({
        termsOfServiceAgreed: true
      });

      assert.isObject(account);
      assert.strictEqual(account.status, "valid");
    });
  });

  describe("find or edit account", () => {

    let testSecondaryPrivateKey: Buffer;
    let testAccount: AcmeAccount;

    before(async () => {
      testSecondaryPrivateKey = await forge.createPrivateKey();
      testAccount = await testClient.createAccount({
        termsOfServiceAgreed: true,
        contact: ["mailto:nacme@outlook.com"]
      });
    });


    it("should produce an account URL", () => {
      const accountUrl = testClient.getAccountUrl();
      assert.isString(accountUrl);
    });

    /**
     * Find existing account using secondary client
     */

    it("should find existing account using account key", async () => {
      const client = new Client({
        directoryUrl: directory.letsencrypt.staging,
        accountKey: testPrivateKey
      });

      const account = await client.createAccount({
        termsOfServiceAgreed: true
      });

      assert.isObject(account);
      assert.strictEqual(account.status, "valid");
      assert.strictEqual(testAccount.id, account.id);
    });


    /**
     * Account URL
     */

    it("should refuse invalid account URL", async () => {
      const client = new Client({
        directoryUrl: directory.letsencrypt.staging,
        accountKey: testPrivateKey,
        accountUrl: "https://acme-staging-v02.api.letsencrypt.org/acme/acct/1"
      });

      await assert.isRejected(client.updateAccount());
    });

    it("should find existing account using account URL", async () => {
      const client = new Client({
        directoryUrl: directory.letsencrypt.staging,
        accountKey: testPrivateKey,
        accountUrl: testClient.getAccountUrl()
      });

      const account = await client.createAccount();

      assert.isObject(account);
      assert.strictEqual(account.status, "valid");
      assert.strictEqual(testAccount.id, account.id);
    });

    it("should retrieve account using private key", async () => {
      const client = new Client({
        directoryUrl: directory.letsencrypt.staging,
        accountKey: testPrivateKey,
      });

      const account = await client.retrieveAccount();
      assert.isObject(account);
      assert.strictEqual(account.status, "valid");
      assert.strictEqual(testAccount.id, account.id);
      assert.sameMembers(testAccount.contact, account.contact);
    });

    /**
     * Update account contact info
     */
    it("should update account contact info", async () => {
      const account = await testClient.updateAccount({});

      assert.isObject(account);
      assert.strictEqual(account.status, "valid");
      assert.strictEqual(testAccount.id, account.id);
      assert.sameMembers(testAccount.contact, account.contact);
    });

    /**
     * Change account private key
     */

    it("should change account private key", async () => {
      const account = await testClient.updateAccountKey(testSecondaryPrivateKey);
      assert.isObject(account);
      assert.strictEqual(account.status, "valid");
    });

  });

  describe("authorization", () => {
    let account: AcmeAccount;

    before(async () => {
      account = await testClient.createAccount({
        termsOfServiceAgreed: true
      });
    });

    /**
     * Create new certificate order
     */
    it("should create new order", async () => {
      const data1 = { identifiers: [{ type: "dns", value: testDomain }] };
      const data2 = { identifiers: [{ type: "dns", value: testDomainWildcard }] };

      const testOrder = await testClient.createOrder(data1);
      const testOrderWildcard = await testClient.createOrder(data2);

      [testOrder, testOrderWildcard].forEach((item) => {
        assert.isObject(item);
        assert.strictEqual(item.status, "pending");

        assert.isArray(item.identifiers);
        assert.isArray(item.authorizations);

        assert.isString(item.url);
        assert.isString(item.finalize);
      });
    });


    it("should work", async () => {
      /**
       * Get identifier authorization
       */
      const data1 = { identifiers: [{ type: "dns", value: testDomain }] };
      const data2 = { identifiers: [{ type: "dns", value: testDomainWildcard }] };

      const testOrder = await testClient.createOrder(data1);
      const testOrderWildcard = await testClient.createOrder(data2);

      const authzArr1 = await testClient.getAuthorizations(testOrder);
      const authzArr2 = await testClient.getAuthorizations(testOrderWildcard);

      [authzArr1, authzArr2].forEach((item) => {
        assert.isArray(item);
        assert.isNotEmpty(item);
      });

      const testAuthz = <AcmeAuthorization>authzArr1.pop();
      const testAuthzWildcard = <AcmeAuthorization>authzArr2.pop();

      [testAuthz, testAuthzWildcard].forEach((item) => {
        assert.isObject(item);
        assert.strictEqual(item.status, "pending");

        assert.isString(item.url);
        assert.isArray(item.challenges);
      });

      const testChallenges = testAuthz.challenges.concat(testAuthzWildcard.challenges);

      testChallenges.forEach((item) => {
        assert.isObject(item);
        assert.strictEqual(item.status, "pending");
        assert.isString(item.url);
      });

      /**
       * Generate challenge key authorization
       */
      await PromiseA.map(testChallenges, async (item) => {
        const keyAuth = await testClient.getChallengeKeyAuthorization(item);
        assert.isString(keyAuth);
      });

      /**
       * Deactivate identifier authorization
       */

      await PromiseA.map([testAuthz, testAuthzWildcard], async (item) => {
        const authz = await testClient.deactivateAuthorization(item);
        assert.strictEqual(authz.status, "deactivated");
      });

      /**
       * Deactivate account
       */

      const account = await testClient.updateAccount({ status: "deactivated" });

      assert.isObject(account);
      assert.strictEqual(account.status, "deactivated");

      /**
       * Verify that no new orders can be made
       */
      await assert.isRejected(testClient.createOrder({ identifiers: [{ type: "dns", value: "nope.com" }] }));
    });
  });

});
