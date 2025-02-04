const { assert } = require('chai');
const puppeteer = require('puppeteer');
const provider = require('./fixture/oidc-provider');
const {
  baseUrl,
  start,
  runExample,
  stubEnv,
  checkContext,
  goto,
  login,
  logout,
} = require('./fixture/helpers');
const { JWT, JWK } = require('jose');
const { publicJWK } = require('./fixture/jwk');
const { apiUrl } = require('./fixture/helpers');

describe('dpop login and logout', async () => {
  let authServer;
  let appServer;

  beforeEach(async () => {
    stubEnv();
    authServer = await start(provider, 3001);
    appServer = await runExample('dpop');
  });

  afterEach(async () => {
    authServer.close();
    appServer.close();
  });

  it('should login and logout with dpop', async () => {
    const browser = await puppeteer.launch({
      args: puppeteer
        .defaultArgs()
        .concat(['--no-sandbox', '--disable-setuid-sandbox']),
    });
    const page = await browser.newPage();
    await goto(baseUrl, page);
    assert.match(
      page.url(),
      /http:\/\/localhost:3001\/interaction/,
      'User should have been redirected to the auth server to login'
    );
    await login('username', 'password', page);
    assert.equal(
      page.url(),
      `${baseUrl}/`,
      'User is returned to the original page'
    );
    const loggedInCookies = await page.cookies('http://localhost:3000');
    assert.ok(
      loggedInCookies.find(
        ({ name }) => name === 'appSession' || name === 'appSession.0'
      )
    );

    const response = await checkContext(await page.cookies(), true);
    assert.isOk(response.isAuthenticated);
    assert.equal(response.userInfo.sub, 'username');
    assert.equal(response.user.sub, 'username');
    assert.equal(response.dpop, true);
    assert.isDefined(response.dpopProof);
    assert.equal(response.accessToken.token_type, 'DPoP');

    assert.exists(response.refreshedAccessToken, 'Should be access token');

    assert.notEqual(
      response.refreshedAccessToken.access_token,
      response.accessToken.access_token,
      'Should not be the same access token'
    );

    const { payload, key } = JWT.verify(response.dpopProof, JWK.EmbeddedJWK, {
      complete: true,
      typ: 'dpop+jwt',
    });

    const jwtToken = JWT.verify(
      response.refreshedAccessToken.access_token,
      JWK.asKey(publicJWK)
    );

    assert.equal(jwtToken.cnf.jkt, key.kid);
    assert.equal(payload.htu, apiUrl);
    assert.equal(payload.htm, 'GET');

    await logout(page);

    const loggedOutCookies = await page.cookies('http://localhost:3000');
    assert.notOk(loggedOutCookies.find(({ name }) => name === 'appSession.1'));
    assert.notOk(loggedOutCookies.find(({ name }) => name === 'appSession.0'));
  });
});
