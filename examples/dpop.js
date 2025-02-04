const express = require('express');
const { auth } = require('../');

const app = express();

app.use(
  auth({
    idpLogout: true,
    dpop: true,
    authorizationParams: {
      scope: 'openid profile',
      response_type: 'code',
    },
  })
);

app.get('/', (req, res) => {
  res.send(`hello ${req.oidc.user.sub}`);
});

app.get('/refresh', async (req, res) => {
  const { isExpired, refresh } = req.oidc.accessToken || {};

  if (typeof isExpired !== 'function') {
    throw new HttpException(HttpStatusCode.NOT_FOUND, 'Auth Session not found');
  }

  if (!refresh) {
    throw new HttpException(HttpStatusCode.NOT_FOUND, 'Refresh  not found');
  }
  await refresh();
  res.send(`hello ${req.oidc.user.sub}`);
});

module.exports = app;
