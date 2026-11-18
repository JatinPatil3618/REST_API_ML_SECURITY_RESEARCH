const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { app } = require('../server');

const PRIVATE_FIELDS = ['title', 'author', 'description', 'rating', 'date', 'owner'];

function request(base, method, path, { token, headers, body } = {}) {
  const url = new URL(path, base);
  const payload = body === undefined ? null : JSON.stringify(body);
  const reqHeaders = { ...(headers || {}) };
  if (token !== undefined) {
    reqHeaders.Authorization = `Bearer ${token}`;
  }
  if (payload !== null) {
    reqHeaders['Content-Type'] = 'application/json';
  }
  return new Promise((resolve, reject) => {
    const req = http.request(url, { method, headers: reqHeaders }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        let parsed = {};
        if (raw) {
          parsed = JSON.parse(raw);
        }
        resolve({ status: res.statusCode, body: parsed });
      });
    });
    req.on('error', reject);
    if (payload !== null) {
      req.write(payload);
    }
    req.end();
  });
}

describe('GET /api/books/:id management view', () => {
  let server;
  let base;
  let ownerToken;
  let otherToken;
  let bookId;

  before(async () => {
    server = app.listen(0);
    await new Promise((resolve) => server.once('listening', resolve));
    const address = server.address();
    base = `http://127.0.0.1:${address.port}`;

    const ownerLogin = await request(base, 'POST', '/api/auth/login', {
      body: { username: 'user01', password: 'Password123!' }
    });
    const otherLogin = await request(base, 'POST', '/api/auth/login', {
      body: { username: 'user02', password: 'Password123!' }
    });
    assert.equal(ownerLogin.status, 200);
    assert.equal(otherLogin.status, 200);
    ownerToken = ownerLogin.body.token;
    otherToken = otherLogin.body.token;

    const created = await request(base, 'POST', '/api/books', {
      token: ownerToken,
      body: {
        title: 'BOLA management probe',
        author: 'Probe',
        category: 'Technology',
        description: 'temporary management-view probe'
      }
    });
    assert.equal(created.status, 201);
    assert.equal(created.body.owner, 'user01');
    bookId = created.body.id;
  });

  after(async () => {
    if (bookId && ownerToken) {
      await request(base, 'DELETE', `/api/books/${bookId}`, { token: ownerToken });
    }
    if (server) {
      await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
    }
  });

  it('returns the public catalog record without credentials', async () => {
    const response = await request(base, 'GET', `/api/books/${bookId}`);
    assert.equal(response.status, 200);
    assert.equal(response.body.title, 'BOLA management probe');
    assert.equal(response.body.owner, 'user01');
  });

  it('lets the owner open the management view', async () => {
    const response = await request(base, 'GET', `/api/books/${bookId}?view=manage`, { token: ownerToken });
    assert.equal(response.status, 200);
    assert.equal(response.body.owner, 'user01');
    assert.equal(response.body.title, 'BOLA management probe');
    assert.equal(response.body.description, 'temporary management-view probe');
  });

  it('denies another authenticated user without the book record', async () => {
    const response = await request(base, 'GET', `/api/books/${bookId}?view=manage`, { token: otherToken });
    assert.equal(response.status, 403);
    assert.equal(response.body.code, 'BOLA_AUTHORIZATION_DENIED');
    assert.equal(response.body.bookId, bookId);
    for (const field of PRIVATE_FIELDS) {
      assert.equal(Object.hasOwn(response.body, field), false);
    }
  });

  it('rejects a management view with no token', async () => {
    const response = await request(base, 'GET', `/api/books/${bookId}?view=manage`);
    assert.equal(response.status, 401);
    assert.equal(response.body.error, 'Authentication required. Please log in.');
    for (const field of PRIVATE_FIELDS) {
      assert.equal(Object.hasOwn(response.body, field), false);
    }
  });

  it('rejects access=edit with no token', async () => {
    const response = await request(base, 'GET', `/api/books/${bookId}?access=edit`);
    assert.equal(response.status, 401);
    assert.equal(response.body.error, 'Authentication required. Please log in.');
  });

  it('rejects an invalid token', async () => {
    const response = await request(base, 'GET', `/api/books/${bookId}?view=manage`, { token: 'not-a-jwt' });
    assert.equal(response.status, 403);
    assert.equal(response.body.error, 'Session invalid or expired. Reauthentication required.');
    for (const field of PRIVATE_FIELDS) {
      assert.equal(Object.hasOwn(response.body, field), false);
    }
  });

  it('ignores X-Authenticated-User as an identity', async () => {
    const response = await request(base, 'GET', `/api/books/${bookId}?view=manage`, {
      headers: { 'X-Authenticated-User': 'user01' }
    });
    assert.equal(response.status, 401);
    assert.equal(response.body.error, 'Authentication required. Please log in.');
    assert.equal(Object.hasOwn(response.body, 'title'), false);
    assert.equal(Object.hasOwn(response.body, 'description'), false);
  });
});
