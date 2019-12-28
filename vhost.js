const fastify = require('fastify');
const path = require('path');
const vhost = require('fastify-vhost');
const fs = require('fs');

const server = require('fastify')({
  logger: true,
  https: {
    key: fs.readFileSync('/etc/letsencrypt/live/itschris.dev/privkey.pem'),
    cert: fs.readFileSync('/etc/letsencrypt/live/itschris.dev/fullchain.pem'),
    ca: fs.readFileSync('/etc/letsencrypt/live/itschris.dev/chain.pem')
  }
});

server.register(vhost, {
  upstream: 'https://localhost:3443',
  host: 'api.itschris.dev',
});

server.register(require('fastify-static'), {
  root: path.join(__dirname, 'dist', 'static'),
  prefix: '/static',
});

server.all('/*', (request, reply) => {
  fs.readFile(path.join(__dirname, 'dist', 'index.html'), 'utf-8', (err, content) => {
    if (err) console.log("Error opening");
    reply.header('Content-Type', 'text/html; charset=utf-8');
    reply.send(content);
  });
});

const redirect = require('fastify')({
  logger: true,
});


redirect.all('/*', (req, res) => {
  res.redirect(`https://${req.hostname}${req.req.url}`);
});

redirect.listen(80, '67.205.140.63');
server.listen(443, '67.205.140.63');

