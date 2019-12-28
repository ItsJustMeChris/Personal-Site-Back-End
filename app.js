const Sequelize = require('sequelize');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const fs = require('fs');
const Moniker = require('moniker');
const path = require('path');
const fileUpload = require('fastify-file-upload');
const sanitizeHtml = require('sanitize-html');
const fastify = require('fastify')({
  logger: true,
  https: {
    key: fs.readFileSync('/etc/letsencrypt/live/itschris.dev/privkey.pem'),
    cert: fs.readFileSync('/etc/letsencrypt/live/itschris.dev/fullchain.pem'),
    ca: fs.readFileSync('/etc/letsencrypt/live/itschris.dev/chain.pem')
  }
});

fastify.register(fileUpload)

const names = Moniker.generator([Moniker.adjective, Moniker.noun, Moniker.adjective]);

const sequelize = new Sequelize(`postgres://${process.env.DBUSER}:${process.env.DBPASS}@${process.env.DBHOST}:${process.env.DBPORT}/${process.env.DBNAME}`);

class User extends Sequelize.Model { }
User.init({
  id: {
    type: Sequelize.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  username: { type: Sequelize.STRING, unique: true },
  avatar: { type: Sequelize.STRING },
  email: { type: Sequelize.STRING, unique: true },
  password: Sequelize.STRING,
}, { sequelize, modelName: 'user' });

class BlogPost extends Sequelize.Model { }
BlogPost.init({
  title: { type: Sequelize.STRING },
  content: { type: Sequelize.TEXT },
  slug: { type: Sequelize.STRING, unique: true, },
  image: { type: Sequelize.STRING },
}, { sequelize, modelName: 'post' });

class SessionToken extends Sequelize.Model { }
SessionToken.init({
  token: { type: Sequelize.STRING, unique: true },
  ip: { type: Sequelize.STRING },
}, { sequelize, modelName: 'token' });

User.hasMany(BlogPost, { as: 'post' });
BlogPost.belongsTo(User);

User.hasMany(SessionToken, { as: 'token' });
SessionToken.belongsTo(User);

fastify.register(require('fastify-cors'), { origin: '*' });

async function generateToken() {
  try {
    const buffer = await new Promise((resolve, reject) => {
      crypto.randomBytes(256, (ex, buf) => {
        if (ex) {
          reject(ex);
        }
        resolve(buf);
      });
    });
    const token = crypto
      .createHash('sha1')
      .update(buffer)
      .digest('hex');
    return token;
  } catch (ex) {
    return 0;
  }
}

function slugify(string) {
  const a = 'àáäâãåăæąçćčđďèéěėëêęğǵḧìíïîįłḿǹńňñòóöôœøṕŕřßşśšșťțùúüûǘůűūųẃẍÿýźžż·/_,:;'
  const b = 'aaaaaaaaacccddeeeeeeegghiiiiilmnnnnooooooprrsssssttuuuuuuuuuwxyyzzz------'
  const p = new RegExp(a.split('').join('|'), 'g')

  return string.toString().toLowerCase()
    .replace(/\s+/g, '-') // Replace spaces with -
    .replace(p, c => b.charAt(a.indexOf(c))) // Replace special characters
    .replace(/&/g, '-and-') // Replace & with 'and'
    .replace(/[^\w\-]+/g, '') // Remove all non-word characters
    .replace(/\-\-+/g, '-') // Replace multiple - with single -
    .replace(/^-+/, '') // Trim - from start of text
    .replace(/-+$/, '') // Trim - from end of text
}

/*
  POST
  @username
  @password
  >token
*/
fastify.post('/api/v1/auth/login', async (req, res) => {
  res.type('application/json').code(200);
  const { username, password } = req.body;
  try {
    const user = await User.findOne({
      where: { username },
    });
    if (user) {
      const auth = await bcrypt.compare(password, user.password);
      if (!auth) return { status: 'error', message: 'Invalid Password' };
      let transaction;
      try {
        transaction = await sequelize.transaction();
        await SessionToken.sync();
        const token = await generateToken();
        if (token === 0) return { status: 'error', message: 'An Error Happens' };
        const { ip } = req;
        const userSession = await SessionToken.create({
          token,
          ip,
        }, { transaction });
        await transaction.commit();
        user.addToken(userSession);
        return { status: 'success', message: 'Logged In', token };
      } catch (error) {
        fastify.log.error(error);
        await transaction.rollback();
        return { status: 'error', message: 'An Error Happens' };
      }
    }
  } catch (error) {
    return { status: 'error', message: 'An Error Happens' };
  }
});

/*
  POST
  @token
  >true/false
*/
fastify.post('/api/v1/auth/verify', async (req, res) => {
  res.type('application/json').code(200);
  const { token } = req.body;

  const session = await SessionToken.findOne({
    where: { token },
  });
  if (session) {
    return { auth: true };
  }
  return { auth: false };
});

/*
  POST
  @token
  >[usersSessionTokens]
*/
fastify.post('/api/v1/auth/sessions', async (req, res) => {
  res.type('application/json').code(200);
  const { token } = req.body;
  try {
    const session = await SessionToken.findOne({
      where: { token },
    });
    if (session) {
      const allTokens = await SessionToken.findAll({ where: { userId: session.userId } });
      return allTokens.map(e => ({ ip: e.ip, token: e.token, created: e.createdAt }));
    }
  } catch (error) {
    return { status: 'error', message: 'An Error Happens' };
  }
  return { status: 'error', message: 'An Error Happens' };
});

/*
  POST
  @token
  >{success}
*/
fastify.post('/api/v1/auth/logout', async (req, res) => {
  res.type('application/json').code(200);
  const { token } = req.body;
  try {
    const session = await SessionToken.findOne({
      where: { token },
    });
    if (session) {
      session.destroy();
      return { status: 'success', message: 'Logged Out' };
    }
  } catch (error) {
    return { status: 'error', message: 'An Error Happens' };
  }
  return { status: 'error', message: 'An Error Happens' };
});

/*
  POST
  @token
  >{success}
*/
fastify.post('/api/v1/blog/new', async (req, res) => {
  res.type('application/json').code(200);
  const { token, title, content, image } = req.body;
  const cleanContent = sanitizeHtml(content, {
    allowedTags: ['h2', 'h1', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'p', 'a', 'ul', 'ol',
      'nl', 'li', 'b', 'i', 'strong', 'em', 'strike', 'code', 'hr', 'br', 'div',
      'table', 'thead', 'caption', 'tbody', 'tr', 'th', 'td', 'pre', 'iframe', 'img'],
  });
  try {
    const session = await SessionToken.findOne({
      where: { token },
    });
    if (session) {
      try {
        const { userId } = session;
        const user = await User.findOne({ where: { id: userId } });
        let transaction;
        try {
          transaction = await sequelize.transaction();
          await BlogPost.sync();
          const slug = slugify(title);
          const post = await BlogPost.create({
            title, content: cleanContent, slug, image,
          }, { transaction });
          await transaction.commit();
          user.addPost(post);
          return { status: 'success', message: 'Post Created' };
        } catch (error) {
          fastify.log.error(error);
          await transaction.rollback();
          return { status: 'error', message: '4' };
        }
      } catch (error) {
        return { status: 'error', message: '3' };
      }
    }
  } catch (error) {
    return { status: 'error', message: '2' };
  }
  return { status: 'error', message: '1' };
});

/*
  GET
  @page
  >{success}
*/
fastify.get('/api/v1/blog/paginate/:page', async (req, res) => {
  res.type('application/json').code(200);
  const { page } = req.params;
  try {
    const posts = await BlogPost.findAll({
      limit: 50,
      offset: 50 * page,
      order: [['updatedAt', 'DESC']],
      include: [User],
    });
    console.log(posts);
    return posts.map(e => ({ title: e.title, image: e.image, slug: e.slug, content: e.content, postTime: e.createdAt, author: e.user.username }));
  } catch (error) {
    return { status: 'error', message: '2' };
  }
});

/*
  GET
  @slug
  >{success}
*/
fastify.get('/api/v1/blog/post/:slug', async (req, res) => {
  res.type('application/json').code(200);
  const { slug } = req.params;
  try {
    const post = await BlogPost.findOne({
      where: { slug },
      include: [User],
    });
    const { title, image, content, createdAt, user: { username } } = post;
    return { title, image, content, createdAt, username };
  } catch (error) {
    return { status: 'error', message: '2' };
  }
});

/*
  POST
  @username
  @password
  @email
  >token
*/
fastify.post('/api/v1/auth/register', async (req, res) => {
  res.type('application/json').code(200);
  const {
    username,
    password,
    email,
    avatar,
  } = req.body;

  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(password, salt);

  let transaction;
  try {
    // get transaction
    transaction = await sequelize.transaction();
    await User.sync();
    const user = await User.create({
      username, password: hash, email, avatar,
    }, { transaction });
    try {
      await SessionToken.sync();
      const token = await generateToken();
      const { ip } = req;
      const userSession = await SessionToken.create({
        token,
        ip,
      }, { transaction });
      await transaction.commit();
      user.addToken(userSession);
      return { status: 'success', message: 'User Created', token };
    } catch (error) {
      fastify.log.error(error);
      await transaction.rollback();
      return { status: 'error', message: 'An Error Happens' };
    }
  } catch (err) {
    if (err) {
      fastify.log.error(err);
      await transaction.rollback();
      return { status: 'error', message: 'An Error Happens' };
    }
  }
  return { status: 'error', message: 'An Error Happens' };
});

fastify.post('/api/v1/upload', async function (req, res) {
  res.type('application/json').code(200);
  const { token } = req.raw.body;
  try {
    const session = await SessionToken.findOne({
      where: { token },
    });
    if (session) {
      const { file } = req.raw.files;
      const name = `${names.choose()}${path.extname(file.name)}`;
      fs.open(path.join('public', 'images', name), 'wx', (err) => {
        if (err) {
          if (err.code === 'EEXIST') {
            console.log('error');
            return { status: 'error', message: 'Error uploading file.' };
          }
          console.log('error');
          return { status: 'error', message: 'Error uploading file.' };
        }
        fs.writeFile(path.join('public', 'images', name), file.data, (err) => {
          if (err) return { status: 'error', message: 'Error uploading file.' };
          return { status: 'success', message: 'File uploaded successfully.' };
        });
      });
      return { status: 'success', message: 'File uploaded successfully.', url: `https://${req.hostname}/public/images/${name}` };
    }
  } catch (err) {
    return { status: 'error', message: '2' };
  }
  return { status: 'error', message: '1' };
});

fastify.register(require('fastify-static'), {
  root: path.join(__dirname, 'public'),
  prefix: '/public/',
});

fastify.listen(3443, '0.0.0.0', (err, address) => {
  if (err) throw err;
  fastify.log.info(`server listening on ${address}`);
});