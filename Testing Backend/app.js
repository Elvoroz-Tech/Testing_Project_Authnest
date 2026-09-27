require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const AuthNestClient = require('@elvoroz/authnest-server');
const cookieParser = require('cookie-parser');
const { createSessionRouter } = require('./authnestSession');

const app = express();
const authnest = new AuthNestClient();

app.use(AuthNestClient.getSecurityMiddlewares());
app.use(cookieParser());
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => { console.error(err); process.exit(1); });

app.get('/health', (req, res) => res.json({ status: 'ok' }));

// Session handling for the newer AuthNest (1-hour access tokens + rotating 30-day refresh tokens).
// Mounted BEFORE the SDK router so these handlers win for the routes named in `exclude` below.
// See authnestSession.js for what each route does and why.
app.use('/api/authnest', createSessionRouter(authnest));

// Everything else (login/registration/profile links, callbacks, modal sessions…) is the stock SDK
// router. getUserData, logout, logout-all and portal are replaced by authnestSession.js.
app.use('/api/authnest', authnest.getRouter({ exclude: ['getUserData', 'logout', 'logoutAll', 'portal'] }));

const PORT = process.env.PORT || 9000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

module.exports = app;
