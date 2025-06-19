const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const SHARED_SECRET = process.env.SHARED_SECRET || 'my_shared_secret';

app.use(bodyParser.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

app.post('/webhook', (req, res) => {
  const signature = req.headers['x-signature'];
  const rawBody = req.rawBody;

  const hmac = crypto.createHmac('sha256', SHARED_SECRET);
  hmac.update(rawBody);
  const expectedSig = 'sha256=' + hmac.digest('hex');

  if (signature !== expectedSig) {
    console.log('❌ Invalid signature');
    return res.status(403).send('Invalid signature');
  }

  console.log('✅ Webhook received and verified!');
  console.log(req.body);

  res.status(200).send('OK');
});

app.listen(PORT, () => {
  console.log(`🚀 Webhook server running on port ${PORT}`);
});
