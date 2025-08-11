import express from 'express';
import axios from 'axios';
import crypto from 'crypto';

const app = express();
app.use(express.json({
  verify: (req, res, buf) => { req.rawBody = buf; }
}));

const {
  FB_PAGE_ACCESS_TOKEN,
  FB_VERIFY_TOKEN,
  FB_APP_SECRET,
  FLOWISE_URL,
  FLOWISE_FLOW_ID,
  FLOWISE_API_KEY
} = process.env;

function verifyFbSignature(req) {
  const signature = req.headers['x-hub-signature-256'];
  if (!signature) return false;
  const [algo, hash] = signature.split('=');
  const hmac = crypto.createHmac('sha256', FB_APP_SECRET)
                     .update(req.rawBody)
                     .digest('hex');
  return hmac === hash;
}

app.get('/webhook', (req, res) => {
  if (req.query['hub.mode'] === 'subscribe' &&
      req.query['hub.verify_token'] === FB_VERIFY_TOKEN) {
    return res.status(200).send(req.query['hub.challenge']);
  }
  res.sendStatus(403);
});

app.post('/webhook', async (req, res) => {
  res.sendStatus(200);
  if (!verifyFbSignature(req)) return;

  const body = req.body;
  if (body.object !== 'page') return;

  for (const entry of body.entry) {
    for (const event of entry.messaging) {
      const senderId = event.sender?.id;
      if (event.message && !event.message.is_echo) {
        const userText = event.message.text || '';

        try {
          const resp = await axios.post(
            `${FLOWISE_URL}/api/v1/prediction/${FLOWISE_FLOW_ID}`,
            { question: userText, overrideConfig: { sessionId: senderId } },
            {
              headers: {
                'Content-Type': 'application/json',
                ...(FLOWISE_API_KEY ? { Authorization: `Bearer ${FLOWISE_API_KEY}` } : {})
              }
            }
          );
          const replyText = resp.data?.text || 'Không có phản hồi';
          await sendToMessenger(senderId, replyText);
        } catch (e) {
          await sendToMessenger(senderId, 'Xin lỗi, tôi không xử lý được yêu cầu.');
        }
      }
    }
  }
});

async function sendToMessenger(psid, text) {
  await axios.post(
    `https://graph.facebook.com/v17.0/me/messages?access_token=${FB_PAGE_ACCESS_TOKEN}`,
    { recipient: { id: psid }, message: { text } }
  );
}

app.listen(10000, () => console.log('Server running on port 10000'));

