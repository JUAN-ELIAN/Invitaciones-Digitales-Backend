// minimal-api/index.ts
import express from 'express';
import serverless from 'serverless-http';

const app = express();

app.get('/', (_req, res) => {
  res.json({ message: 'Backend funcionando correctamente' });
});

export default serverless(app);