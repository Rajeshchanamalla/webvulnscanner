import { Router } from 'express';
import { loginController } from '../services/auth/controller.js';
import { verifyToken } from '../middleware/auth.js';

const router = Router();

router.post('/login', loginController);

router.get('/me', verifyToken, (req, res) => {
  const user = (req as any).user;
  res.json({ user });
});

export default router;
