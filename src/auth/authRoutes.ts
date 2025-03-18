import { Router } from 'express';
import { login, logout, getSession } from './authController';
import rateLimit from 'express-rate-limit';
import { authenticate } from '../middleware/authMiddleware';

const router = Router();

// Rate limiting for login attempts
const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 5, // 5 attempts per window
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    message: 'Too many login attempts, please try again later',
    code: 'RATE_LIMIT_EXCEEDED'
  }
});

// Auth routes
router.post('/login', loginLimiter, login);
router.post('/logout', logout);
router.get('/session', authenticate, getSession);

export default router; 