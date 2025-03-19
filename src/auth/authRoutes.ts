import { Router } from 'express';
import { login, logout, getSession, refreshToken } from './authController';
import { register, resendConfirmation } from './registerController';
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

// Rate limiting for refresh token attempts
const refreshLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts per window (reduced from 20)
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    message: 'Too many refresh attempts, please try again later',
    code: 'RATE_LIMIT_EXCEEDED'
  }
});

// Stricter rate limiting for session endpoint
const sessionLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 30, // 30 attempts per window
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    message: 'Too many session requests, please try again later',
    code: 'RATE_LIMIT_EXCEEDED'
  }
});

// Rate limiting for registration attempts
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 attempts per window
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    message: 'Too many registration attempts, please try again later',
    code: 'RATE_LIMIT_EXCEEDED'
  }
});

// Auth routes
router.post('/login', loginLimiter, login);
router.post('/logout', logout);
router.get('/session', sessionLimiter, authenticate, getSession);
router.post('/refresh', refreshLimiter, refreshToken);
router.post('/register', registerLimiter, register);
router.post('/resend-confirmation', registerLimiter, resendConfirmation);

export default router; 