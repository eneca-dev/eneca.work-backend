import { Router } from 'express';
import { getProfile, updateProfile, getReferences } from '../controllers/profileController';
import { authenticate } from '../middleware/authMiddleware';
import rateLimit from 'express-rate-limit';

const router = Router();

// Ограничение запросов для API профиля
const profileLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 минут
  max: 60, // 60 запросов за 15 минут
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    message: 'Слишком много запросов, пожалуйста, попробуйте позже',
    code: 'RATE_LIMIT_EXCEEDED'
  }
});

// Маршрут для получения профиля
router.get('/profile', authenticate, profileLimiter, getProfile);

// Маршрут для обновления профиля
router.put('/profile', authenticate, profileLimiter, updateProfile);

// Маршрут для получения справочных данных
router.get('/references/:type', authenticate, profileLimiter, getReferences);

export default router; 