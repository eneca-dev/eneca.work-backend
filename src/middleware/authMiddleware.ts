import { Response, NextFunction } from 'express';
import { AuthenticatedRequest } from '../types/auth';
import supabase from '../utils/supabase';

// Хранилище для отслеживания последних обновлений токенов пользователей
// userId -> timestamp последнего обновления
const lastTokenRefreshMap = new Map<string, number>();
// Уменьшаем минимальный интервал между обновлениями токена (в мс) - 5 минут (было 15)
const MIN_REFRESH_INTERVAL = 5 * 60 * 1000;

/**
 * Middleware to authenticate requests using JWT from cookies
 */
export const authenticate = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    // Get token from cookie
    const token = req.cookies['auth-token'];
    
    if (!token) {
      return res.status(401).json({
        message: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }

    // Verify token with Supabase
    const { data, error } = await supabase.auth.getUser(token);

    if (error || !data.user) {
      // Try to refresh token if refresh-token exists
      const refreshToken = req.cookies['refresh-token'];
      
      if (refreshToken) {
        // Проверяем, не было ли недавних обновлений токена для этого пользователя
        // Для неаутентифицированного пользователя используем refresh token как ключ
        const userId = data?.user?.id || refreshToken.substring(0, 20);  // Используем часть токена как id если нет userId
        const lastRefresh = lastTokenRefreshMap.get(userId) || 0;
        const now = Date.now();
        
        // Проверяем, не слишком ли часто происходят обновления токена
        // Блокируем только если было больше 3 обновлений за последние 5 минут
        const refreshCount = getRefreshCount(userId, now);
        if (refreshCount > 3 && now - lastRefresh < MIN_REFRESH_INTERVAL) {
          console.log(`Rate limiting token refresh for user ${userId} - ${refreshCount} refreshes in last 5 minutes`);
          return res.status(429).json({
            message: 'Too many token refresh attempts. Please try again later.',
            code: 'REFRESH_RATE_LIMITED',
            retryAfter: Math.ceil((MIN_REFRESH_INTERVAL - (now - lastRefresh)) / 1000)
          });
        }
        
        try {
          // Attempt to refresh session using refresh token
          const refreshResult = await supabase.auth.refreshSession({ refresh_token: refreshToken });
          
          if (refreshResult.error || !refreshResult.data.session || !refreshResult.data.user) {
            // If refresh fails, clear cookies and return error
            clearAuthCookies(res);
            
            return res.status(401).json({
              message: 'Session expired. Please login again.',
              code: 'SESSION_EXPIRED'
            });
          }
          
          // Обновляем время последнего обновления токена
          // Убедимся, что refreshResult.data.user существует и имеет id
          if (refreshResult.data.user && refreshResult.data.user.id) {
            recordRefresh(refreshResult.data.user.id, now);
            lastTokenRefreshMap.set(refreshResult.data.user.id, now);
          }
          
          // Set new tokens in cookies с улучшенными настройками
          setAuthCookies(res, refreshResult.data.session.access_token, refreshResult.data.session.refresh_token);
          
          // Set user from refreshed session
          // Защитим от возможных null значений
          req.user = {
            id: refreshResult.data.user.id,
            email: refreshResult.data.user.email || '',
            role: refreshResult.data.user.role || 'user'
          };
          
          // Cleanup old entries in the map (удаляем записи старше 24 часов)
          const ONE_DAY = 24 * 60 * 60 * 1000;
          for (const [key, timestamp] of lastTokenRefreshMap.entries()) {
            if (now - timestamp > ONE_DAY) {
              lastTokenRefreshMap.delete(key);
            }
          }
          
          console.log(`Token refreshed successfully for user ${refreshResult.data.user.id}`);
          
          // Continue with refreshed token
          return next();
        } catch (refreshErr) {
          console.error('Token refresh error in middleware:', refreshErr);
          clearAuthCookies(res);
          
          return res.status(401).json({
            message: 'Invalid or expired session',
            code: 'INVALID_SESSION'
          });
        }
      }
      
      // If no refresh token, clear cookie and return error
      clearAuthCookies(res);
      return res.status(401).json({
        message: 'Invalid or expired token',
        code: 'INVALID_TOKEN'
      });
    }

    // Attach user to request
    req.user = {
      id: data.user.id,
      email: data.user.email || '',
      role: data.user.role || 'user'
    };

    next();
  } catch (err) {
    console.error('Auth middleware error:', err);
    return res.status(500).json({
      message: 'Internal server error',
      code: 'SERVER_ERROR'
    });
  }
};

// Улучшенный механизм отслеживания количества обновлений
const refreshHistory = new Map<string, number[]>();

function recordRefresh(userId: string, timestamp: number) {
  if (!refreshHistory.has(userId)) {
    refreshHistory.set(userId, []);
  }
  
  const userHistory = refreshHistory.get(userId)!;
  userHistory.push(timestamp);
  
  // Удаляем старые записи (старше 5 минут)
  const cutoff = timestamp - MIN_REFRESH_INTERVAL;
  const newHistory = userHistory.filter(time => time >= cutoff);
  refreshHistory.set(userId, newHistory);
}

function getRefreshCount(userId: string, now: number): number {
  if (!refreshHistory.has(userId)) {
    return 0;
  }
  
  const userHistory = refreshHistory.get(userId)!;
  const cutoff = now - MIN_REFRESH_INTERVAL;
  return userHistory.filter(time => time >= cutoff).length;
}

// Централизованная установка кук аутентификации
function setAuthCookies(res: Response, accessToken: string, refreshToken: string) {
  // Определяем правильные настройки для куки
  const isProd = process.env.NODE_ENV === 'production';
  const secureCookie = isProd;
  const cookieDomain = isProd ? '.eneca.work' : undefined; // В продакшене используем домен .eneca.work
  
  // Access token cookie
  res.cookie('auth-token', accessToken, {
    httpOnly: true,
    secure: secureCookie,
    sameSite: isProd ? 'none' : 'lax', // none для cross-origin в продакшене
    domain: cookieDomain,
    path: '/',
    maxAge: 1000 * 60 * 60 * 24 * 7 // 7 days
  });
  
  // Refresh token cookie
  res.cookie('refresh-token', refreshToken, {
    httpOnly: true,
    secure: secureCookie,
    sameSite: isProd ? 'none' : 'lax', // none для cross-origin в продакшене
    domain: cookieDomain,
    path: '/',
    maxAge: 1000 * 60 * 60 * 24 * 30 // 30 days
  });
}

// Централизованная очистка кук аутентификации
function clearAuthCookies(res: Response) {
  const isProd = process.env.NODE_ENV === 'production';
  const cookieDomain = isProd ? '.eneca.work' : undefined;
  
  res.clearCookie('auth-token', {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    domain: cookieDomain,
    path: '/'
  });
  
  res.clearCookie('refresh-token', {
    httpOnly: true, 
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    domain: cookieDomain,
    path: '/'
  });
} 