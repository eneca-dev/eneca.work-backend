import { Response, NextFunction } from 'express';
import { AuthenticatedRequest } from '../types/auth';
import supabase from '../utils/supabase';

// Хранилище для отслеживания последних обновлений токенов пользователей
// userId -> timestamp последнего обновления
const lastTokenRefreshMap = new Map<string, number>();
// Минимальный интервал между обновлениями токена (в мс) - 15 минут
const MIN_REFRESH_INTERVAL = 15 * 60 * 1000;

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
        
        // Если с последнего обновления прошло меньше минимального интервала, не обновляем токен
        if (now - lastRefresh < MIN_REFRESH_INTERVAL) {
          console.log(`Skipping token refresh for user - too soon (${Math.floor((now - lastRefresh) / 1000)} seconds since last refresh)`);
          res.clearCookie('auth-token');
          res.clearCookie('refresh-token');
          
          return res.status(401).json({
            message: 'Session refresh rate limited. Please try again later.',
            code: 'REFRESH_RATE_LIMITED'
          });
        }
        
        try {
          // Attempt to refresh session using refresh token
          const refreshResult = await supabase.auth.refreshSession({ refresh_token: refreshToken });
          
          if (refreshResult.error || !refreshResult.data.session || !refreshResult.data.user) {
            // If refresh fails, clear cookies and return error
            res.clearCookie('auth-token');
            res.clearCookie('refresh-token');
            
            return res.status(401).json({
              message: 'Session expired. Please login again.',
              code: 'SESSION_EXPIRED'
            });
          }
          
          // Обновляем время последнего обновления токена
          // Убедимся, что refreshResult.data.user существует и имеет id
          if (refreshResult.data.user && refreshResult.data.user.id) {
            lastTokenRefreshMap.set(refreshResult.data.user.id, now);
          }
          
          // Set new tokens in cookies
          res.cookie('auth-token', refreshResult.data.session.access_token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 1000 * 60 * 60 * 24 * 7 // 7 days
          });
          
          res.cookie('refresh-token', refreshResult.data.session.refresh_token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 1000 * 60 * 60 * 24 * 30 // 30 days
          });
          
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
          res.clearCookie('auth-token');
          res.clearCookie('refresh-token');
          
          return res.status(401).json({
            message: 'Invalid or expired session',
            code: 'INVALID_SESSION'
          });
        }
      }
      
      // If no refresh token, clear cookie and return error
      res.clearCookie('auth-token');
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