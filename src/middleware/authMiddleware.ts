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
    const requestPath = req.path || 'unknown';
    console.log(`[AUTH] Authenticating request to: ${requestPath}`);
    
    // Get token from cookie
    const token = req.cookies['auth-token'];
    
    if (!token) {
      console.log(`[AUTH] No auth-token cookie found for request to ${requestPath}`);
      // Проверяем наличие refresh токена для потенциального восстановления сессии
      const refreshToken = req.cookies['refresh-token'];
      if (refreshToken) {
        console.log(`[AUTH] Found refresh-token, will attempt to refresh session`);
        // Перенаправляем на обработку обновления токена
        return handleRefreshToken(req, res, next, refreshToken);
      }
      
      return res.status(401).json({
        message: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }

    // Вывод для отладки токена
    const tokenFirstChars = token.substring(0, 10);
    console.log(`[AUTH] Found auth-token starting with: ${tokenFirstChars}...`);

    // Validate token via Supabase
    console.log(`[AUTH] Validating token with Supabase`);
    const { data, error } = await supabase.auth.getUser(token);

    if (error || !data || !data.user) {
      console.error(`[AUTH] Token validation failed: ${error?.message || 'No user data returned'}`);
      
      // Attempt to refresh session using refresh token
      const refreshToken = req.cookies['refresh-token'];
      
      if (refreshToken) {
        console.log(`[AUTH] Found refresh-token, attempting to refresh session`);
        return handleRefreshToken(req, res, next, refreshToken);
      }
      
      // If no refresh token, clear cookies and return error
      console.log('[AUTH] No refresh-token found, authentication failed');
      clearAuthCookies(res);
      return res.status(401).json({
        message: 'Invalid or expired token',
        code: 'INVALID_TOKEN'
      });
    }

    // Valid token, attach user to request
    console.log(`[AUTH] Token valid for user: ${data.user.email}`);
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

/**
 * Helper function to handle refresh token logic
 */
async function handleRefreshToken(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
  refreshToken: string
) {
  try {
    const now = Date.now();
    
    // Короткая выдержка из токена для логирования (без полного раскрытия)
    const tokenPart = refreshToken.substring(0, 10);
    console.log(`[AUTH:REFRESH] Processing refresh token: ${tokenPart}...`);
    
    // Проверка на ограничение частоты обновления
    const refreshedUserId = getUserIdFromRefreshToken(refreshToken);
    if (refreshedUserId) {
      const lastRefresh = lastTokenRefreshMap.get(refreshedUserId);
      if (lastRefresh && now - lastRefresh < MIN_REFRESH_INTERVAL) {
        const timeSinceRefresh = now - lastRefresh;
        console.log(`[AUTH:REFRESH] Rate limiting token refresh, last refresh was ${timeSinceRefresh}ms ago`);
        
        // Если последнее обновление было слишком недавно, все равно продолжаем обработку,
        // но логируем для потенциальной отладки проблем с частыми обновлениями
      }
    }
    
    console.log(`[AUTH:REFRESH] Calling Supabase to refresh session`);
    // Attempt to refresh session using refresh token
    const refreshResult = await supabase.auth.refreshSession({ refresh_token: refreshToken });
    
    if (refreshResult.error || !refreshResult.data.session || !refreshResult.data.user) {
      console.error(`[AUTH:REFRESH] Failed to refresh session: ${refreshResult.error?.message || 'No session data'}`);
      // If refresh fails, clear cookies and return error
      clearAuthCookies(res);
      
      return res.status(401).json({
        message: 'Session expired. Please login again.',
        code: 'SESSION_EXPIRED'
      });
    }
    
    // Логирование успешного обновления и информации о новой сессии
    const userId = refreshResult.data.user.id;
    console.log(`[AUTH:REFRESH] Session refreshed successfully for user: ${refreshResult.data.user.email}`);
    
    // Данные о времени истечения сессии
    const expiresAtRaw = refreshResult.data.session.expires_at;
    const expiresAt = new Date(expiresAtRaw!);
    const timeUntilExpiry = expiresAt.getTime() - now;
    console.log(`[AUTH:REFRESH] New token expires at: ${expiresAt.toISOString()}`);
    console.log(`[AUTH:REFRESH] Time until expiry: ${timeUntilExpiry}ms (${Math.floor(timeUntilExpiry/1000/60)} minutes)`);
    
    // Update refresh time tracking
    lastTokenRefreshMap.set(userId, now);
    
    // Set new tokens in cookies
    setAuthCookies(res, refreshResult.data.session.access_token, refreshResult.data.session.refresh_token);
    
    // Set user from refreshed session
    req.user = {
      id: userId,
      email: refreshResult.data.user.email || '',
      role: refreshResult.data.user.role || 'user'
    };
    
    // Cleanup old entries in the map (delete entries older than 24 hours)
    const ONE_DAY = 24 * 60 * 60 * 1000;
    for (const [key, timestamp] of lastTokenRefreshMap.entries()) {
      if (now - timestamp > ONE_DAY) {
        lastTokenRefreshMap.delete(key);
      }
    }
    
    // Continue with refreshed token
    return next();
  } catch (refreshErr) {
    console.error(`[AUTH:REFRESH] Unexpected error during refresh:`, refreshErr);
    clearAuthCookies(res);
    
    return res.status(401).json({
      message: 'Invalid or expired session',
      code: 'INVALID_SESSION'
    });
  }
}

/**
 * Try to extract user ID from refresh token for rate limiting
 * This is a simplified implementation and might not work with all token formats
 */
function getUserIdFromRefreshToken(token: string): string | null {
  try {
    // Мы не можем декодировать refresh token напрямую, так как это не JWT
    // Используем часть токена как идентификатор для rate limiting
    return token.substring(0, 20);
  } catch (err) {
    console.error('[AUTH] Error extracting user ID from refresh token:', err);
    return null;
  }
}

// Централизованная установка кук аутентификации
function setAuthCookies(res: Response, accessToken: string, refreshToken: string) {
  // Определяем правильные настройки для куки
  const isProd = process.env.NODE_ENV === 'production';
  const secureCookie = isProd;
  const cookieDomain = isProd ? '.eneca.work' : undefined; // В продакшене используем домен .eneca.work
  
  console.log(`[COOKIES] Setting auth cookies: domain=${cookieDomain}, secure=${secureCookie}, sameSite=${isProd ? 'none' : 'lax'}`);
  
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
  
  console.log(`[COOKIES] Clearing auth cookies: domain=${cookieDomain}`);
  
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