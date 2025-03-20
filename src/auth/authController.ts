import { Request, Response } from 'express';
import supabase from '../utils/supabase';
import { LoginRequest, AuthenticatedRequest } from '../types/auth';

// Хранилище для отслеживания последних обновлений токенов пользователей
// userId или IP -> timestamp последнего обновления
const tokenRefreshRateLimit = new Map<string, number>();
// Минимальный интервал между обновлениями токена (в мс) - 5 минут (было 15)
const MIN_REFRESH_INTERVAL = 5 * 60 * 1000;

/**
 * Handle user login
 */
export const login = async (req: Request, res: Response) => {
  try {
    const { email, password }: LoginRequest = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({
        message: 'Email and password are required',
        code: 'MISSING_FIELDS'
      });
    }

    // Authenticate with Supabase
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password
    });

    // Handle authentication error
    if (error) {
      console.error(`Auth error for user ${email}:`, error.message);
      return res.status(401).json({
        message: 'Authentication failed',
        code: 'AUTH_FAILED'
      });
    }

    // Get user profile
    const { data: profile } = await supabase
      .from('profiles')
      .select('*')
      .eq('user_id', data.user.id)
      .single();

    // Log successful login
    console.info(`User ${email} logged in successfully | ${new Date().toISOString()}`);
    
    // Установка куки с использованием централизованной функции
    setAuthCookies(res, data.session.access_token, data.session.refresh_token);

    // Return user information (without sending the token in response body)
    return res.status(200).json({
      user: {
        id: data.user.id,
        email: data.user.email,
        profile: profile
      },
      expiresAt: new Date(data.session.expires_at!).getTime()
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({
      message: 'Internal server error',
      code: 'SERVER_ERROR'
    });
  }
};

/**
 * Handle user logout
 */
export const logout = async (req: Request, res: Response) => {
  try {
    // Sign out from Supabase
    const { error } = await supabase.auth.signOut();
    
    if (error) {
      console.error('Logout error:', error.message);
      return res.status(500).json({
        message: 'Failed to logout',
        code: 'LOGOUT_ERROR'
      });
    }
    
    // Очистка куки с использованием централизованной функции
    clearAuthCookies(res);
    
    return res.status(200).json({
      message: 'Logged out successfully'
    });
  } catch (err) {
    console.error('Logout error:', err);
    return res.status(500).json({
      message: 'Internal server error',
      code: 'SERVER_ERROR'
    });
  }
};

/**
 * Refresh user token
 */
export const refreshToken = async (req: Request, res: Response) => {
  try {
    const refreshToken = req.cookies['refresh-token'];
    
    if (!refreshToken) {
      return res.status(401).json({
        message: 'Refresh token not found',
        code: 'REFRESH_TOKEN_MISSING'
      });
    }
    
    // Проверка частоты обновления токена - используем улучшенный механизм подсчета
    const clientIP = req.ip || 'unknown';
    const clientId = refreshToken.substring(0, 20); // Используем часть токена как идентификатор
    const key = `${clientId}:${clientIP}`;
    const refreshCount = getRefreshCount(key);
    const now = Date.now();
    
    // Проверяем количество обновлений в последние 5 минут
    if (refreshCount > 5) {
      console.log(`Rate limiting token refresh from ${clientIP} - ${refreshCount} refreshes in last 5 minutes`);
      return res.status(429).json({
        message: 'You are refreshing tokens too frequently. Please try again later.',
        code: 'REFRESH_RATE_LIMITED',
        retryAfter: 60 // 1 минута до следующей попытки
      });
    }
    
    // Refresh session using Supabase
    const { data, error } = await supabase.auth.refreshSession({ 
      refresh_token: refreshToken 
    });
    
    if (error || !data || !data.session || !data.user) {
      console.error('Token refresh error:', error?.message || 'Session data missing');
      clearAuthCookies(res);
      
      return res.status(401).json({
        message: 'Failed to refresh token',
        code: 'REFRESH_FAILED'
      });
    }
    
    // Записываем обновление токена
    recordRefresh(key);
    
    // Установка куки с использованием централизованной функции
    setAuthCookies(res, data.session.access_token, data.session.refresh_token);
    
    // Получение профиля пользователя
    const { data: profile } = await supabase
      .from('profiles')
      .select('*')
      .eq('user_id', data.user.id)
      .single();
    
    // Log successful token refresh
    console.info(`Token refreshed for user ${data.user.email} | ${new Date().toISOString()}`);
    
    // Return updated user information
    return res.status(200).json({
      user: {
        id: data.user.id,
        email: data.user.email,
        profile: profile
      },
      expiresAt: new Date(data.session.expires_at!).getTime()
    });
  } catch (err) {
    console.error('Token refresh error:', err);
    // Clear cookies on error
    clearAuthCookies(res);
    
    return res.status(500).json({
      message: 'Internal server error',
      code: 'SERVER_ERROR'
    });
  }
};

/**
 * Get current user session
 */
export const getSession = async (req: AuthenticatedRequest, res: Response) => {
  try {
    // User is already authenticated by middleware
    if (!req.user) {
      return res.status(401).json({
        message: 'Not authenticated',
        code: 'AUTH_REQUIRED'
      });
    }

    // Get user profile from Supabase
    const { data: profile } = await supabase
      .from('profiles')
      .select('*')
      .eq('user_id', req.user.id)
      .single();

    // Return user session data with точным временем истечения токена
    // Используем текущее время плюс 7 дней (так же, как и для кук)
    const tokenExpiry = Date.now() + (7 * 24 * 60 * 60 * 1000);
    
    return res.status(200).json({
      user: {
        id: req.user.id,
        email: req.user.email,
        profile: profile
      },
      expiresAt: tokenExpiry
    });
  } catch (err) {
    console.error('Get session error:', err);
    return res.status(500).json({
      message: 'Internal server error',
      code: 'SERVER_ERROR'
    });
  }
};

// Централизованная установка кук аутентификации
export function setAuthCookies(res: Response, accessToken: string, refreshToken: string) {
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
export function clearAuthCookies(res: Response) {
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

// Храним историю обновлений токенов
const refreshHistory = new Map<string, number[]>();

// Запись обновления токена
function recordRefresh(key: string) {
  if (!refreshHistory.has(key)) {
    refreshHistory.set(key, []);
  }
  
  const history = refreshHistory.get(key)!;
  history.push(Date.now());
  
  // Очистка старых записей (старше 5 минут)
  const cutoff = Date.now() - MIN_REFRESH_INTERVAL;
  const newHistory = history.filter(time => time >= cutoff);
  refreshHistory.set(key, newHistory);
  
  // Периодическая очистка всей истории (раз в день)
  if (Math.random() < 0.01) { // ~1% вероятность при каждом вызове
    const ONE_DAY = 24 * 60 * 60 * 1000;
    const dayAgo = Date.now() - ONE_DAY;
    
    for (const [histKey, timestamps] of refreshHistory.entries()) {
      // Если все записи старше 24 часов, удаляем ключ
      if (timestamps.every(t => t < dayAgo)) {
        refreshHistory.delete(histKey);
      }
    }
  }
}

// Получение количества обновлений токена
function getRefreshCount(key: string): number {
  if (!refreshHistory.has(key)) {
    return 0;
  }
  
  const history = refreshHistory.get(key)!;
  const cutoff = Date.now() - MIN_REFRESH_INTERVAL;
  return history.filter(time => time >= cutoff).length;
} 