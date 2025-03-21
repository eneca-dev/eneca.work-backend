import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import dotenv from 'dotenv';
import authRoutes from './auth/authRoutes';
import profileRoutes from './routes/profileRoutes';

// Load environment variables version stable
dotenv.config();

// Create Express app
const app = express();
const PORT = process.env.PORT || 3001;
const CORS_ORIGIN = process.env.CORS_ORIGIN || 'http://localhost:3000';

// Middleware
app.use(helmet()); // Security headers
app.use(express.json()); // Parse JSON requests
app.use(cookieParser()); // Parse cookies

// Настройка CORS с поддержкой credentials и корректным origin
app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (like mobile apps, curl, etc.)
      if (!origin) return callback(null, true);
      
      // Разрешенные origin из env или по умолчанию
      const allowedOrigins = [
        CORS_ORIGIN,
        'https://eneca.work',
        'https://www.eneca.work',
        'http://local.eneca.work'
      ];
      
      if (allowedOrigins.indexOf(origin) !== -1) {
        callback(null, true);
      } else {
        console.warn(`CORS blocked for origin: ${origin}`);
        callback(null, false);
      }
    },
    credentials: true, // Allow cookies in cross-origin requests
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
  })
);

// Routes
app.use('/api/auth', authRoutes);
app.use('/api', profileRoutes);

// API health check endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok', env: process.env.NODE_ENV });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 