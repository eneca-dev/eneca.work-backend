import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import dotenv from 'dotenv';
import authRoutes from './auth/authRoutes';

// Load environment variables
dotenv.config();

// Create Express app
const app = express();
const PORT = process.env.PORT || 3001;
const CORS_ORIGIN = process.env.CORS_ORIGIN || 'http://localhost:3000';

// Middleware
app.use(helmet()); // Security headers
app.use(express.json()); // Parse JSON requests
app.use(cookieParser()); // Parse cookies
app.use(
  cors({
    origin: CORS_ORIGIN,
    credentials: true // Allow cookies in cross-origin requests
  })
);

// Routes
app.use('/api/auth', authRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

// Add API health check endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 