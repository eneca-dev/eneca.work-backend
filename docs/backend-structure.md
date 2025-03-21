# EnecaWork Backend Structure

## Project Overview
EnecaWork Backend is a Node.js application built with Express and TypeScript. It serves as the API layer for the EnecaWork application, handling authentication, data processing, and business logic. The backend uses Supabase as its database and authentication provider.

## Directory Structure

### `/src`
The main source code directory:
- `index.ts` - The entry point that sets up the Express server, middleware, and routes

### `/src/auth`
Authentication-related functionality:
- `authController.ts` - Handles login, logout, session management, and token refresh
- `registerController.ts` - Manages user registration and email confirmation
- `authRoutes.ts` - Defines all authentication-related API endpoints with rate limiting

### `/src/controllers`
Business logic controllers:
- `sessionController.ts` - Manages user sessions and related operations

### `/src/middleware`
Request processing middleware:
- `authMiddleware.ts` - Authentication and authorization middleware for protected routes

### `/src/types`
TypeScript type definitions:
- `auth.ts` - Type definitions for authentication-related objects

### `/src/utils`
Utility functions and helpers:
- `supabase.ts` - Supabase client configuration and initialization

## API Routes

### Authentication Routes (`/api/auth`)
- `POST /api/auth/login` - User login with email and password
  - Rate limited to 5 attempts per 10 minutes
  - Returns authentication tokens as HTTP-only cookies
  
- `POST /api/auth/logout` - User logout
  - Clears authentication cookies
  
- `GET /api/auth/session` - Get current user session
  - Rate limited to 30 requests per 5 minutes
  - Requires authentication
  - Returns user session data
  
- `POST /api/auth/refresh` - Refresh authentication token
  - Rate limited to 10 attempts per 15 minutes
  - Uses refresh token to issue a new authentication token
  
- `POST /api/auth/register` - User registration
  - Rate limited to 5 attempts per hour
  - Creates new user account and sends confirmation email
  
- `POST /api/auth/resend-confirmation` - Resend confirmation email
  - Rate limited to 5 attempts per hour
  - Sends a new confirmation email to the user

### Health Check
- `GET /api/health` - API health check endpoint
  - Returns server status and environment information

## Authentication Flow
The backend implements a secure authentication system with:
- JWT-based authentication with HTTP-only cookies
- Refresh token rotation for enhanced security
- Rate limiting to prevent brute force attacks
- Email verification for new user accounts
- Session management for authenticated users

## Security Features
- CORS configuration for frontend domains only
- Rate limiting on sensitive endpoints
- Helmet for HTTP security headers
- HTTP-only cookie-based authentication tokens
- Environment-specific configurations

## Database Integration
The backend uses Supabase as the database and authentication provider:
- Supabase client is configured in `utils/supabase.ts`
- Database connections use environment variables for credentials
- Supports different environments (development, production)

## Development Workflow
The project uses TypeScript with ts-node-dev for hot reloading. Start the development server with:
```
npm run dev
```

## Deployment
The application is configured for deployment on Heroku as indicated by the Procfile:
- `npm run build` compiles TypeScript to JavaScript
- `npm start` runs the compiled code
- Environment variables are managed through the hosting platform
