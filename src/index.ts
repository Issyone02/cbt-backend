import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import crypto from 'crypto';

// FIX 10: Basic HTML sanitiser — strips dangerous tags/attributes from question text.
// For production, install sanitize-html: npm install sanitize-html @types/sanitize-html
// and replace this with: import sanitizeHtml from 'sanitize-html';
function sanitizeQuestionHtml(html: string): string {
  if (!html) return '';
  // Remove script tags and their contents
  let clean = html.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
  // Remove event handlers (onclick, onerror, onload, etc.)
  clean = clean.replace(/\s+on\w+\s*=\s*(['"])[^'"]*\1/gi, '');
  clean = clean.replace(/\s+on\w+\s*=\s*[^\s>]*/gi, '');
  // Remove javascript: hrefs
  clean = clean.replace(/href\s*=\s*(['"]?)javascript:[^'"\s>]*/gi, '');
  // Remove iframe, object, embed, form tags
  clean = clean.replace(/<(iframe|object|embed|form|input|button)[^>]*>.*?<\/\1>/gis, '');
  clean = clean.replace(/<(iframe|object|embed|form|input|button)[^>]*\/>/gi, '');
  return clean.trim();
}

dotenv.config();

// FIX 1: Enforce strong JWT_SECRET at startup — short/missing secrets allow token forgery
const JWT_SECRET = process.env.JWT_SECRET || '';
const KNOWN_WEAK = ['secret','password','123456','jwt_secret','changeme','admin'];
if (!JWT_SECRET || JWT_SECRET.length < 32 || KNOWN_WEAK.includes(JWT_SECRET.toLowerCase())) {
  console.error('[SECURITY] JWT_SECRET is missing, too short (<32 chars), or a known weak value.');
  console.error("[SECURITY] Generate a strong JWT_SECRET (min 32 chars) and set it in your .env file.");
  process.exit(1);
}

// FIX 20: Validate all required env keys at startup
const REQUIRED_ENV = ['JWT_SECRET', 'DATABASE_URL'];
const missingEnv = REQUIRED_ENV.filter(k => !process.env[k]);
if (missingEnv.length > 0) {
  console.error('[SECURITY] Missing required environment variables:', missingEnv.join(', '));
  process.exit(1);
}

export const prisma = new PrismaClient();
const app = express();

// FIX 16: Enforce HTTPS in production + add HSTS header
app.use(helmet({
  hsts: process.env.NODE_ENV === 'production'
    ? { maxAge: 31536000, includeSubDomains: true, preload: true }
    : false
}));
// FIX 17: Tight Content-Security-Policy to block injected scripts
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc:  ["'self'"],
    styleSrc:   ["'self'", "'unsafe-inline'"],
    imgSrc:     ["'self'", "data:"],
    objectSrc:  ["'none'"],
    frameAncestors: ["'none'"]
  }
}));
if (process.env.NODE_ENV === 'production') {
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect(301, 'https://' + req.headers.host + req.url);
    }
    next();
  });
}
// FIX 2: Never fall back to wildcard / reflect-any-origin CORS — explicit allowlist only.
// `origin: true` (previous setting) reflects whatever Origin header is sent, which is
// effectively open CORS with credentials enabled — any website could call this API
// using a logged-in admin's cookies/token. Replaced with a real allowlist check.
const allowedOrigins = process.env.FRONTEND_URL
  ? process.env.FRONTEND_URL.split(',').map(s => s.trim())
  : ['http://localhost:5173', 'http://localhost:5174'];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no Origin header (curl, mobile apps, same-origin, SEB in some configs)
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));

// General rate limit: 300 requests per 15 minutes per IP
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 300 }));

// Strict rate limit on login: 10 attempts per 15 minutes per IP
// This prevents brute-force attacks against student/admin credentials.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts. Please try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ---------- MIDDLEWARE ----------
interface AuthRequest extends Request {
  user?: { id: string; roles: string[] };
}

const authenticate = async (req: AuthRequest, res: Response, next: NextFunction) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as { userId: string };
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      include: { userRoles: { include: { role: true } } }
    });
    if (!user || !user.isActive) return res.status(401).json({ error: 'Invalid user' });
    req.user = { id: user.id, roles: user.userRoles.map(ur => ur.role.name) };
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

const requireRole = (roles: string[]) => {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthenticated' });
    if (!req.user.roles.some(r => roles.includes(r))) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
};

// ─────────────────────────────────────────────────────────────────────────────
// asyncHandler — wraps async route handlers so any thrown error is forwarded
// to the global error handler automatically, eliminating repetitive try/catch.
// ─────────────────────────────────────────────────────────────────────────────
const asyncHandler = (fn: (req: any, res: any, next: any) => Promise<any>) =>
  (req: any, res: any, next: any) => Promise.resolve(fn(req, res, next)).catch(next);

// Audit log helper — records ALL system events with category, IP, and metadata.
// Categories: AUTH | EXAM | QUESTION | IMPORT | USER | ATTEMPT | SECURITY | SYSTEM
async function auditLog(userId: string | null, action: string, targetId: string, details = '', req?: any) {
  try {
    const ip = req ? String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').split(',')[0].trim() : 'system';
    await prisma.auditLog.create({
      data: {
        userId: userId || undefined,
        action,
        ipAddress: ip,
        metadata: JSON.stringify({ targetId, details, timestamp: new Date().toISOString() })
      }
    });
  } catch {
    console.warn('[AUDIT] Failed to write audit log:', action, targetId);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// SAFE EXAM BROWSER (SEB) DETECTION
// ═══════════════════════════════════════════════════════════════════════════
// Two layers, each independently togglable via environment variables so you
// can test locally without SEB installed, then tighten security for production.
//
//   Layer 1 — User-Agent check (SEB_REQUIRED=true)
//     SEB's browser identifies itself in the User-Agent string (contains "SEB"
//     and/or "SafeExamBrowser"). This alone stops the vast majority of casual
//     attempts to open the exam in normal Chrome/Firefox/Edge.
//
//   Layer 2 — Cryptographic hash check (SEB_STRICT_MODE=true, requires Layer 1)
//     SEB can be configured with a "Browser Exam Key" in the .seb config file.
//     When set, SEB sends header `X-SafeExamBrowser-RequestHash` on every
//     request, computed as SHA-256(fullRequestURL + browserExamKey). The
//     server independently computes the same hash and compares.
//     NOTE: exact URL matching (protocol/host/path/query) must line up between
//     what SEB hashes and what the server reconstructs. Test this in a real
//     SEB session before relying on it — start with Layer 1 only in production
//     until you've confirmed Layer 2 matches in your environment.
// ═══════════════════════════════════════════════════════════════════════════

const SEB_REQUIRED = process.env.SEB_REQUIRED === 'true';
const SEB_STRICT_MODE = process.env.SEB_STRICT_MODE === 'true';
const SEB_BROWSER_EXAM_KEY = process.env.SEB_BROWSER_EXAM_KEY || '';

function isSebUserAgent(ua: string | undefined): boolean {
  if (!ua) return false;
  return /SEB[\/\s]|SafeExamBrowser/i.test(ua);
}

function computeSebRequestHash(fullUrl: string, key: string): string {
  return crypto.createHash('sha256').update(fullUrl + key).digest('hex');
}

const requireSEB = (req: Request, res: Response, next: NextFunction) => {
  if (!SEB_REQUIRED) return next(); // toggle fully off for local dev/testing

  const ua = req.headers['user-agent'];

  // Layer 1: User-Agent must identify as Safe Exam Browser
  if (!isSebUserAgent(ua)) {
    return res.status(403).json({
      error: 'This exam must be opened in Safe Exam Browser.',
      code: 'SEB_REQUIRED'
    });
  }

  // Layer 2 (optional): verify the cryptographic request hash
  if (SEB_STRICT_MODE) {
    if (!SEB_BROWSER_EXAM_KEY) {
      console.error('[SEB] SEB_STRICT_MODE is enabled but SEB_BROWSER_EXAM_KEY is not set.');
      return res.status(500).json({ error: 'Server SEB configuration error.' });
    }
    const sebHash = req.headers['x-safeexambrowser-requesthash'] as string | undefined;
    if (!sebHash) {
      return res.status(403).json({
        error: 'Missing Safe Exam Browser verification header.',
        code: 'SEB_HASH_MISSING'
      });
    }
    const fullUrl = `${req.protocol}://${req.get('host')}${req.originalUrl}`;
    const expectedHash = computeSebRequestHash(fullUrl, SEB_BROWSER_EXAM_KEY);
    if (expectedHash.toLowerCase() !== sebHash.toLowerCase()) {
      // Log details server-side to help you tune URL matching against a real SEB session
      console.warn('[SEB] Request hash mismatch', { fullUrl, expectedHash, receivedHash: sebHash });
      return res.status(403).json({
        error: 'Safe Exam Browser verification failed.',
        code: 'SEB_HASH_MISMATCH'
      });
    }
  }

  next();
};


// ═══════════════════════════════════════════════════════════════════════════
// PASSWORD RESET ROUTES
// Flow:
//   1. Student submits email on "Forgot Password" page → creates a reset request
//      with a 6-digit code and 24hr expiry
//   2. Admin sees pending requests on their dashboard → shares the 6-digit code
//      with the student (in person, via notice board, or phone call)
//   3. Student enters their email + the code + new password → account unlocked
//
// No email server required — designed for school environments.
// ═══════════════════════════════════════════════════════════════════════════


// AUTH_LOGOUT — call this before clearing the session client-side.
// Records who logged out, when, and from which IP.
app.post('/api/auth/logout', authenticate, asyncHandler(async (req: AuthRequest, res: Response) => {
  await auditLog(
    req.user!.id,
    'AUTH_LOGOUT',
    req.user!.id,
    `Logged out (roles: ${req.user!.roles.join(', ')})`,
    req
  );
  res.json({ success: true });
}));

// STEP 1: Student requests a password reset
app.post('/api/auth/forgot-password', asyncHandler(async (req: Request, res: Response) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });

  const user = await prisma.user.findUnique({ where: { email } });

  // Always respond with success even if user not found — prevents email enumeration
  if (!user) return res.json({ success: true, message: 'If that email exists, a reset request has been created.' });

  // Cancel any existing unused reset requests for this user
  await prisma.passwordResetRequest.updateMany({
    where: { userId: user.id, isUsed: false },
    data: { isUsed: true }
  });

  // Generate a random 6-digit code
  const resetCode = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

  await prisma.passwordResetRequest.create({
    data: { userId: user.id, resetCode, expiresAt }
  });

  res.json({ success: true, message: 'Reset request submitted. Please contact your administrator for the reset code.' });
}));

// STEP 2: Admin views all pending reset requests
app.get('/api/admin/password-resets', authenticate, requireRole(['SuperAdmin', 'SchoolAdmin']), asyncHandler(async (req: AuthRequest, res: Response) => {
  const requests = await prisma.passwordResetRequest.findMany({
    where: { isUsed: false, expiresAt: { gt: new Date() } },
    include: { user: { select: { id: true, firstName: true, lastName: true, email: true, studentId: true } } },
    orderBy: { createdAt: 'desc' }
  });
  res.json(requests);
}));

// STEP 2b: Admin dismisses / cancels a reset request without acting on it
app.delete('/api/admin/password-resets/:id', authenticate, requireRole(['SuperAdmin', 'SchoolAdmin']), asyncHandler(async (req: AuthRequest, res: Response) => {
  await prisma.passwordResetRequest.update({
    where: { id: req.params.id },
    data: { isUsed: true }
  });
  res.json({ success: true });
}));

// STEP 3: Student resets their password using email + code + new password
app.post('/api/auth/reset-password', asyncHandler(async (req: Request, res: Response) => {
  const { email, resetCode, newPassword } = req.body;

  if (!email || !resetCode || !newPassword) {
    return res.status(400).json({ error: 'Email, reset code and new password are required' });
  }
  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters' });
  }

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(400).json({ error: 'Invalid email or reset code' });

  const request = await prisma.passwordResetRequest.findFirst({
    where: {
      userId: user.id,
      resetCode,
      isUsed: false,
      expiresAt: { gt: new Date() }
    }
  });

  if (!request) {
    return res.status(400).json({ error: 'Invalid or expired reset code. Please submit a new request.' });
  }

  // Check password history — reject if same as current or last 3 passwords
  const historyCheck = await checkPasswordHistory(user.id, newPassword);
  if (historyCheck.reused) {
    return res.status(400).json({ error: historyCheck.message });
  }

  // Save current password to history before overwriting
  const currentUser = await prisma.user.findUnique({ where: { id: user.id }, select: { passwordHash: true } });
  if (currentUser) await savePasswordHistory(user.id, currentUser.passwordHash);

  // Mark request as used, update password
  await prisma.passwordResetRequest.update({ where: { id: request.id }, data: { isUsed: true } });
  const passwordHash = await bcrypt.hash(newPassword, 12);
  await prisma.user.update({ where: { id: user.id }, data: { passwordHash } });

  await auditLog(user.id, 'PASSWORD_RESET', user.id, 'Student-initiated via reset code');
  res.json({ success: true, message: 'Password reset successfully. You can now log in.' });
}));

// ─────────────────────────────────────────────────────────────────────────────
// checkPasswordHistory — returns true if the new password matches the current
// password OR any of the last 3 passwords used. Prevents password reuse.
// ─────────────────────────────────────────────────────────────────────────────
async function checkPasswordHistory(userId: string, newPassword: string): Promise<{ reused: boolean; message: string }> {
  // Get current hash
  const user = await prisma.user.findUnique({ where: { id: userId }, select: { passwordHash: true } });
  if (user && await bcrypt.compare(newPassword, user.passwordHash)) {
    return { reused: true, message: 'New password cannot be the same as your current password.' };
  }
  // Get last 3 historical hashes
  const history = await prisma.passwordHistory.findMany({
    where: { userId },
    orderBy: { createdAt: 'desc' },
    take: 3,
    select: { passwordHash: true }
  });
  for (const h of history) {
    if (await bcrypt.compare(newPassword, h.passwordHash)) {
      return { reused: true, message: 'You have used this password recently. Please choose a different password.' };
    }
  }
  return { reused: false, message: '' };
}

// Saves current password to history, keeping only the last 3 entries
async function savePasswordHistory(userId: string, currentHash: string): Promise<void> {
  await prisma.passwordHistory.create({ data: { userId, passwordHash: currentHash } });
  // Keep only last 3 — delete older ones
  const all = await prisma.passwordHistory.findMany({
    where: { userId }, orderBy: { createdAt: 'desc' }, select: { id: true }
  });
  if (all.length > 3) {
    const toDelete = all.slice(3).map(h => h.id);
    await prisma.passwordHistory.deleteMany({ where: { id: { in: toDelete } } });
  }
}

// ---------- AUTH ----------
app.post('/api/auth/login', loginLimiter, async (req: Request, res: Response) => {
  const { email, password } = req.body;
  const user = await prisma.user.findUnique({
    where: { email },
    include: { userRoles: { include: { role: true } } }
  });
  // FIX 3: Always run bcrypt.compare to prevent timing-based email enumeration.
  // If user doesn't exist, compare against a fake hash — response time stays constant.
  const DUMMY_HASH = '$2b$12$dummyhashfortimingprotectionxx';
  const hashToCompare = user ? user.passwordHash : DUMMY_HASH;
  const valid = await bcrypt.compare(password, hashToCompare);
  if (!user || !valid || !user.isActive) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET!, { expiresIn: '8h' });
  // Check if user has a pending CLI recovery reset — flag them to change password
  const pendingRecovery = await prisma.passwordResetRequest.findFirst({
    where: { userId: user.id, resetCode: 'CLI_RECOVERY', isUsed: false, expiresAt: { gt: new Date() } }
  });
  // Mark it used immediately so the temp password cannot be reused
  if (pendingRecovery) {
    await prisma.passwordResetRequest.update({ where: { id: pendingRecovery.id }, data: { isUsed: true } });
  }

  // AUTH log — every login recorded
  await auditLog(user.id, 'AUTH_LOGIN', user.id, `Logged in as ${user.userRoles.map((ur: any) => ur.role.name).join(', ')}`, req);

  res.json({
    token,
    mustChangePassword: !!pendingRecovery,
    user: { id: user.id, email: user.email, firstName: user.firstName, lastName: user.lastName, roles: user.userRoles.map(ur => ur.role.name) }
  });
});

// ---------- STUDENT EXAM ROUTES ----------
app.get('/api/exams/available', authenticate, requireRole(['Student']), async (req: AuthRequest, res: Response) => {
  const now = new Date();
  // An exam is visible to students when it is published AND within its time window.
  // Do NOT include questions — that would expose correct answers before the exam starts.
  const exams = await prisma.exam.findMany({
    where: {
      isPublished: true,
      startTime: { lte: now },
      endTime: { gte: now }
    },
    select: {
      id: true,
      title: true,
      description: true,
      startTime: true,
      endTime: true,
      durationMinutes: true,
      passingScorePercent: true,
      negativeMarkingPercent: true,
      _count: { select: { questions: true } },
    },
  });
  res.json(exams);
});

app.post('/api/exams/:examId/start', authenticate, requireRole(['Student']), requireSEB, async (req: AuthRequest, res: Response) => {
  const { examId } = req.params;
  const studentId = req.user!.id;
  
  // Count submitted attempts for this student & exam
  const submittedCount = await prisma.examAttempt.count({
    where: { studentId, examId, status: 'SUBMITTED' }
  });
  if (submittedCount >= 3) {
    return res.status(403).json({ error: 'Maximum 3 attempts allowed for this exam. Contact admin to reset.' });
  }
  
  // Check if there is already an in-progress attempt (resume)
  // FIX 11: Re-verify student is still active when resuming — deactivation takes effect immediately
  const studentRecord = await prisma.user.findUnique({ where: { id: studentId } });
  if (!studentRecord?.isActive) {
    return res.status(403).json({ error: 'Your account has been deactivated. Contact your administrator.' });
  }

  const existingAttempt = await prisma.examAttempt.findFirst({
    where: { studentId, examId, status: { in: ['IN_PROGRESS', 'PAUSED'] } }
  });
  if (existingAttempt) {
    const exam = await prisma.exam.findUnique({
      where: { id: examId },
      include: { questions: { include: { options: true } } }
    });
    if (!exam) return res.status(404).json({ error: 'Exam not found' });

    // Fix 9: Restore previously saved question order from autoSaveData
    // so refreshing the page doesn't re-shuffle questions on the student.
    let questions = [...exam.questions];
    let savedAnswers = {};
    try {
      const saved = JSON.parse(existingAttempt.autoSaveData || '{}');
      savedAnswers = saved.answers || {};
      if (saved.questionOrder && saved.questionOrder.length > 0) {
        const orderMap: Record<string, number> = {};
        saved.questionOrder.forEach((id: string, idx: number) => { orderMap[id] = idx; });
        questions.sort((a, b) => (orderMap[a.id] ?? 999) - (orderMap[b.id] ?? 999));
      } else if (exam.shuffleQuestions) {
        questions = questions.sort(() => Math.random() - 0.5);
      }
    } catch {
      if (exam.shuffleQuestions) questions = questions.sort(() => Math.random() - 0.5);
    }
    if (exam.shuffleOptions) {
      questions = questions.map(q => ({ ...q, options: [...q.options].sort(() => Math.random() - 0.5) }));
    }
    // Fix 7: Return startedAt so frontend can compute time remaining instead of resetting timer
    return res.json({
      attempt: existingAttempt,
      questions,
      examDuration: exam.durationMinutes,
      startedAt: existingAttempt.startedAt,
      savedAnswers
    });
  }

  // New attempt
  const exam = await prisma.exam.findUnique({
    where: { id: examId },
    include: { questions: { include: { options: true } } }
  });
  if (!exam) return res.status(404).json({ error: 'Exam not found' });
  const now = new Date();
  if (now < exam.startTime || now > exam.endTime) return res.status(400).json({ error: 'Exam not available' });

  const attempt = await prisma.examAttempt.create({
    data: { studentId, examId, status: 'IN_PROGRESS', startedAt: now, autoSaveData: '{}' }
  });

  // Create all answer rows in one batch (Fix 10 prep — avoid N+1 on submit)
  await prisma.answer.createMany({
    data: exam.questions.map(q => ({
      attemptId: attempt.id, questionId: q.id,
      answerText: '', pointsAwarded: 0, isCorrect: false, selectedOptionId: null
    }))
  });

  // Fix 9: Shuffle once and persist order in autoSaveData immediately
  let questions = [...exam.questions];
  if (exam.shuffleQuestions) questions = questions.sort(() => Math.random() - 0.5);
  if (exam.shuffleOptions) {
    questions = questions.map(q => ({ ...q, options: [...q.options].sort(() => Math.random() - 0.5) }));
  }
  const questionOrder = questions.map(q => q.id);
  await prisma.examAttempt.update({
    where: { id: attempt.id },
    data: { autoSaveData: JSON.stringify({ answers: {}, questionOrder, savedAt: now.toISOString() }) }
  });

  await auditLog(studentId, 'EXAM_START', exam.id, `Started exam: ${exam.title}`, req);
  // Fix 7: Return startedAt so frontend computes remaining time correctly
  res.json({ attempt, questions, examDuration: exam.durationMinutes, startedAt: now, savedAnswers: {} });
});

app.get('/api/my-results', authenticate, requireRole(['Student']), async (req: AuthRequest, res: Response) => {
  const studentId = req.user!.id;
  const results = await prisma.result.findMany({
    where: { attempt: { studentId } },
    include: {
      attempt: {
        include: { exam: true }
      }
    },
    orderBy: { computedAt: 'desc' }
  });
  res.json(results);
});

// Student review: Get full details of a submitted attempt (read-only)
app.get('/api/results/:attemptId/review', authenticate, async (req: AuthRequest, res: Response) => {
  const { attemptId } = req.params;
  const studentId = req.user!.id;
  
  const attempt = await prisma.examAttempt.findFirst({
    where: { id: attemptId, studentId, status: 'SUBMITTED' },
    include: {
      exam: true,
      answers: {
        include: {
          question: {
            include: { options: true }
          }
        }
      },
      result: true
    }
  });
  
  if (!attempt) {
    return res.status(404).json({ error: 'Review not available' });
  }
  
  // Build review data
  const review = {
    examTitle: attempt.exam.title,
    submittedAt: attempt.submittedAt,
    totalPoints: attempt.result?.totalPoints,
    obtainedPoints: attempt.result?.obtainedPoints,
    percentage: attempt.result?.percentage,
    isPassed: attempt.result?.isPassed,
    questions: attempt.answers.map(ans => {
      const q = ans.question;
      let studentAnswerText = '';
      let correctAnswerText = '';
      
      if (q.type === 'MCQ' || q.type === 'TRUE_FALSE') {
        const selectedOpt = q.options.find(opt => opt.id === ans.selectedOptionId);
        studentAnswerText = selectedOpt ? selectedOpt.text : 'Not answered';
        const correctOpt = q.options.find(opt => opt.isCorrect);
        correctAnswerText = correctOpt ? correctOpt.text : 'N/A';
      } else if (q.type === 'FILL_BLANK') {
        studentAnswerText = ans.answerText || 'Not answered';
        correctAnswerText = q.options[0]?.text || 'N/A';
      } else {
        studentAnswerText = ans.answerText || 'Not answered';
        correctAnswerText = 'Manual grading required';
      }
      
      return {
        id: q.id,
        text: q.text,
        type: q.type,
        points: q.points,
        studentAnswer: studentAnswerText,
        correctAnswer: correctAnswerText,
        isCorrect: ans.isCorrect,
        pointsAwarded: ans.pointsAwarded,
        options: q.type === 'MCQ' || q.type === 'TRUE_FALSE' ? q.options.map(opt => ({
          id: opt.id,
          text: opt.text,
          isCorrect: opt.isCorrect
        })) : []
      };
    })
  };
  
  res.json(review);
});

// ---------- SUBMIT EXAM WITH CORRECT GRADING ----------

// Fix 6: Auto-save route — persists student's in-progress answers every 10 seconds
// Stores answers + question order in autoSaveData so they survive a page reload.
app.patch('/api/attempts/:attemptId/auto-save', authenticate, requireSEB, async (req: AuthRequest, res: Response) => {
  const { attemptId } = req.params;
  const { answers, questionOrder } = req.body;

  const attempt = await prisma.examAttempt.findUnique({ where: { id: attemptId } });
  if (!attempt) return res.status(404).json({ error: 'Attempt not found' });
  if (attempt.studentId !== req.user!.id) return res.status(403).json({ error: 'Forbidden' });
  if (attempt.status !== 'IN_PROGRESS') return res.status(400).json({ error: 'Attempt already submitted' });

  const saveData = JSON.stringify({ answers: answers || {}, questionOrder: questionOrder || [], savedAt: new Date().toISOString() });
  // FIX 8: Reject oversized payloads to prevent database bloat attacks
  if (saveData.length > 100000) {
    return res.status(400).json({ error: 'Auto-save payload too large' });
  }
  await prisma.examAttempt.update({
    where: { id: attemptId },
    data: { autoSaveData: saveData }
  });
  res.json({ success: true, savedAt: new Date().toISOString() });
});

app.post('/api/attempts/:attemptId/submit', authenticate, requireSEB, async (req: AuthRequest, res: Response) => {
  const { attemptId } = req.params;
  const { answers } = req.body; // answers: { questionId: optionId or answerText }
  const attempt = await prisma.examAttempt.findUnique({
    where: { id: attemptId },
    include: {
      exam: true,
      answers: {
        include: {
          question: {
            include: { options: true }
          }
        }
      }
    }
  });
  if (!attempt) {
    return res.status(404).json({ error: 'Attempt not found' });
  }
  if (attempt.studentId !== req.user!.id) {
    return res.status(403).json({ error: 'Forbidden: this is not your attempt' });
  }
  if (attempt.status !== 'IN_PROGRESS') {
    return res.status(400).json({ error: 'Attempt is not in progress' });
  }
  // FIX 5: Enforce exam deadline — allow 5-minute grace period for network delays
  const now = new Date();
  const gracePeriodMs = 5 * 60 * 1000;
  if (attempt.exam.endTime && (now.getTime() - attempt.exam.endTime.getTime()) > gracePeriodMs) {
    return res.status(400).json({ error: 'Exam time has ended. Your saved answers have been recorded.' });
  }

  let totalPoints = 0;
  let obtainedPoints = 0;

  for (const ans of attempt.answers) {
    const q = ans.question;
    totalPoints += q.points;
    let isCorrect = false;
    const studentAnswer = answers ? answers[q.id] : null;

    // Fix 10: Build the full update object in one pass — single DB write per answer
    // Fix 8: awarded is Float — negative marking now works correctly (e.g. -0.25)
    const updateData: any = {};

    if (q.type === 'MCQ' || q.type === 'TRUE_FALSE') {
      const selectedOpt = q.options.find((opt: any) => opt.id === studentAnswer);
      isCorrect = selectedOpt ? selectedOpt.isCorrect : false;
      updateData.selectedOptionId = studentAnswer || null;
    } else if (q.type === 'FILL_BLANK') {
      const correctText = q.options[0]?.text?.trim().toLowerCase();
      const studentText = (studentAnswer || '').trim().toLowerCase();
      isCorrect = studentText !== '' && studentText === correctText;
      updateData.answerText = studentAnswer || '';
    } else if (q.type === 'THEORY') {
      updateData.answerText = studentAnswer || '';
      isCorrect = false; // Requires manual grading
    }

    const awarded: number = isCorrect
      ? q.points
      : (attempt.exam.negativeMarkingPercent && attempt.exam.negativeMarkingPercent > 0
          ? -(q.points * (attempt.exam.negativeMarkingPercent / 100))
          : 0);

    obtainedPoints += awarded;
    updateData.isCorrect = isCorrect;
    updateData.pointsAwarded = awarded;

    // Single update per answer (was two updates before — now merged)
    await prisma.answer.update({ where: { id: ans.id }, data: updateData });
  }

  const percentage = totalPoints === 0 ? 0 : (obtainedPoints / totalPoints) * 100;
  const isPassed = percentage >= attempt.exam.passingScorePercent;
  const result = await prisma.result.create({
    data: {
      attemptId,
      totalPoints,
      obtainedPoints,
      percentage,
      isPassed,
      gradeDetails: '{}',
      computedAt: new Date()
    }
  });
  await prisma.examAttempt.update({
    where: { id: attemptId },
    data: { status: 'SUBMITTED', submittedAt: new Date() }
  });
  await auditLog(req.user!.id, 'EXAM_SUBMIT', attemptId, 'Exam submitted and graded', req);
  res.json(result);
});

app.get('/api/results/:attemptId', authenticate, async (req: AuthRequest, res: Response) => {
  const result = await prisma.result.findUnique({
    where: { attemptId: req.params.attemptId },
    include: {
      attempt: {
        include: {
          exam: true,
          student: { select: { id:true, firstName:true, lastName:true, email:true, studentId:true } }
        }
      }
    }
  });
  if (!result) return res.status(404).json({ error: 'Result not found' });
  // FIX 4: Only the owning student or staff can view a result
  const isStaff = req.user!.roles.some(r => ['SuperAdmin','SchoolAdmin','Lecturer'].includes(r));
  if (!isStaff && result.attempt.studentId !== req.user!.id) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  res.json(result);
});

// ---------- ADMIN ROUTES (unchanged, but ensure they exist) ----------

// Admin: Publish or unpublish an exam (makes it visible/invisible to students)
app.patch('/api/admin/exams/:examId/publish', authenticate, requireRole(['SuperAdmin', 'SchoolAdmin']), async (req: AuthRequest, res: Response) => {
  const { examId } = req.params;
  const { isPublished } = req.body;
  const exam = await prisma.exam.update({
    where: { id: examId },
    data: { isPublished: Boolean(isPublished) }
  });
  await auditLog(req.user!.id, isPublished ? 'EXAM_PUBLISH' : 'EXAM_UNPUBLISH', examId, `Exam ${isPublished ? 'published' : 'unpublished'}`, req);
  res.json({ id: exam.id, isPublished: exam.isPublished });
});

// Admin: Quick action — extend exam window to stay open for N more hours from now
app.patch('/api/admin/exams/:examId/extend', authenticate, requireRole(['SuperAdmin', 'SchoolAdmin']), async (req: AuthRequest, res: Response) => {
  const { examId } = req.params;
  const { hours = 24 } = req.body;
  const now = new Date();
  const newEnd = new Date(now.getTime() + Number(hours) * 60 * 60 * 1000);
  // If startTime is in the future, reset it to now so students can access immediately
  const existing = await prisma.exam.findUnique({ where: { id: examId } });
  if (!existing) return res.status(404).json({ error: 'Exam not found' });
  const newStart = existing.startTime > now ? now : existing.startTime;
  const exam = await prisma.exam.update({
    where: { id: examId },
    data: { startTime: newStart, endTime: newEnd, isPublished: true }
  });
  res.json({ id: exam.id, startTime: exam.startTime, endTime: exam.endTime, isPublished: exam.isPublished });
});

app.get('/api/admin/exams', authenticate, requireRole(['SuperAdmin', 'SchoolAdmin', 'Lecturer']), async (req: AuthRequest, res: Response) => {
  const exams = await prisma.exam.findMany({ orderBy: { createdAt: 'desc' }, include: { questions: true } });
  res.json(exams);
});

app.post('/api/admin/exams', authenticate, requireRole(['SuperAdmin', 'SchoolAdmin']), async (req: AuthRequest, res: Response) => {
  const { title, description, startTime, endTime, durationMinutes, shuffleQuestions, shuffleOptions, negativeMarkingPercent, passingScorePercent } = req.body;
  const start = new Date(startTime);
  const end = new Date(endTime);
  if (isNaN(start.getTime()) || isNaN(end.getTime())) return res.status(400).json({ error: 'Invalid date' });
  const exam = await prisma.exam.create({
    data: {
      title, description, startTime: start, endTime: end, durationMinutes: Number(durationMinutes),
      isPublished: false,
      shuffleQuestions: shuffleQuestions === true, shuffleOptions: shuffleOptions === true,
      negativeMarkingPercent: negativeMarkingPercent || 0, passingScorePercent: Number(passingScorePercent),
      createdBy: req.user!.id
    }
  });
  await auditLog(req.user!.id, 'EXAM_CREATE', exam.id, `Created exam: ${exam.title}`, req);
  res.json(exam);
});

app.post('/api/admin/exams/:examId/questions', authenticate, requireRole(['SuperAdmin', 'SchoolAdmin', 'Lecturer']), async (req: AuthRequest, res: Response) => {
  const { examId } = req.params;
  const { text, type, points, orderIndex, options } = req.body;
  // FIX 6: Validate input lengths to prevent database bloat
  if (!text || typeof text !== 'string' || text.length > 5000) {
    return res.status(400).json({ error: 'Question text must be between 1 and 5000 characters' });
  }
  // FIX 15: Validate points is a positive integer within sane bounds
  if (!Number.isInteger(points) || points < 1 || points > 100) {
    return res.status(400).json({ error: 'Points must be a whole number between 1 and 100' });
  }
  if (Array.isArray(options)) {
    for (const opt of options) {
      if (opt.text && opt.text.length > 500) {
        return res.status(400).json({ error: 'Option text must not exceed 500 characters' });
      }
    }
  }
  const question = await prisma.question.create({
    data: {
      examId, text: sanitizeQuestionHtml(text), type, points, orderIndex,
      options: { create: options.map((opt: any) => ({ text: opt.text, isCorrect: opt.isCorrect, orderIndex: opt.orderIndex })) }
    }
  });
  await auditLog(req.user!.id, 'QUESTION_ADD', question.id, `Added question to exam ${examId}`, req);
  res.json(question);
});


// ---------- CSV QUESTION IMPORT ----------
// Expected CSV columns (see template):
// type, question, option_a, option_b, option_c, option_d, correct, points, explanation
//
// type:     MCQ | TRUE_FALSE | FILL_BLANK | THEORY
// correct:  A/B/C/D for MCQ; TRUE/FALSE for TRUE_FALSE; exact answer text for FILL_BLANK
// points:   integer (defaults to 1 if blank)

app.post('/api/admin/exams/:examId/import-questions', authenticate, requireRole(['SuperAdmin', 'SchoolAdmin', 'Lecturer']), async (req: AuthRequest, res: Response) => {
  const { examId } = req.params;
  const { rows } = req.body; // Pre-parsed rows from frontend

  if (!Array.isArray(rows) || rows.length === 0) {
    return res.status(400).json({ error: 'No rows provided' });
  }
  // FIX 7: Cap CSV imports to prevent DoS via massive uploads
  if (rows.length > 500) {
    return res.status(400).json({ error: 'Maximum 500 questions per import. Please split into multiple files.' });
  }

  const exam = await prisma.exam.findUnique({ where: { id: examId }, include: { questions: true } });
  if (!exam) return res.status(404).json({ error: 'Exam not found' });

  let startOrder = exam.questions.length;
  const errors: string[] = [];
  const created: any[] = [];

  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    const rowNum = i + 2; // +2 because row 1 is header

    const type = (row.type || 'MCQ').toString().trim().toUpperCase();
    const questionText = (row.question || '').toString().trim();
    const points = parseInt(row.points) || 1;

    if (!questionText) { errors.push(`Row ${rowNum}: question text is empty`); continue; }
    if (!['MCQ', 'TRUE_FALSE', 'FILL_BLANK', 'THEORY'].includes(type)) {
      errors.push(`Row ${rowNum}: invalid type "${row.type}". Must be MCQ, TRUE_FALSE, FILL_BLANK, or THEORY`); continue;
    }

    let options: { text: string; isCorrect: boolean; orderIndex: number }[] = [];

    if (type === 'MCQ') {
      const opts = [row.option_a, row.option_b, row.option_c, row.option_d].map(o => (o || '').toString().trim()).filter(Boolean);
      if (opts.length < 2) { errors.push(`Row ${rowNum}: MCQ needs at least 2 options (option_a, option_b...)`); continue; }
      const correct = (row.correct || '').toString().trim().toUpperCase();
      const correctIdx = ['A','B','C','D'].indexOf(correct);
      if (correctIdx === -1) { errors.push(`Row ${rowNum}: correct must be A, B, C, or D for MCQ (got "${row.correct}")`); continue; }
      options = opts.map((text, idx) => ({ text, isCorrect: idx === correctIdx, orderIndex: idx }));
    } else if (type === 'TRUE_FALSE') {
      const correct = (row.correct || '').toString().trim().toUpperCase();
      if (!['TRUE','FALSE'].includes(correct)) { errors.push(`Row ${rowNum}: correct must be TRUE or FALSE for TRUE_FALSE`); continue; }
      options = [
        { text: 'True', isCorrect: correct === 'TRUE', orderIndex: 0 },
        { text: 'False', isCorrect: correct === 'FALSE', orderIndex: 1 }
      ];
    } else if (type === 'FILL_BLANK') {
      const answer = (row.correct || '').toString().trim();
      if (!answer) { errors.push(`Row ${rowNum}: FILL_BLANK needs the correct answer in the "correct" column`); continue; }
      options = [{ text: answer, isCorrect: true, orderIndex: 0 }];
    }
    // THEORY: no options needed

    try {
      const question = await prisma.question.create({
        data: {
          examId,
          text: sanitizeQuestionHtml(questionText),
          type,
          points,
          orderIndex: startOrder++,
          options: { create: options }
        },
        include: { options: true }
      });
      created.push(question);
    } catch (err) {
      errors.push(`Row ${rowNum}: database error — ${(err as any).message}`);
    }
  }

  await auditLog(req.user!.id, 'IMPORT_QUESTIONS', examId, `Imported ${created.length}/${rows.length} questions. Errors: ${errors.length}`, req);
  res.json({
    imported: created.length,
    errors,
    total: rows.length
  });
});

app.get('/api/admin/exams/:examId/questions', authenticate, requireRole(['SuperAdmin', 'SchoolAdmin', 'Lecturer']), async (req: AuthRequest, res: Response) => {
  const questions = await prisma.question.findMany({ where: { examId: req.params.examId }, include: { options: true }, orderBy: { orderIndex: 'asc' } });
  res.json(questions);
});

app.put('/api/admin/questions/:questionId', authenticate, requireRole(['SuperAdmin', 'SchoolAdmin', 'Lecturer']), async (req: AuthRequest, res: Response) => {
  const { questionId } = req.params;
  const { text, type, points, orderIndex, options } = req.body;
  await prisma.option.deleteMany({ where: { questionId } });
  const updated = await prisma.question.update({
    where: { id: questionId },
    data: { text, type, points, orderIndex, options: { create: options.map((opt: any) => ({ text: opt.text, isCorrect: opt.isCorrect, orderIndex: opt.orderIndex })) } }
  });
  res.json(updated);
});

app.delete('/api/admin/questions/:questionId', authenticate, requireRole(['SuperAdmin', 'SchoolAdmin']), async (req: AuthRequest, res: Response) => {
  const { questionId } = req.params;
  await prisma.option.deleteMany({ where: { questionId } });
  await prisma.answer.deleteMany({ where: { questionId } });
  await prisma.question.delete({ where: { id: questionId } });
  await auditLog(req.user!.id, 'QUESTION_DELETE', questionId, 'Question deleted', req);
  res.json({ success: true });
});

app.post('/api/admin/users', authenticate, requireRole(['SuperAdmin', 'SchoolAdmin']), async (req: AuthRequest, res: Response) => {
  const { email, password, firstName, lastName, studentId, department, roleName } = req.body;

  if (!email || !password || !firstName || !lastName || !roleName) {
    return res.status(400).json({ error: 'email, password, firstName, lastName and roleName are required' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  try {
    const hash = await bcrypt.hash(password, 12);
    const user = await prisma.user.create({
      data: {
        email, passwordHash: hash, firstName, lastName,
        studentId: studentId || null,
        department: department || null,
        isActive: true,
        userRoles: { create: { role: { connectOrCreate: { where: { name: roleName }, create: { name: roleName } } } } }
      }
    });
        await auditLog(req.user!.id, 'USER_CREATE', user.id, `Created account for ${email} with role ${roleName}`, req);
    res.json({ id: user.id, email: user.email, firstName: user.firstName, lastName: user.lastName });
  } catch (err: any) {
    if (err.code === 'P2002') {
      const field = err.meta?.target?.[0] || 'field';
      const friendlyField = field === 'studentId' ? 'Student ID' : field === 'email' ? 'Email' : field;
      return res.status(409).json({ error: friendlyField + ' already exists. Please use a different one.' });
    }
    throw err;
  }
});


// ---------- USER MANAGEMENT ROUTES ----------

// GET all users (with their roles)
app.get('/api/admin/users', authenticate, requireRole(['SuperAdmin', 'SchoolAdmin']), async (req: AuthRequest, res: Response) => {
  const users = await prisma.user.findMany({
    select: {
      id: true,
      email: true,
      firstName: true,
      lastName: true,
      studentId: true,
      department: true,
      isActive: true,
      createdAt: true,
      userRoles: { select: { role: { select: { name: true } } } },
      _count: { select: { examAttempts: true } }
    },
    orderBy: { createdAt: 'desc' }
  });
  // Flatten roles array for easier frontend consumption
  const shaped = users.map(u => ({
    ...u,
    roles: u.userRoles.map(ur => ur.role.name),
    examAttempts: u._count.examAttempts,
    userRoles: undefined,
    _count: undefined
  }));
  res.json(shaped);
});

// GET single user
app.get('/api/admin/users/:userId', authenticate, requireRole(['SuperAdmin', 'SchoolAdmin']), async (req: AuthRequest, res: Response) => {
  const user = await prisma.user.findUnique({
    where: { id: req.params.userId },
    select: {
      id: true, email: true, firstName: true, lastName: true,
      studentId: true, department: true, isActive: true, createdAt: true,
      userRoles: { select: { role: { select: { name: true } } } }
    }
  });
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ ...user, roles: user.userRoles.map(ur => ur.role.name) });
});

// PUT update user (name, department, studentId, role, active status)
app.put('/api/admin/users/:userId', authenticate, requireRole(['SuperAdmin', 'SchoolAdmin']), async (req: AuthRequest, res: Response) => {
  const { userId } = req.params;
  const { firstName, lastName, studentId, department, isActive, roleName, password } = req.body;

  // Prevent admin from deactivating themselves
  if (userId === req.user!.id && isActive === false) {
    return res.status(400).json({ error: 'You cannot deactivate your own account' });
  }

  try {
    // Update basic fields
    const updateData: any = {};
    if (firstName !== undefined) updateData.firstName = firstName;
    if (lastName !== undefined) updateData.lastName = lastName;
    if (studentId !== undefined) updateData.studentId = studentId || null;
    if (department !== undefined) updateData.department = department || null;
    if (isActive !== undefined) updateData.isActive = isActive;
    if (password && password.length >= 6) {
      // FIX 9: Admin changing their own password must verify current password first
      if (userId === req.user!.id) {
        const { currentPassword } = req.body;
        if (!currentPassword) {
          return res.status(400).json({ error: 'Current password is required to change your own password' });
        }
        const adminUser = await prisma.user.findUnique({ where: { id: userId } });
        const valid = adminUser ? await bcrypt.compare(currentPassword, adminUser.passwordHash) : false;
        if (!valid) return res.status(403).json({ error: 'Current password is incorrect' });
      }
      // Check password history before accepting new password
      const histCheck = await checkPasswordHistory(userId, password);
      if (histCheck.reused) {
        return res.status(400).json({ error: histCheck.message });
      }
      // Save current password to history before overwriting
      const targetUser = await prisma.user.findUnique({ where: { id: userId }, select: { passwordHash: true } });
      if (targetUser) await savePasswordHistory(userId, targetUser.passwordHash);
      updateData.passwordHash = await bcrypt.hash(password, 12);
    }

    const user = await prisma.user.update({ where: { id: userId }, data: updateData });

    // Update role if provided — use explicit roleId to satisfy Prisma's strict types
    if (roleName) {
      const role = await prisma.role.upsert({
        where: { name: roleName },
        update: {},
        create: { name: roleName }
      });
      await prisma.userRole.deleteMany({ where: { userId } });
      await prisma.userRole.create({ data: { userId, roleId: role.id } });
    }

    res.json({ id: user.id, email: user.email, firstName: user.firstName, lastName: user.lastName, isActive: user.isActive });
  } catch (err: any) {
    if (err.code === 'P2002') {
      const field = err.meta?.target?.[0] || 'field';
      const friendlyField = field === 'studentId' ? 'Student ID' : field === 'email' ? 'Email' : field;
      return res.status(409).json({ error: `${friendlyField} already exists.` });
    }
    throw err;
  }
});

// DELETE user permanently
app.delete('/api/admin/users/:userId', authenticate, requireRole(['SuperAdmin', 'SchoolAdmin']), async (req: AuthRequest, res: Response) => {
  const { userId } = req.params;

  if (userId === req.user!.id) {
    return res.status(400).json({ error: 'You cannot delete your own account' });
  }

  // Delete in dependency order
  await prisma.answer.deleteMany({ where: { attempt: { studentId: userId } } });
  await prisma.result.deleteMany({ where: { attempt: { studentId: userId } } });
  await prisma.examAttempt.deleteMany({ where: { studentId: userId } });
  await prisma.userRole.deleteMany({ where: { userId } });
  await prisma.auditLog.deleteMany({ where: { userId } });
  await prisma.user.delete({ where: { id: userId } });
  await auditLog(req.user!.id, 'DELETE_USER', userId);
  res.json({ success: true });
});

app.put('/api/admin/exams/:examId', authenticate, requireRole(['SuperAdmin', 'SchoolAdmin']), async (req: AuthRequest, res: Response) => {
  const { examId } = req.params;
  const { title, description, startTime, endTime, durationMinutes, shuffleQuestions, shuffleOptions, negativeMarkingPercent, passingScorePercent } = req.body;
  const start = new Date(startTime);
  const end = new Date(endTime);
  if (isNaN(start.getTime()) || isNaN(end.getTime())) return res.status(400).json({ error: 'Invalid date' });
  const updated = await prisma.exam.update({
    where: { id: examId },
    data: { title, description, startTime: start, endTime: end, durationMinutes: Number(durationMinutes), shuffleQuestions, shuffleOptions, negativeMarkingPercent, passingScorePercent }
  });
  res.json(updated);
});

app.delete('/api/admin/exams/:examId', authenticate, requireRole(['SuperAdmin', 'SchoolAdmin']), async (req: AuthRequest, res: Response) => {
  const { examId } = req.params;
  const exam = await prisma.exam.findUnique({ where: { id: examId } });
  if (!exam) return res.status(404).json({ error: 'Exam not found' });
  // Batch deletes in dependency order — replaces old N+1 per-question/per-attempt loops
  await prisma.answer.deleteMany({ where: { attempt: { examId } } });
  await prisma.result.deleteMany({ where: { attempt: { examId } } });
  await prisma.examAttempt.deleteMany({ where: { examId } });
  await prisma.option.deleteMany({ where: { question: { examId } } });
  await prisma.question.deleteMany({ where: { examId } });
  await prisma.exam.delete({ where: { id: examId } });
  await auditLog(req.user!.id, 'DELETE_EXAM', examId);
  res.json({ success: true });
});

// Admin: Reset (delete) a student's attempt so they can retake the exam
app.delete('/api/admin/attempts/:attemptId', authenticate, requireRole(['SuperAdmin', 'SchoolAdmin']), async (req: AuthRequest, res: Response) => {
  const { attemptId } = req.params;
  try {
    // Delete associated answers, result, then the attempt itself
    await prisma.answer.deleteMany({ where: { attemptId } });
    await prisma.result.deleteMany({ where: { attemptId } });
    await prisma.examAttempt.delete({ where: { id: attemptId } });
    await auditLog(req.user!.id, 'RESET_ATTEMPT', attemptId);
    res.json({ success: true, message: 'Attempt reset. Student can retake the exam.' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to reset attempt' });
  }
});

// Admin: Get all submitted attempts (for reset management)
app.get('/api/admin/attempts', authenticate, requireRole(['SuperAdmin', 'SchoolAdmin', 'Lecturer']), async (req: AuthRequest, res: Response) => {
  const attempts = await prisma.examAttempt.findMany({
    where: { status: 'SUBMITTED' },
    include: {
      // FIX 18: Explicitly select student fields — never return passwordHash
      student: { select: { id:true, firstName:true, lastName:true, email:true, studentId:true, department:true } },
      exam: true,
      result: true
    },
    orderBy: { submittedAt: 'desc' }
  });
  res.json(attempts);
});

app.get('/api/health', (req: Request, res: Response) => res.json({ status: 'ok' }));


// ═══════════════════════════════════════════════════════════════════════════
// REPORTS & ANALYTICS ROUTES
// ═══════════════════════════════════════════════════════════════════════════

// GET /api/admin/reports/overview
// Summary stats: total exams, students, attempts, overall pass rate
app.get('/api/admin/reports/overview', authenticate, requireRole(['SuperAdmin', 'SchoolAdmin']), asyncHandler(async (req: AuthRequest, res: Response) => {
  const [totalExams, totalStudents, totalAttempts, passedAttempts] = await Promise.all([
    prisma.exam.count(),
    prisma.user.count({ where: { userRoles: { some: { role: { name: 'Student' } } } } }),
    prisma.examAttempt.count({ where: { status: 'SUBMITTED' } }),
    prisma.result.count({ where: { isPassed: true } }),
  ]);
  const passRate = totalAttempts > 0 ? Math.round((passedAttempts / totalAttempts) * 100) : 0;
  res.json({ totalExams, totalStudents, totalAttempts, passedAttempts, passRate });
}));

// GET /api/admin/reports/exams
// Per-exam analytics: attempt count, avg score, pass rate, high/low score
app.get('/api/admin/reports/exams', authenticate, requireRole(['SuperAdmin', 'SchoolAdmin']), asyncHandler(async (req: AuthRequest, res: Response) => {
  const exams = await prisma.exam.findMany({
    select: {
      id: true, title: true, passingScorePercent: true,
      _count: { select: { questions: true } },
      examAttempts: {
        where: { status: 'SUBMITTED' },
        include: { result: true }
      }
    }
  });

  const report = exams.map(exam => {
    const attempts = exam.examAttempts;
    const results = attempts.map(a => a.result).filter(Boolean) as any[];
    const scores = results.map(r => r.percentage);
    const passed = results.filter(r => r.isPassed).length;
    const avgScore = scores.length ? scores.reduce((a, b) => a + b, 0) / scores.length : 0;
    const highScore = scores.length ? Math.max(...scores) : 0;
    const lowScore = scores.length ? Math.min(...scores) : 0;
    return {
      id: exam.id,
      title: exam.title,
      totalQuestions: exam._count.questions,
      passingScorePercent: exam.passingScorePercent,
      totalAttempts: attempts.length,
      passCount: passed,
      failCount: attempts.length - passed,
      passRate: attempts.length > 0 ? Math.round((passed / attempts.length) * 100) : 0,
      avgScore: Math.round(avgScore * 10) / 10,
      highScore: Math.round(highScore * 10) / 10,
      lowScore: Math.round(lowScore * 10) / 10,
    };
  });
  res.json(report);
}));

// GET /api/admin/reports/students
// Per-student performance across all exams
app.get('/api/admin/reports/students', authenticate, requireRole(['SuperAdmin', 'SchoolAdmin']), asyncHandler(async (req: AuthRequest, res: Response) => {
  const students = await prisma.user.findMany({
    where: { userRoles: { some: { role: { name: 'Student' } } } },
    select: {
      id: true, firstName: true, lastName: true, email: true,
      studentId: true, department: true,
      examAttempts: {
        where: { status: 'SUBMITTED' },
        include: { result: true, exam: { select: { title: true } } }
      }
    }
  });

  const report = students.map(s => {
    const attempts = s.examAttempts;
    const results = attempts.map(a => a.result).filter(Boolean) as any[];
    const scores = results.map(r => r.percentage);
    const passed = results.filter(r => r.isPassed).length;
    const avgScore = scores.length ? scores.reduce((a, b) => a + b, 0) / scores.length : 0;
    return {
      id: s.id,
      name: `${s.firstName} ${s.lastName}`,
      email: s.email,
      studentId: s.studentId,
      department: s.department,
      totalAttempts: attempts.length,
      passCount: passed,
      failCount: attempts.length - passed,
      avgScore: Math.round(avgScore * 10) / 10,
      bestScore: scores.length ? Math.round(Math.max(...scores) * 10) / 10 : 0,
      recentAttempts: attempts.slice(-3).map(a => ({
        examTitle: a.exam.title,
        percentage: a.result?.percentage ?? 0,
        isPassed: a.result?.isPassed ?? false,
        submittedAt: a.submittedAt
      }))
    };
  });
  res.json(report);
}));

// GET /api/admin/reports/exams/:examId/questions
// Per-question difficulty: how many students got each question right/wrong
app.get('/api/admin/reports/exams/:examId/questions', authenticate, requireRole(['SuperAdmin', 'SchoolAdmin']), asyncHandler(async (req: AuthRequest, res: Response) => {
  const { examId } = req.params;
  const questions = await prisma.question.findMany({
    where: { examId },
    include: {
      options: true,
      answers: {
        include: { attempt: { select: { status: true } } }
      }
    },
    orderBy: { orderIndex: 'asc' }
  });

  const report = questions.map((q, idx) => {
    const submittedAnswers = q.answers.filter(a => a.attempt.status === 'SUBMITTED');
    const total = submittedAnswers.length;
    const correct = submittedAnswers.filter(a => a.isCorrect).length;
    const correctPct = total > 0 ? Math.round((correct / total) * 100) : 0;
    // Difficulty: Easy >70%, Medium 40-70%, Hard <40%
    const difficulty = correctPct >= 70 ? 'Easy' : correctPct >= 40 ? 'Medium' : 'Hard';
    return {
      index: idx + 1,
      id: q.id,
      text: q.text.replace(/<[^>]*>/g, '').substring(0, 120),
      type: q.type,
      points: q.points,
      totalAnswered: total,
      correctCount: correct,
      wrongCount: total - correct,
      correctPercent: correctPct,
      difficulty,
    };
  });
  res.json(report);
}));


// ═══════════════════════════════════════════════════════════════════════════
// AUDIT LOG ROUTES — Admin only, never accessible to students or lecturers
// ═══════════════════════════════════════════════════════════════════════════

app.get('/api/admin/audit-logs', authenticate, requireRole(['SuperAdmin', 'SchoolAdmin']), asyncHandler(async (req: AuthRequest, res: Response) => {
  const { category, userId, from, to, page = '1', limit = '50' } = req.query as Record<string, string>;

  // Build category filter — each category maps to action prefixes
  const categoryPrefixes: Record<string, string[]> = {
    AUTH:     ['AUTH_LOGIN', 'AUTH_LOGOUT', 'ADMIN_PASSWORD_RECOVERY'],
    EXAM:     ['EXAM_CREATE', 'EXAM_DELETE', 'EXAM_PUBLISH', 'EXAM_UNPUBLISH', 'EXAM_START', 'EXAM_SUBMIT'],
    QUESTION: ['QUESTION_ADD', 'QUESTION_DELETE', 'QUESTION_UPDATE'],
    IMPORT:   ['IMPORT_QUESTIONS'],
    USER:     ['USER_CREATE', 'USER_UPDATE', 'DELETE_USER'],
    ATTEMPT:  ['RESET_ATTEMPT'],
    SECURITY: ['PASSWORD_RESET', 'ADMIN_PASSWORD_RECOVERY_CLI'],
  };

  const where: any = {};
  if (category && categoryPrefixes[category]) {
    where.action = { in: categoryPrefixes[category] };
  }
  if (userId) where.userId = userId;
  if (from || to) {
    where.createdAt = {};
    if (from) where.createdAt.gte = new Date(from);
    if (to) where.createdAt.lte = new Date(to);
  }

  const pageNum = Math.max(1, parseInt(page));
  const limitNum = Math.min(200, Math.max(1, parseInt(limit)));
  const skip = (pageNum - 1) * limitNum;

  const [logs, total] = await Promise.all([
    prisma.auditLog.findMany({
      where,
      include: {
        user: { select: { firstName: true, lastName: true, email: true, userRoles: { select: { role: { select: { name: true } } } } } }
      },
      orderBy: { createdAt: 'desc' },
      skip,
      take: limitNum
    }),
    prisma.auditLog.count({ where })
  ]);

  res.json({ logs, total, page: pageNum, totalPages: Math.ceil(total / limitNum) });
}));

// CSV export of audit logs — admin only
app.get('/api/admin/audit-logs/export', authenticate, requireRole(['SuperAdmin', 'SchoolAdmin']), asyncHandler(async (req: AuthRequest, res: Response) => {
  const { category, from, to } = req.query as Record<string, string>;

  const categoryPrefixes: Record<string, string[]> = {
    AUTH:     ['AUTH_LOGIN', 'AUTH_LOGOUT', 'ADMIN_PASSWORD_RECOVERY'],
    EXAM:     ['EXAM_CREATE', 'EXAM_DELETE', 'EXAM_PUBLISH', 'EXAM_UNPUBLISH', 'EXAM_START', 'EXAM_SUBMIT'],
    QUESTION: ['QUESTION_ADD', 'QUESTION_DELETE', 'QUESTION_UPDATE'],
    IMPORT:   ['IMPORT_QUESTIONS'],
    USER:     ['USER_CREATE', 'USER_UPDATE', 'DELETE_USER'],
    ATTEMPT:  ['RESET_ATTEMPT'],
    SECURITY: ['PASSWORD_RESET', 'ADMIN_PASSWORD_RECOVERY_CLI'],
  };

  const where: any = {};
  if (category && categoryPrefixes[category]) where.action = { in: categoryPrefixes[category] };
  if (from || to) {
    where.createdAt = {};
    if (from) where.createdAt.gte = new Date(from);
    if (to) where.createdAt.lte = new Date(to);
  }

  const logs = await prisma.auditLog.findMany({
    where,
    include: { user: { select: { firstName: true, lastName: true, email: true } } },
    orderBy: { createdAt: 'desc' },
    take: 10000
  });

  const rows = logs.map(log => {
    const meta = (() => { try { return JSON.parse(log.metadata || '{}'); } catch { return {}; } })();
    return [
      log.createdAt.toISOString(),
      log.action,
      log.user ? `${log.user.firstName} ${log.user.lastName}` : 'System',
      log.user?.email || '',
      log.ipAddress || '',
      meta.details || '',
      meta.targetId || ''
    ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(',');
  });

  const csv = ['Timestamp,Action,User,Email,IP Address,Details,Target ID', ...rows].join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="audit-log-${new Date().toISOString().slice(0,10)}.csv"`);
  res.send(csv);
}));

// ---------- GLOBAL ERROR HANDLER ----------
// Must be BEFORE app.listen and AFTER all routes.
// Catches any unhandled error — never exposes stack traces to the client.
app.use((err: any, req: Request, res: Response, _next: NextFunction) => {
  const status = err.status || err.statusCode || 500;
  const message = err.message || 'An unexpected error occurred';
  console.error(`[ERROR] ${req.method} ${req.path} ->`, err);
  res.status(status).json({ error: message });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
