require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const connectDB = require('./config/db');

// Route'larni import qilamiz
const authRoutes = require('./routes/authRoutes');
const shipmentRoutes = require('./routes/shipmentRoutes');

// ============================================================
// Express ilovasini yaratamiz
// ============================================================
const app = express();

// ============================================================
// 1. HELMET — HTTP xavfsizlik sarlavhalari (Security Headers)
// ============================================================
app.use(
  helmet({
    // Content Security Policy
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'https:'],
      },
    },
    // Clickjacking himoyasi
    frameguard: { action: 'deny' },
    // MIME-sniffing himoyasi
    noSniff: true,
    // X-Powered-By: Express ni o'chirib, server turini yashirish
    hidePoweredBy: true,
    // HSTS — HTTPS talab qilish (production uchun)
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
  })
);

// ============================================================
// 2. CORS sozlamalari (Xavfsiz Whitelist bilan)
// ============================================================
const allowedOrigins = [
  process.env.CLIENT_URL,
  'http://localhost:5173',
  'http://127.0.0.1:5173',
].filter(Boolean);

const corsOptions = {
  origin: function (origin, callback) {
    // Postman yoki mobil ilovalarda origin bo'lmaydi — ruxsat beramiz
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS bloklandi: Ushbu domen uchun ruxsat yo'q: ${origin}`));
    }
  },
  credentials: true, // httpOnly cookie va auth headerlar uchun MAJBURIY
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  maxAge: 86400, // Preflight kesh muddati (24 soat)
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// ============================================================
// 3. Body Parser va Cookie Parser (DoS himoyasi: 10mb limit)
// ============================================================
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// ============================================================
// 4. API Route'lari
// ============================================================
app.use('/auth', authRoutes);
app.use('/shipments', shipmentRoutes);

// ============================================================
// Health Check — Server holatini tekshirish
// ============================================================
app.get('/health', (req, res) => {
  res.status(200).json({
    success: true,
    message: '✅ Numeo Logistics API xavfsiz ishlayapti!',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV,
  });
});

// ============================================================
// 404 — Topilmagan route'lar uchun
// ============================================================
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: `Route topilmadi: ${req.method} ${req.originalUrl}`,
  });
});

// ============================================================
// Global Error Handler (CORS xatolarini ham xavfsiz ushlaydi)
// ============================================================
app.use((err, req, res, next) => {
  if (err.message && err.message.includes('CORS')) {
    return res.status(403).json({
      success: false,
      message: err.message,
    });
  }

  console.error('Global server xatosi:', err.stack);
  res.status(err.status || 500).json({
    success: false,
    message: err.message || 'Ichki server xatosi.',
  });
});

// ============================================================
// MongoDB ulanishi va serverni ishga tushirish
// ============================================================
const PORT = process.env.PORT || 5000;

const startServer = async () => {
  await connectDB();
  app.listen(PORT, () => {
    console.log('');
    console.log('🚀 ======================================= 🚀');
    console.log(`   NUMEO LOGISTICS API (Secured) — Port: ${PORT}`);
    console.log(`   Muhit: ${process.env.NODE_ENV}`);
    console.log(`   MongoDB: ${process.env.MONGO_URI ? 'Ulangan' : 'Mavjud emas'}`);
    console.log(`   Ruxsat etilgan domenlar: ${allowedOrigins.join(', ')}`);
    console.log('🚀 ======================================= 🚀');
    console.log('');
  });
};

startServer();

module.exports = app;
