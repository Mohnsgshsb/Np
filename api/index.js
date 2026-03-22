const express = require('express');
const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public'))); // ملفات HTML/CSS/JS

// ─── MongoDB Connection (Serverless-friendly) ───
let cached = global.mongoose;

if (!cached) cached = global.mongoose = { conn: null, promise: null };

async function connectDB() {
  if (cached.conn) return cached.conn;

  if (!cached.promise) {
    const opts = {
      bufferCommands: false,
      serverSelectionTimeoutMS: 5000,
      maxPoolSize: 10
    };

    cached.promise = mongoose.connect(process.env.MONGODB_URI, opts)
      .then(mongoose => {
        console.log('MongoDB متصل');
        return mongoose;
      })
      .catch(err => {
        console.error('MongoDB connection error:', err);
        cached.promise = null;
        throw err;
      });
  }

  cached.conn = await cached.promise;
  return cached.conn;
}

// ─── Schemas & Models ───
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  password: { type: String, required: true },
  code:     { type: String, required: true },
  expire:   { type: String, required: true },
  isAdmin:  { type: Boolean, default: false },
  createdAt:{ type: Date, default: Date.now }
});

const codeSchema = new mongoose.Schema({
  code:      { type: String, required: true, unique: true },
  type:      { type: String, default: 'normal' },
  expire:    { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  used:      { type: Boolean, default: false }
});

const User = mongoose.models.User || mongoose.model('User', userSchema);
const Code = mongoose.models.Code || mongoose.model('Code', codeSchema);

// ─── Initialization ───
(async () => {
  try {
    await connectDB();
    const adminExists = await User.findOne({ username: 'admin' });
    if (!adminExists) {
      const hashed = await bcrypt.hash('1234', 10);
      await User.create({
        username: 'admin',
        password: hashed,
        code: 'VIPADMIN',
        expire: '2030-01-01',
        isAdmin: true
      });
      console.log('Admin user created');
    }
  } catch (err) {
    console.error('Initialization error:', err);
  }
})();

// ─── Routes for frontend pages ───
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/gp', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'gp.html'));
});

// Simple admin middleware (يمكنك تحسينه لاحقاً بـ auth token)
function authAdmin(req, res, next) {
  // تحقق من كلمة مرور أو session لو حبيت
  next();
}

app.get('/admin', authAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ─── API Routes ───

// Login
app.post('/login', async (req, res) => {
  try {
    const { username, password, code } = req.body;
    if (!username || !password || !code)
      return res.status(400).json({ error: 'جميع الحقول مطلوبة' });

    await connectDB();
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور خاطئة' });

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور خاطئة' });

    if (code !== user.code) return res.status(403).json({ error: 'كود الاشتراك غير صحيح' });

    const today = new Date().toISOString().split('T')[0];
    if (today > user.expire) return res.status(403).json({ error: '⛔ الاشتراك منتهي الصلاحية' });

    res.json({ success: true, isAdmin: user.isAdmin });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'خطأ داخلي في السيرفر' });
  }
});

// Admin APIs
app.post('/admin/adduser', authAdmin, async (req, res) => {
  try {
    const { username, password, code, expire } = req.body;
    if (!username || !password || !code || !expire) return res.status(400).json({ error: 'جميع الحقول مطلوبة' });

    await connectDB();
    const exists = await User.findOne({ username });
    if (exists) return res.status(409).json({ error: 'اسم المستخدم موجود مسبقًا' });

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ username, password: hashedPassword, code, expire, isAdmin: false });

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'خطأ أثناء إضافة المستخدم' });
  }
});

app.post('/admin/deleteuser', authAdmin, async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'اسم المستخدم مطلوب' });

    await connectDB();
    const result = await User.deleteOne({ username });
    if (result.deletedCount === 0) return res.status(404).json({ error: 'المستخدم غير موجود' });

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'خطأ أثناء الحذف' });
  }
});

app.post('/admin/generatecode', authAdmin, async (req, res) => {
  try {
    const { type = 'normal', expire } = req.body;
    if (!expire) return res.status(400).json({ error: 'تاريخ الانتهاء مطلوب' });

    await connectDB();
    const newCode = { code: uuidv4().slice(0, 8).toUpperCase(), type, expire, used: false };
    await Code.create(newCode);

    res.json(newCode);
  } catch (err) {
    res.status(500).json({ error: 'خطأ أثناء إنشاء الكود' });
  }
});

app.get('/admin/users', authAdmin, async (req, res) => {
  try {
    await connectDB();
    const users = await User.find({}).select('-password');
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'خطأ في جلب المستخدمين' });
  }
});

app.get('/admin/codes', authAdmin, async (req, res) => {
  try {
    await connectDB();
    const codes = await Code.find({});
    res.json(codes);
  } catch (err) {
    res.status(500).json({ error: 'خطأ في جلب الأكواد' });
  }
});

// ─── Export app for Vercel ───
module.exports = app;
