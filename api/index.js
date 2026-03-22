const express = require('express');
const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static('public'));

// ─── MongoDB Connection (cached for serverless) ───
let cached = global.mongoose;

if (!cached) {
  cached = global.mongoose = { conn: null, promise: null };
}

async function connectDB() {
  if (cached.conn) {
    return cached.conn;
  }

  if (!cached.promise) {
    const opts = {
      bufferCommands: false,          // مهم في serverless
      serverSelectionTimeoutMS: 5000, // تجنب تعليق طويل
      maxPoolSize: 10                 // حد أقصى معقول للـ connections
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

// ─── Models ───
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

// ربط الداتابيز في بداية الـ cold start (مهم)
(async () => {
  try {
    await connectDB();

    // إنشاء admin أول مرة لو مش موجود
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

// ─── Routes ───

// Login
app.post('/login', async (req, res) => {
  try {
    const { username, password, code } = req.body;
    if (!username || !password || !code) {
      return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
    }

    await connectDB();
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور خاطئة' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور خاطئة' });
    }

    if (code !== user.code) {
      return res.status(403).json({ error: 'كود الاشتراك غير صحيح' });
    }

    const today = new Date().toISOString().split('T')[0];
    if (today > user.expire) {
      return res.status(403).json({ error: '⛔ الاشتراك منتهي الصلاحية' });
    }

    res.json({ success: true, isAdmin: user.isAdmin });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'خطأ داخلي في السيرفر' });
  }
});

// Add user (admin only – يفضل تضيف middleware لاحقًا)
app.post('/admin/adduser', async (req, res) => {
  try {
    const { username, password, code, expire } = req.body;
    if (!username || !password || !code || !expire) {
      return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
    }

    await connectDB();

    const exists = await User.findOne({ username });
    if (exists) {
      return res.status(409).json({ error: 'اسم المستخدم موجود مسبقًا' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await User.create({
      username,
      password: hashedPassword,
      code,
      expire,
      isAdmin: false
    });

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'خطأ أثناء إضافة المستخدم' });
  }
});

// Delete user
app.post('/admin/deleteuser', async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'اسم المستخدم مطلوب' });

    await connectDB();
    const result = await User.deleteOne({ username });

    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'المستخدم غير موجود' });
    }

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'خطأ أثناء الحذف' });
  }
});

// Generate code
app.post('/admin/generatecode', async (req, res) => {
  try {
    const { type = 'normal', expire } = req.body;
    if (!expire) return res.status(400).json({ error: 'تاريخ الانتهاء مطلوب' });

    await connectDB();

    const newCode = {
      code: uuidv4().slice(0, 8).toUpperCase(),
      type,
      expire,
      used: false
    };

    await Code.create(newCode);

    res.json(newCode);
  } catch (err) {
    res.status(500).json({ error: 'خطأ أثناء إنشاء الكود' });
  }
});

// List users (hide password)
app.get('/admin/users', async (req, res) => {
  try {
    await connectDB();
    const users = await User.find({}).select('-password');
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'خطأ في جلب المستخدمين' });
  }
});

// List codes
app.get('/admin/codes', async (req, res) => {
  try {
    await connectDB();
    const codes = await Code.find({});
    res.json(codes);
  } catch (err) {
    res.status(500).json({ error: 'خطأ في جلب الأكواد' });
  }
});

// Export for Vercel (مهم جدًا – احذف app.listen)
module.exports = app;