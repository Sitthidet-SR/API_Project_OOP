const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const User = require('./models/User');
const Product = require('./models/Product');
const PopularProduct = require('./models/PopularProduct');
const Cart = require('./models/Cart');
const Order = require('./models/Order');

dotenv.config();

const app = express();

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

app.use(express.json());
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
  })
);

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/jackcoffee')
  .then(() => console.log('✅ MongoDB Connected'))
  .catch((err) => console.log('MongoDB connection error:', err));

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix + ext);
  },
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image/')) {
    cb(null, true);
  } else {
    cb(new Error('ไม่ใช่ไฟล์รูปภาพ! โปรดอัปโหลดเฉพาะไฟล์รูปภาพเท่านั้น.'), false);
  }
};

const upload = multer({ 
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024
  }
});

app.get('/api/test', (req, res) => {
  res.json({ message: 'API is working!' });
});

app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/register', upload.single('profileImage'), async (req, res) => {
  console.log('Register API called with body:', req.body);
  console.log('File:', req.file);
  
  try {
    const { username, firstName, lastName, email, phone, password } = req.body;
    
    if (!username || !firstName || !lastName || !email || !phone || !password) {
      return res.status(400).json({ error: 'กรุณากรอกข้อมูลให้ครบถ้วน' });
    }

    const profileImage = req.file ? req.file.path : null;
    console.log('Profile image path:', profileImage);

    const existingUser = await User.findOne({ 
      $or: [
        { email: email },
        { username: username }
      ]
    });
    
    if (existingUser) {
      if (existingUser.email === email) {
        return res.status(400).json({ error: 'อีเมลนี้ถูกใช้งานแล้ว กรุณาใช้อีเมลอื่น' });
      } else {
        return res.status(400).json({ error: 'ชื่อผู้ใช้นี้ถูกใช้งานแล้ว กรุณาใช้ชื่อผู้ใช้อื่น' });
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      firstName,
      lastName,
      email,
      phone,
      password: hashedPassword,
      profileImage
    });

    await newUser.save();
    
    const userResponse = { ...newUser.toObject() };
    delete userResponse.password;
    
    res.status(201).json({ 
      message: 'ลงทะเบียนผู้ใช้สำเร็จ', 
      user: userResponse 
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: error.message || 'เกิดข้อผิดพลาดในการลงทะเบียน' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ message: 'กรุณากรอกอีเมลและรหัสผ่าน' });
    }
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' });
    }

    const token = jwt.sign(
      { userId: user._id }, 
      process.env.JWT_SECRET || 'your-secret-key', 
      { expiresIn: '1d' }
    );
    
    const userResponse = { ...user.toObject() };
    delete userResponse.password;
    
    res.json({ 
      message: 'เข้าสู่ระบบสำเร็จ',
      token,
      user: userResponse
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: error.message || 'เกิดข้อผิดพลาดในการเข้าสู่ระบบ' });
  }
});

app.post('/api/products', upload.single('image'), async (req, res) => {
  try {
    const { name_en, description_en, price } = req.body;
    if (!name_en || !description_en || !price) {
      return res.status(400).json({ error: "Missing required fields: name_en, description_en, price" });
    }

    const image = req.file ? req.file.path : '';

    const newProduct = new Product({ 
      name_en, 
      description_en, 
      price, 
      image 
    });

    await newProduct.save();
    res.status(201).json({ 
      message: '✅ Product added successfully', 
      product: newProduct 
    });
  } catch (error) {
    console.error('❌ Add product error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/products/:id/translate/:lang', async (req, res) => {
  try {
    const { id, lang } = req.params;
    const { name, description } = req.body;
    
    if (!['th', 'en'].includes(lang)) {
      return res.status(400).json({ error: 'Unsupported language' });
    }
    
    const product = await Product.findById(id);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    if (lang === 'th') {
      product.name_th = name;
      product.description_th = description;
      product.translation_status.th = true;
    } else if (lang === 'en') {
      product.name_en = name;
      product.description_en = description;
    }
    
    await product.save();
    
    res.json({ 
      message: `Product translated to ${lang} successfully`, 
      product 
    });
  } catch (error) {
    console.error('Translate product error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/products', async (req, res) => {
  try {
    const lang = req.query.lang || 
                (req.headers['accept-language']?.startsWith('th') ? 'th' : 'en');
    
    const products = await Product.find();
    const baseUrl = `${req.protocol}://${req.get('host')}/`;
    
    const formattedProducts = products.map(product => {
      const result = {
        _id: product._id,
        price: product.price,
        // แปลงพาธรูปภาพเป็น URL เต็ม
        image: product.image && !product.image.startsWith('http') ? 
               baseUrl + product.image : product.image,
        createdAt: product.createdAt,
        updatedAt: product.updatedAt
      };
      
      if (lang === 'th' && product.translation_status.th) {
        result.name = product.name_th;
        result.description = product.description_th;
      } else if (lang === 'th' && !product.translation_status.th) {
        result.name = product.name_en;
        result.description = product.description_en;
        result.untranslated = true;
      } else {
        result.name = product.name_en;
        result.description = product.description_en;
      }
      
      return result;
    });
    
    res.json(formattedProducts);
  } catch (error) {
    console.error('Get products error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/popular-products', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 5;
    const baseUrl = `${req.protocol}://${req.get('host')}/`;
    
    const popularProducts = await PopularProduct.find()
      .sort({ rank: 1, popularCount: -1 })
      .limit(limit)
      .populate('productId');
    
    const formattedProducts = popularProducts.map(item => {
      const product = item.productId;
      return {
        _id: product._id,
        name: product.name_en,
        description: product.description_en,
        price: product.price,
        // แปลงพาธรูปภาพเป็น URL เต็ม
        image: product.image && !product.image.startsWith('http') ? 
               baseUrl + product.image : product.image,
        popularRank: item.rank,
        popularCount: item.popularCount,
        addedToPopularAt: item.addedAt
      };
    });
    
    res.json(formattedProducts);
  } catch (error) {
    console.error('Get popular products error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/popular-products', async (req, res) => {
  try {
    const { productId, rank } = req.body;
    
    console.log("📌 Received productId:", productId, "| Type:", typeof productId);

    const validObjectId = mongoose.Types.ObjectId.isValid(productId);
    if (!validObjectId) {
      console.log("❌ Invalid ObjectId Format:", productId);
      return res.status(400).json({ error: "Invalid productId format" });
    }

    const product = await Product.findById(productId);
    
    if (!product) {
      console.log("❌ ไม่พบสินค้าในฐานข้อมูล!", productId);
      return res.status(404).json({ error: "ไม่พบสินค้า" });
    }

    console.log("✅ พบสินค้า:", product.name_en);
    
    let popularProduct = await PopularProduct.findOne({ productId });

    if (popularProduct) {
      popularProduct.rank = rank || popularProduct.rank;
      await popularProduct.save();
      res.json({ message: "อัปเดตเมนูยอดฮิตสำเร็จ", popularProduct });
    } else {
      popularProduct = new PopularProduct({ productId, rank: rank || 0 });
      await popularProduct.save();
      res.status(201).json({ message: "เพิ่มสินค้าเข้าเมนูยอดฮิตสำเร็จ", popularProduct });
    }
  } catch (error) {
    console.error("❌ Add to popular products error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/popular-products/:id', async (req, res) => {
  try {
    const popularProduct = await PopularProduct.findOneAndDelete({
      productId: req.params.id
    });
    
    if (!popularProduct) {
      return res.status(404).json({ error: 'ไม่พบเมนูยอดฮิต' });
    }
    
    res.json({ message: 'ลบสินค้าออกจากเมนูยอดฮิตสำเร็จ' });
  } catch (error) {
    console.error('Remove from popular products error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/popular-products/:id/increase', async (req, res) => {
  try {
    let popularProduct = await PopularProduct.findOne({ productId: req.params.id })
      .populate('productId');
    
    if (popularProduct) {
      popularProduct.popularCount += 1;
      await popularProduct.save();
      
      const product = popularProduct.productId;
      res.json({ 
        message: 'อัปเดตความนิยมสำเร็จ', 
        popularProduct: {
          _id: popularProduct._id,
          rank: popularProduct.rank,
          popularCount: popularProduct.popularCount,
          product: {
            _id: product._id,
            name: product.name_en,
            description: product.description_en,
            price: product.price,
            image: product.image
          }
        }
      });
    } else {
      const product = await Product.findById(req.params.id);
      if (!product) {
        return res.status(404).json({ error: 'ไม่พบสินค้า' });
      }
      
      popularProduct = new PopularProduct({
        productId: req.params.id,
        popularCount: 1
      });
      
      await popularProduct.save();
      
      res.json({ 
        message: 'เพิ่มสินค้าเข้าเมนูยอดฮิตโดยอัตโนมัติและอัปเดตความนิยมสำเร็จ', 
        popularProduct: {
          _id: popularProduct._id,
          rank: popularProduct.rank,
          popularCount: popularProduct.popularCount,
          product: {
            _id: product._id,
            name: product.name_en,
            description: product.description_en,
            price: product.price,
            image: product.image
          }
        }
      });
    }
  } catch (error) {
    console.error('Increase popularity error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/popular-products/:id/rank', async (req, res) => {
  try {
    const { rank } = req.body;
    
    const popularProduct = await PopularProduct.findOneAndUpdate(
      { productId: req.params.id },
      { rank },
      { new: true }
    );
    
    if (!popularProduct) {
      return res.status(404).json({ error: 'ไม่พบเมนูยอดฮิต' });
    }
    
    res.json({ message: 'อัปเดตลำดับความนิยมสำเร็จ', popularProduct });
  } catch (error) {
    console.error('Update rank error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.use((err, req, res, next) => {
  console.error('Server error:', err);
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'ไฟล์มีขนาดใหญ่เกินไป (สูงสุด 5MB)' });
    }
    return res.status(400).json({ error: `Error uploading file: ${err.message}` });
  }
  res.status(500).json({ error: err.message || 'เกิดข้อผิดพลาดบนเซิร์ฟเวอร์' });
});

app.get('/', (req, res) => {
  res.send('Jack Coffee API is running...');
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));