const mongoose = require('mongoose');

const ProductSchema = new mongoose.Schema(
  {
    // ข้อมูลทั่วไปที่ไม่ขึ้นอยู่กับภาษา
    price: { type: Number, required: true },
    image: { type: String, default: '' },
    
    // ข้อมูลภาษาอังกฤษ (เริ่มต้น)
    name_en: { type: String, required: true },
    description_en: { type: String, required: true },
    
    // ข้อมูลภาษาไทย (อาจจะว่างเปล่าเมื่อเพิ่มสินค้าครั้งแรก)
    name_th: { type: String, default: '' },
    description_th: { type: String, default: '' },
    
    // สถานะการแปล
    translation_status: { 
      th: { type: Boolean, default: false } // true หากมีการแปลภาษาไทยแล้ว
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model('Product', ProductSchema);