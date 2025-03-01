const mongoose = require('mongoose');

const PopularProductSchema = new mongoose.Schema(
  {
    productId: { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: 'Product',  // ต้องตรงกับชื่อโมเดล
      required: true 
    },
    rank: { 
      type: Number, 
      default: 0 
    },
    popularCount: { 
      type: Number, 
      default: 0 
    },
    addedAt: { 
      type: Date, 
      default: Date.now 
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model('PopularProduct', PopularProductSchema);
