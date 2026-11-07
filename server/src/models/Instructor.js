import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

// Instructor Portal account.
const instructorSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    username: { type: String, required: true, unique: true, trim: true },
    password: { type: String, required: true },
    department: { type: String },
    role: { type: String, default: 'instructor' }, // 'instructor' | 'superadmin'

    // Sensitive "trophy" fields the directory hides but injection can leak.
    apiKey: { type: String },
    privateEmail: { type: String },
    privatePhone: { type: String }
  },
  { timestamps: true }
);

// Pre-save hook to hash password before saving to database
instructorSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();

  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

// Method to compare passwords for login
instructorSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

export const Instructor = mongoose.model('Instructor', instructorSchema);
