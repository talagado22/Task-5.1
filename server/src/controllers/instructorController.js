import { Instructor } from '../models/Instructor.js';
import Joi from 'joi';

// =============================================================================
//  INSTRUCTOR PORTAL CONTROLLER  —  ✅ SECURED
// =============================================================================

// Input validation schemas
const loginSchema = Joi.object({
  username: Joi.string().required(),
  password: Joi.string().required()
});

const searchSchema = Joi.object({
  name: Joi.string().optional(),
  department: Joi.string().optional(),
  role: Joi.string().optional()
}).unknown(false); // Reject any field not explicitly listed here

function publicProfile(doc) {
  // Removed sensitive fields (apiKey, privateEmail, privatePhone)
  return {
    id: doc._id.toString(),
    name: doc.name,
    username: doc.username,
    department: doc.department,
    role: doc.role,
  };
}

// POST /api/instructors/login
export async function loginInstructor(req, res, next) {
  try {
    // 1. Validate input types using Joi
    const { error, value } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: 'Invalid input types. Username and password must be strings.' });
    }

    const { username, password } = value;

    // 2. Use explicit string values in the query to prevent object injection
    // 3. Find the user by username only (we compare passwords separately)
    const instructor = await Instructor.findOne({ username: String(username) });

    if (!instructor) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // 4. Securely compare hashed password using bcrypt
    const isMatch = await instructor.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    return res.json({ instructor: publicProfile(instructor) });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors
export async function getDirectory(req, res, next) {
  try {
    const instructors = await Instructor.find()
      .select('name department role')
      .sort({ name: 1 })
      .lean();
    res.json({ instructors });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors/search
export async function searchInstructors(req, res, next) {
  try {
    // 1. Validate and sanitize query parameters using Joi
    const { error, value } = searchSchema.validate(req.query);
    if (error) {
      return res.status(400).json({ message: 'Invalid search parameters. Only name, department, and role are allowed.' });
    }

    // 2. Build a clean filter object using only validated values
    const filter = {};
    if (value.name) filter.name = String(value.name);
    if (value.department) filter.department = String(value.department);
    if (value.role) filter.role = String(value.role);

    // 3. Explicitly exclude sensitive fields using .select('-...')
    const instructors = await Instructor.find(filter)
      .select('-password -apiKey -privateEmail -privatePhone')
      .lean();

    res.json({ count: instructors.length, instructors });
  } catch (err) {
    next(err);
  }
}
