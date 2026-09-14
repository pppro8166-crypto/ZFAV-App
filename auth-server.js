// ZFAV Team Management App — Auth System
// Stack: Node.js + Express + bcryptjs + jsonwebtoken
// Storage: simple JSON file (data/members.json) — replace later with a real DB if needed

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'zfav_dev_secret_change_me';
const DATA_FILE = path.join(__dirname, 'data', 'members.json');
const ALL_ROLES = ['Chief', 'Manager', 'Animator', 'Designer', 'Developer', 'Guest'];
const EXECUTIVE_ROLES = ['Chief', 'Manager']; // full access: create members, view all data, downloads
const ARTIST_ROLES = ['Animator', 'Designer', 'Developer']; // restricted: own dashboard + assigned projects only
const RESTRICTED_ROLES = [...ARTIST_ROLES, 'Guest']; // Guest gets the same restrictions as artists

// ---------- Storage helpers ----------
function ensureDataFile() {
  const dir = path.dirname(DATA_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, JSON.stringify([]));
}

function readMembers() {
  ensureDataFile();
  return JSON.parse(fs.readFileSync(DATA_FILE, 'utf-8'));
}

function writeMembers(members) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(members, null, 2));
}

// ---------- Member ID generator ----------
// "Rahul Sharma" -> "Zfav_Rahul_Sharma"
function generateMemberId(fullName) {
  const cleaned = fullName.trim().replace(/\s+/g, '_');
  return `Zfav_${cleaned}`;
}

// ---------- Auth middleware ----------
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // "Bearer <token>"
  if (!token) return res.status(401).json({ error: 'Token missing. Please login.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
    req.user = user; // { memberId, role }
    next();
  });
}

function requireExecutive(req, res, next) {
  if (!EXECUTIVE_ROLES.includes(req.user.role)) {
    return res.status(403).json({ error: 'Only Chief or Manager can perform this action.' });
  }
  next();
}

// Allows access only if the requester is viewing their OWN data, or is executive.
// Use this on any route that takes a :memberId param (profile, tasks, project details, etc.)
function requireOwnDataOrExecutive(req, res, next) {
  const targetMemberId = req.params.memberId;
  const isSelf = req.user.memberId === targetMemberId;
  const isExecutive = EXECUTIVE_ROLES.includes(req.user.role);

  if (!isSelf && !isExecutive) {
    return res.status(403).json({ error: 'You can only view your own data.' });
  }
  next();
}

// Blocks download/export endpoints for Animator, Designer, Developer, and Guest
function blockDownloadForRestricted(req, res, next) {
  if (RESTRICTED_ROLES.includes(req.user.role)) {
    return res.status(403).json({ error: 'Download access is not available for your role.' });
  }
  next();
}

// ---------- Routes ----------

// Create a new member (member ID auto-generated as Zfav_FullName)
// Allowed if: (a) no members exist yet (first-time Founder setup), OR (b) requester is executive
router.post('/create-member', (req, res, next) => {
  const members = readMembers();
  if (members.length === 0) {
    // Bootstrap: allow first account creation without auth (must be Founder)
    return handleCreateMember(req, res);
  }
  // Otherwise require valid token + executive role
  authenticateToken(req, res, () => requireExecutive(req, res, () => handleCreateMember(req, res)));
});

function handleCreateMember(req, res) {
  const { fullName, role, password } = req.body;

  if (!fullName || !role || !password) {
    return res.status(400).json({ error: 'fullName, role, and password are required.' });
  }
  if (!ALL_ROLES.includes(role)) {
    return res.status(400).json({ error: `Role must be one of: ${ALL_ROLES.join(', ')}` });
  }

  const members = readMembers();

  // First-ever account must be Chief (bootstrap safety check)
  if (members.length === 0 && role !== 'Chief') {
    return res.status(400).json({ error: 'First account must be a Chief.' });
  }

  const memberId = generateMemberId(fullName);

  if (members.some(m => m.memberId === memberId)) {
    return res.status(409).json({ error: `Member ID "${memberId}" already exists. Use a different name.` });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);

  const newMember = {
    memberId,
    fullName: fullName.trim(),
    role,
    password: hashedPassword,
    createdAt: new Date().toISOString(),
  };

  members.push(newMember);
  writeMembers(members);

  return res.status(201).json({
    message: 'Member created successfully.',
    memberId,
    role,
  });
}

// Login using memberId (Zfav_FullName) instead of email
router.post('/login', (req, res) => {
  const { memberId, password } = req.body;

  if (!memberId || !password) {
    return res.status(400).json({ error: 'memberId and password are required.' });
  }

  const members = readMembers();
  const member = members.find(m => m.memberId === memberId);

  if (!member) {
    return res.status(401).json({ error: 'Invalid member ID or password.' });
  }

  const passwordMatches = bcrypt.compareSync(password, member.password);
  if (!passwordMatches) {
    return res.status(401).json({ error: 'Invalid member ID or password.' });
  }

  const token = jwt.sign(
    { memberId: member.memberId, role: member.role, fullName: member.fullName },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  return res.json({
    message: 'Login successful.',
    token,
    member: { memberId: member.memberId, fullName: member.fullName, role: member.role },
  });
});

// ---------- Example data-access routes (permission enforcement demo) ----------

// Dashboard: everyone sees only THEIR OWN assigned projects/tasks.
// Executives can pass ?memberId=Zfav_X to view someone else's dashboard.
router.get('/dashboard', authenticateToken, (req, res) => {
  const members = readMembers();
  const requestedMemberId = req.query.memberId;

  let targetMemberId = req.user.memberId;
  if (requestedMemberId && requestedMemberId !== req.user.memberId) {
    if (!EXECUTIVE_ROLES.includes(req.user.role)) {
      return res.status(403).json({ error: 'You can only view your own dashboard.' });
    }
    targetMemberId = requestedMemberId;
  }

  const member = members.find(m => m.memberId === targetMemberId);
  if (!member) return res.status(404).json({ error: 'Member not found.' });

  return res.json({
    memberId: member.memberId,
    fullName: member.fullName,
    role: member.role,
    assignedProjects: member.assignedProjects || [],
  });
});

// Single member profile — self or executive only
router.get('/member/:memberId', authenticateToken, requireOwnDataOrExecutive, (req, res) => {
  const members = readMembers();
  const member = members.find(m => m.memberId === req.params.memberId);
  if (!member) return res.status(404).json({ error: 'Member not found.' });

  return res.json({
    memberId: member.memberId,
    fullName: member.fullName,
    role: member.role,
    assignedProjects: member.assignedProjects || [],
  });
});

// Example: export/download project data — executives only, blocked for artists + guest
router.get('/project/:projectId/download', authenticateToken, blockDownloadForRestricted, (req, res) => {
  // Actual file/export logic goes here
  return res.json({ message: `Download ready for project ${req.params.projectId}.` });
});

// List all members — executive only (used by the Team/Executive panel)
router.get('/members', authenticateToken, requireExecutive, (req, res) => {
  const members = readMembers();
  const safeMembers = members.map(({ password, ...rest }) => rest); // never send password hashes
  return res.json({ members: safeMembers });
});

module.exports = {
  router,
  authenticateToken,
  requireExecutive,
  requireOwnDataOrExecutive,
  blockDownloadForRestricted,
  EXECUTIVE_ROLES,
  ARTIST_ROLES,
  RESTRICTED_ROLES,
  ALL_ROLES,
};
