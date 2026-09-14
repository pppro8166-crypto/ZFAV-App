// ZFAV Team Management App — Task Tracking Module
// Only two statuses allowed: "Complete" and "Not completed" — no extra phases.
// Integrates with auth-server.js (authenticateToken, EXECUTIVE_ROLES)

const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const { authenticateToken, EXECUTIVE_ROLES } = require('./auth-server');

const router = express.Router();

const DATA_FILE = path.join(__dirname, 'data', 'tasks.json');
const VALID_STATUSES = ['Complete', 'Not completed'];

// ---------- Storage helpers ----------
function ensureDataFile() {
  const dir = path.dirname(DATA_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, JSON.stringify([]));
}

function readTasks() {
  ensureDataFile();
  return JSON.parse(fs.readFileSync(DATA_FILE, 'utf-8'));
}

function writeTasks(tasks) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(tasks, null, 2));
}

// ---------- Routes ----------

// Create a task — executive only (Chief, Manager), assigned to one member
router.post('/tasks', authenticateToken, (req, res) => {
  if (!EXECUTIVE_ROLES.includes(req.user.role)) {
    return res.status(403).json({ error: 'Only Chief or Manager can create tasks.' });
  }

  const { title, projectName, assignedTo } = req.body;
  if (!title || !projectName || !assignedTo) {
    return res.status(400).json({ error: 'title, projectName, and assignedTo (memberId) are required.' });
  }

  const tasks = readTasks();
  const newTask = {
    taskId: crypto.randomUUID(),
    title: title.trim(),
    projectName: projectName.trim(),
    assignedTo, // memberId, e.g. "Zfav_Rahul_Sharma"
    status: 'Not completed', // default status
    createdBy: req.user.memberId,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  tasks.push(newTask);
  writeTasks(tasks);

  return res.status(201).json({ message: 'Task created.', task: newTask });
});

// Get tasks assigned to the logged-in member (their own dashboard view)
router.get('/tasks/mine', authenticateToken, (req, res) => {
  const tasks = readTasks();
  const myTasks = tasks.filter(t => t.assignedTo === req.user.memberId);
  return res.json({ tasks: myTasks });
});

// Get all tasks — executive only
router.get('/tasks', authenticateToken, (req, res) => {
  if (!EXECUTIVE_ROLES.includes(req.user.role)) {
    return res.status(403).json({ error: 'Only Chief or Manager can view all tasks.' });
  }
  const tasks = readTasks();
  return res.json({ tasks });
});

// Get a single task — allowed only if it's assigned to you, or you're executive
router.get('/tasks/:taskId', authenticateToken, (req, res) => {
  const tasks = readTasks();
  const task = tasks.find(t => t.taskId === req.params.taskId);
  if (!task) return res.status(404).json({ error: 'Task not found.' });

  const isOwner = task.assignedTo === req.user.memberId;
  const isExecutive = EXECUTIVE_ROLES.includes(req.user.role);
  if (!isOwner && !isExecutive) {
    return res.status(403).json({ error: 'You can only view your own tasks.' });
  }

  return res.json({ task });
});

// Update task status — only "Complete" or "Not completed" accepted.
// Allowed if you're the assigned member, or you're executive.
router.patch('/tasks/:taskId/status', authenticateToken, (req, res) => {
  const { status } = req.body;

  if (!VALID_STATUSES.includes(status)) {
    return res.status(400).json({ error: `Status must be one of: ${VALID_STATUSES.join(', ')}` });
  }

  const tasks = readTasks();
  const task = tasks.find(t => t.taskId === req.params.taskId);
  if (!task) return res.status(404).json({ error: 'Task not found.' });

  const isOwner = task.assignedTo === req.user.memberId;
  const isExecutive = EXECUTIVE_ROLES.includes(req.user.role);
  if (!isOwner && !isExecutive) {
    return res.status(403).json({ error: 'You can only update your own tasks.' });
  }

  task.status = status;
  task.updatedAt = new Date().toISOString();
  writeTasks(tasks);

  return res.json({ message: 'Task status updated.', task });
});

module.exports = { router, VALID_STATUSES };
