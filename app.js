// const express = require('express');
import express from 'express';
import mongoose from 'mongoose';
// const mongoose = require('mongoose');
import bcrypt from 'bcrypt';
// const bcrypt = require('bcrypt');
import session from 'express-session';
// const session = require('express-session');
import dotenv from 'dotenv';
dotenv.config();

const app = express();
app.use(express.json());

mongoose.connect(process.env.mongouri)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Could not connect to MongoDB...', err));


const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  const hash = await bcrypt.hash(this.password, 10);
  this.password = hash;
  next();
});

userSchema.methods.comparePassword = function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);


app.use(session({
  secret: `${process.env.secret_key}`,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // set to true if using HTTPS
}));


app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const user = new User({ username, email, password });
    await user.save();
    res.status(201).send('User registered');
  } catch (error) {
    res.status(400).send('Error registering user: ' + error.message);
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).send('Invalid credentials');
    }
    req.session.userId = user._id;
    res.send('User authenticated');
  } catch (error) {
    res.status(500).send('Error logging in: ' + error.message);
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Error logging out: ' + err.message);
    }
    res.send('User logged out');
  });
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
