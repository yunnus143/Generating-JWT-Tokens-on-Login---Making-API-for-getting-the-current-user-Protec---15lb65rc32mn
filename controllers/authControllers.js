const User = require('../models/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const JWT_SECRET = 'newtonSchool';

const signup = async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const user = await User.create({
            username,
            email,
            password,
        });
        res.status(201).json({
            status: 'success',
            data: {
                user,
            },
        });
    } catch (err) {
        res.status(400).json({
            status: 'error',
            message: err.message,
        });
    }
}
const login = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Please provide email and password', status: 'Error' });
  }

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(401).json({ message: 'Invalid email or password', status: 'Error', error: 'Invalid Credentials' });
  }

  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    return res.status(401).json({ message: 'Invalid email or password', status: 'Error', error: 'Invalid Credentials' });
  }

  const token = jwt.sign({ sub: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

  res.status(200).json({ token, status: 'Success' });
};

const decodeToken = async (req, res) => {
  const { token } = req.body;
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    res.status(200).json({ payload, status: 'Success' });
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

module.exports = { login, decodeToken };
