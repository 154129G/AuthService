var express = require('express');
var router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
var cookie = require('cookie');
const User = require('../models/user');
const isAuth = require('../middleware/is-auth');

router.post('/getUserByEmail', async function (req, res, next) {
  const valid = await isAuth( req.headers.authorization);
  try {
   
    if (!valid) {
      return res.status(401).send({
       message: 'unauthenticated'
   });
   }else{
    const user = await User.findOne({ email: req.body.email });
   
    delete user.password;
    res.send({status: 200 , user :{email:  user.email ,firstName: user.firstName , lastName: user.lastName, mobile: user.mobile, parent: user.parent } });
   }
    

  } catch (error) {
    console.error(error);
  }
});


router.post('/refreshToken', async function (req, res, next) {
  const refreshToken = req.cookies['refreshToken'];
  
  const payload =  jwt.verify(refreshToken, 'somesupersecretkey');
  console.log('refreshToken', payload); 
  if (!payload) {
    return res.status(401).send({
      message: 'unauthenticated'
  });
  }
  try {
    const user = await User.findOne({ email: payload.email });
    const token = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        parent: user.parent,
        lastName: user.lastName,
        firstName: user.firstName
      },
      'somesupersecretkey',
      {
        expiresIn: '1h'
      }
    );
    const refreshToken = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        parent: user.parent,
        lastName: user.lastName,
        firstName: user.firstName
      },
      'somesupersecretkey',
      {
        expiresIn: '1w'
      }
    );
    res.cookie('refreshToken', refreshToken, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 })
    res.send({status: 200 , accessToken: token});

  } catch (error) {
    console.error(error);
  }
});


router.post('/register', async function (req, res, next) {
  try {
    const userDetails = req.body;
    const checkUser = await User.findOne({ email: req.body.email });
    if (checkUser) {
      return res.status(400).send({
        message: 'User alredy exist!'
    });
    }
    const hashedPassword = await bcrypt.hash(req.body.password, 12);
    const user = new User({
      email: req.body.email,
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      mobile: req.body.mobile,
      parent: req.body.parent,
      password: hashedPassword,
    });

    const result = await user.save();
    delete result.password;
  
    res.send({status: 200 , massege: `Hi ${result.firstName} You are registere now!`});

  } catch (error) {
    console.error(error);
  }
});


router.post('/login', async function (req, res, next) {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      throw new Error('User does not exist!');
    }
    const isEqual = await bcrypt.compare(req.body.password, user.password);
    if (!isEqual) {
      return res.status(400).send({
        message: 'Password is incorrect!'
      });
    }
    const token = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        parent: user.parent,
        lastName: user.lastName,
        firstName: user.firstName
      },
      'somesupersecretkey',
      {
        expiresIn: '1h'
      }
    );
    const refreshToken = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        parent: user.parent,
        lName: user.lName,
        fName: user.fName
      },
      'somesupersecretkey',
      {
        expiresIn: '1w'
      }
    );
    res.cookie('refreshToken', refreshToken, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 })
    res.send({status: 200 , accessToken: token});

  } catch (error) {
    console.error(error);
  }
});
module.exports = router;
