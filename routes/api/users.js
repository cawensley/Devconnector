const express = require('express');
const router = express.Router();
const {check, validationResult} = require('express-validator');
const User = require('../../Models/Users');
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');

//@route    POST api/users
//@desc     Register User
//@access   Public
router.post('/',[
    check('name','Name is required').not().isEmpty(),
    check('email','Please include a valid email').isEmail(),
    check('password','Please enter a password with 6 or more characters').isLength({min: 6})
    ],async (req,res)=>{
    const errors = validationResult(req);
    if(!errors.isEmpty()) {
        return res.status(400).json({errors: errors.array()})
    }
    const {name,email,password} = req.body;
    try {
        //See if user exists, dont want same user multiple times
        let user = await User.findOne({email});
        if(user) {
            return res.status(400).json({errors: [{msg: 'User already exists'}]})
        }
        //Get Users Gravatar
        const avatar = gravatar.url(email,{s:'200',r:'pg',d:'mm'});//s=size,r=rating,d=default option
        user = new User({name,email,avatar,password});
        //Encrypt Passord
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password,salt);
        await user.save();
        //Return jsonwebtoken
        const payload = { user: {id: user.id}}
        jwt.sign(
            payload,
            config.get('jwtSecret'),
            {expiresIn: 360000}, //In seconds, 3600 is 1 hour
            (err,token)=>{
                if(err) throw err;
                res.json({token})
            }
        );
    } catch(err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

module.exports = router;
