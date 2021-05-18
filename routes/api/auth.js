const express = require('express');
const router = express.Router();
const auth = require('../../middleWare/auth');
const User = require('../../Models/Users');
const {check, validationResult} = require('express-validator');
const jwt = require('jsonwebtoken');
const config = require('config');
const bcrypt = require('bcryptjs');

//@route    GET api/auth
//desc return User info if a user exists
//@access   Public
router.get('/',auth, async (req,res)=>{
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error')
    }
});

//@route    POST api/auth
//desc authenticate user & get token
//@access   Public
router.post('/',[
    check('email','Please include a valid email').isEmail(),
    check('password','Password is required').exists()
],async (req,res)=>{
    const errors = validationResult(req);
    if(!errors.isEmpty()) {
        return res.status(400).json({errors: errors.array()})
    }
    const {email,password} = req.body;
    try {
        //See if user exists, dont want same user multiple times
        let user = await User.findOne({email});
        if(!user) {
            return res.status(400).json({errors: [{msg: 'Invalid Credentials'}]})
        }
        //check saved hashpassword is same as user entered password
        const isMatch = await bcrypt.compare(password,user.password);
        if(!isMatch) {
            return res.status(400).json({errors: [{msg: 'Invalid Password'}]})
        }

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
