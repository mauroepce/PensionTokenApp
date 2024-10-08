const jwt = require("jsonwebtoken")
require('dotenv').config();
const JWT_SECRET = process.env.JWT_SECRET

/**
 * We need to pass the user object
 * @param {*} user 
 */

console.log('JWT_SECRET',JWT_SECRET);


const tokenSign = async (user) => {
    const sign = jwt.sign(
        {
            _id: user._id,
            role: user.role
        },
        JWT_SECRET,
        {
            expiresIn: "2h"
        }
    );

    return sign;
};

/**
 * We need to pass the session token JWT
 * @param {*} tokenJwt 
 * @returns 
 */

const verifyToken = async (tokenJwt) => {
    try {
        return jwt.verify(tokenJwt,JWT_SECRET)
    } catch (error) {
        return null
    }
}

module.exports = {
    tokenSign,
    verifyToken
}