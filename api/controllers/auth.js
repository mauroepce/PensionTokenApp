const axios = require('axios');
const { encrypt } = require("../utils/handlePassword");
const { tokenSign, verifyToken } = require('../utils/handlejwt');
const { compare } = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { sendVerificationEmail } = require('../utils/emailNotification');
const users = require('../models/users');
require('dotenv').config();

const USER_REGISTER_URL = process.env.USER_REGISTER_URL;
const CHECK_USER_EMAIL = process.env.CHECK_USER_EMAIL;
const STORE_VERIFICATION_CODE= process.env.STORE_VERIFICATION_CODE;
const VERIFY_USER_URL = process.env.VERIFY_USER_URL;

const authController = {

    /**
     *  Controller for registering a user
     * @param {*} req 
     * @param {*} res 
     */

    registerController: async (req, res) => {
        try {
            // Receive the user data
            const newUser = req.body;
            const { email } = req.body;
            
            const password = await encrypt(newUser.password);
            const payload = { ...newUser, password };
    
            // Verify if the email is already registered
            const existingUser = await users.findOne({ email });
    
            if (existingUser !== null) {
                if (existingUser.isVerified) {
                    return res.status(400).send({ error: "This email already contains a registered account" });
                }
    
                const currentTime = new Date().getTime();
                const lastSentTime = existingUser.verificationSentAt ? existingUser.verificationSentAt.getTime() : 0;
                const timeDifference = currentTime - lastSentTime;
                const sixHoursInMillis = 6 * 60 * 60 * 1000;
                
                // Check if the user has tried to verify the email more than 3 times
                if (existingUser.verificationAttempts >= 3) {
                    if (timeDifference < 5 * 60 * 1000) { // 5 minutes
                        return res.status(400).send({existingUser, error: "Too many verification attempts. Please wait for 5 minutes before trying again." });
                    } else {
                        await users.findByIdAndUpdate(existingUser._id, { $set: { verificationAttempts: 0 } });
                    }
                }
    
                // Check if the user has tried to verify the email in the last 6 hours
                if (timeDifference >= sixHoursInMillis) {
                    const verificationToken = uuidv4();
                    const updatedUser = await users.findByIdAndUpdate(
                        existingUser._id,
                        { verificationToken, verificationSentAt: new Date(), $inc: { verificationAttempts: 1 } },
                        { new: true }
                    );
    
                    await sendVerificationEmail(updatedUser.email, updatedUser.verificationToken);
                    return res.status(400).send({ userData: updatedUser, error: "Looks like you've already registered with this email! A new verification email has been sent. Please check your inbox to verify." });
                } else {
                    await users.findByIdAndUpdate(existingUser._id, { $inc: { verificationAttempts: 1 } });
                    return res.status(400).send({ userData: existingUser, error: "Looks like you've already registered with this email! Please check your inbox to verify." });
                }
            }
    
            // Register the user on DB 
            const userCreated = await users.create(payload);
            userCreated.set("password", undefined, { strict: false });
            
            // Generate verification token
            const verificationToken = uuidv4();
    
            // Store the verification token in the DB
            const storeVerificationTokenData = await users.findByIdAndUpdate(
                userCreated._id,
                { verificationToken, verificationSentAt: new Date(), verificationAttempts: 1 },
                { new: true }
            );
    
            // Check if the token was stored
            const tokenStored = storeVerificationTokenData.verificationToken;
            
            // Send verification email if the token was stored
            if (tokenStored) {
                await sendVerificationEmail(storeVerificationTokenData.email, tokenStored);
            }
    
            res.status(200).send({ data: userCreated, message: "User registered successfully"})
        } catch (error) {
            console.error(`Error while registering the "user" on DB: ${error.message}`);
            res.status(400).json({ error: error.message });
        }
    },

    /**
     *  Controller for login a user
     * @param {*} req 
     * @param {*} res 
     */

    loginController: async (req, res) => {
        try {
            const { email, password } = req.body;

            console.log("email", email);
            console.log("password", password);
            
            
    
            // Verificar si se proporciona email 
            if (!email) {
                return res.status(400).send({ error: "Please enter an email" });
            }
    
            // Verificar si se proporciona password
            if (!password) {
                return res.status(400).send({ error: "Please enter a password" });
            }
    
            // Verificar si el usuario existe en la base de datos
            const checkUser = await users.findOne({ email }).select("+password");
            if (!checkUser) {
                return res.status(400).send({ error: "There's no user with this email" });
            }
    
            if (!checkUser.isVerified) {
                return res.status(400).send({ error: "Please verify your email before login" });
            }
    
            // Verificar si la contraseña es correcta
            const checkPassword = await bcrypt.compare(password, checkUser.password);
            if (!checkPassword) {
                return res.status(400).send({ error: "The password doesn't match" });
            }
    
            // Generar el token JWT
            const token = await tokenSign(checkUser);
    
            // Eliminar el campo password del usuario antes de enviar la respuesta
            checkUser.password = undefined;
    
            // Enviar la respuesta con el token y los datos del usuario
            res.status(200).send({
                data: {
                    token,
                    user: checkUser
                },
                message: "User logged in successfully"
            });
    
        } catch (error) {
            console.error(`Error while trying to log the user: ${error.message}`);
            res.status(500).json({ error: "Internal Server Error" });
        }
    },

    /**
     * Controller for verify user token
     * @param {*} req 
     * @param {*} es 
     */
    verifyUserController: async (req, res) => {
        try {
            const token = req.query.token;
            console.log("Received token:", token);
            
            if (!token) {
                return res.status(400).send({ error: "Token not provided" });
            }
    
            // Buscar al usuario en la base de datos utilizando el token de verificación
            const user = await users.findOne({ verificationToken: token });
    
            if (!user) {
                return res.status(400).send({ error: "Invalid or expired token" });
            }
    
            // Calcular el tiempo de expiración (2 horas en milisegundos)
            const expirationTime = 2 * 60 * 60 * 1000; // 2 horas
            const currentTime = new Date().getTime();
            const tokenSentTime = new Date(user.verificationSentAt).getTime();
    
            // Verificar si el token ha expirado
            if (currentTime - tokenSentTime > expirationTime) {
                return res.status(400).send({ error: "Token has expired" });
            }
    
            // Si no ha expirado, marcar al usuario como verificado
            user.isVerified = true;
            user.verificationToken = null;  // Eliminar el token después de verificar
            await user.save();
    
            res.status(200).send({ message: "User verified successfully", user });
    
        } catch (error) {
            console.error(`Error while trying to verify user on DB: ${error.message}`);
            res.status(400).json({ error: "An error occurred while verifying the token" });
        }
    }

}




module.exports =  authController;
