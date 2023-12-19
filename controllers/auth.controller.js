//Here logic  for register signin signout forget and reset is done....

const { authModel } = require("../models/auth.model");
const { passwordResetTokenModel } = require("../models/prToken.model");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { sendEmail } = require("../utils/sendEmail");


//Express.js route handler for handling user registration.
const register = async (req, res) => {
    const payload = req.body;//extracts the request body(user registration datas to payload variable)
    try {
        const existingUser = await authModel.findOne({ username: payload.username}); //Check if user exist else it continue..
        if (!existingUser) {
            const hashedPassword = await bcrypt.hash(payload.password, 10);
            payload.hashedPassword = hashedPassword;
            delete payload.password;  //plain text password is deleted from the payload for security reasons
            const newUser = await new authModel(payload).save(); // A new user document is created using the authModel, and it is saved to the database using the save method.

            return res.status(201).send({ message: "User registered successfully", userID: newUser._id });
        }
        res.status(409).send({ message: "An account is already registered with this Email address. If you don't remember the password, try to reset the password in the login page or try to register with another Email address" });
    } catch (error) {
        res.status(500).send({ message: "Internal server error", error: error });
    }
};

//Express.js route handler for handling user sign-ins.
const signin = async (req, res) => {
    const { username, password } = req.body; //extracts login credentials from body..
    try {
        if(username && password) {
            let existingUser = await authModel.findOne({ username: username });
            if (existingUser) {
                const isPasswordMatch = await bcrypt.compare(password, existingUser.hashedPassword);//bcrypt.compare checks if the provided password matches the stored hashed password for that user.
                if(isPasswordMatch) {
                    const token = jwt.sign({ _id: existingUser._id }, process.env.JWT_SECRET); //JWT created with  user's ID and the provided secret key.
                    res.cookie("accessToken", token, { httpOnly: true, sameSite: "none", secure: true, expire: new Date() + 86400000 });//sets the JWT as a cookie named "accessToken" in the HTTP response..(expiration time is set to 24 hours from the current date)

                    existingUser = existingUser.toObject(); //Before sending the response it converts the Mongoose document to a plain JavaScript object
                    delete existingUser.hashedPassword; //removes the hashedPassword field for security reasons.
                    return res.status(201).send({ message: "User signed-in successfully", user: existingUser });
                }
                return res.status(400).send({ message: "Invalid credentials" });
            }
            return res.status(400).send({ message: "User not registered" });
        }
        res.status(400).send({ message: "Credentials are required" });
    } catch (error) {
        res.status(500).send({ message: "Internal server error", error: error });
    }
};

//Express.js route handler for handling user sign-out.
const signout = async (req, res) => {
    try {
        res.clearCookie("accessToken");
        res.status(200).send({ message: "User signed-out successfully" });
    } catch (error) {
        res.status(500).send({ message: "Internal server error", error: error });
    }
};


//Express.js route handler for initiating the password reset process.
const forgotPassword = async (req, res) => {
    const { username } = req.body;
    try {
        if (username) {
            const getUser = await authModel.findOne({ username: username });
            if (getUser) {
                const getPRToken = await passwordResetTokenModel.findOne({ userId: getUser._id });
                if (getPRToken) {
                    await getPRToken.remove();//Removing Existing Password Reset Token if there..
                }
                const PRToken = crypto.randomBytes(32).toString("hex");
                const hashedPRToken = await bcrypt.hash(PRToken, 10);//Generating and Hashing a New Password Reset Token
                const newPRToken = await new passwordResetTokenModel({ userId: getUser._id, hashedPRToken: hashedPRToken }).save(); //Creating and Saving a New Password Reset Token
                const PRLink = `${process.env.CLIENT_URL}/reset-password?PRToken=${PRToken}&userId=${getUser._id}`;//Constructing Password Reset Link with token and userid(CLIENT URL:Deployed FE url or localhost url)
                sendEmail(getUser.username, "Password Reset Request", {firstName: getUser.firstName, PRLink: PRLink });//send reset mail with username, subject,and object containing user-specific data like the first name and the password reset link.
                
                return res.status(200).send({ message: "Email sent successfully" });
            }
            return res.status(400).send({ message: "User not registered" });
        }
        res.status(400).send({ message: "Username is required" }); 
    } catch (error) {
        res.status(500).send({ message: "Internal server error", error: error });
    }
};


//Express.js route handler for resetting user passwords.
const resetPassword = async (req, res) => {
    const { userId, PRToken, password } = req.body;//These parameters provided when making a request to reset the password.
    try {
        if (password) {  //It checks if the password is provided in the request
            const getPRToken = await passwordResetTokenModel.findOne({ userId: userId }); //It queries the database to find a password reset token associated with the provided 
            if (getPRToken) {  //If a password reset token is found
                const isValidPRToken = await bcrypt.compare(PRToken, getPRToken.hashedPRToken);//check PRToken provided with url link matches the hashed password reset token stored in the database.
                if (isValidPRToken) {
                    const hashedPassword = await bcrypt.hash(password, 10); //hashes the new password using bcrypt.hash...
                    const updatedUser = await authModel.findByIdAndUpdate( //updates the user's password in the authModel collection..
                        { _id: userId },
                        { $set: { hashedPassword: hashedPassword } }
                      );
                      if (!updatedUser) {
                        return res.status(400).send({ message: "Error while resetting password" });
                      }
                    // Use deleteOne to remove the document
                    await passwordResetTokenModel.deleteOne({ userId: userId }); //removeing used password reset token from the database.

                    return res.status(200).send({ message: "Password reset successfully" });
                }
                return res.status(400).send({ message: "Invalid token" });
            }
            return res.status(401).send({ message: "Invalid or expired token" });
        }
        res.status(400).send({ message: "Password is required" });
    } catch (error) {
        console.error("Error resetting password:", error);
        res.status(500).send({ message: "Internal server error", error: error });
    }
};

module.exports = { register, signin, signout, forgotPassword, resetPassword };
