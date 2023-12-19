//Here this route handler retrieves user information based on the user ID...

const { authModel } = require("../models/auth.model"); //represent user authentication data in a DB

exports.getUser = async (req, res) => {  //Route Handler Function
  try {
    const { userId } = req; //It extracts the userId from the request object(from authentication middleware.)
    let user = await authModel.findById(userId);
    if (user) {
      user = user.toObject(); //converts the Mongoose document to a plain JavaScript object
      delete user.hashedPassword; //removing the hashedPassword field (for security reasons)

      return res.status(200).send({ success: true, user: user }); //sends a successful response with the user information 
    }
    res.status(400).send({ success: false, message: "User does not exist" });
  } catch (error) {
    res.status(500).send({ message: "Internal Server Error", error: error });
  }
};

