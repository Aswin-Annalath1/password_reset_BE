//we create isAuth middleware function and pass b/w userRoute to get Authenticated...(Here routes are Authorized)

const jwt = require("jsonwebtoken");

exports.isAuth = (req, res, next) => {
  const { cookies } = req;
  if (cookies.accessToken) {  //extracting the accessToken from the request cookies
    const decryptedData = jwt.verify(cookies.accessToken, process.env.JWT_SECRET); //It verify and decrypt the accessToken using a secret key. The decrypted data typically contains the payload of the token, including user information..
    req.userId = decryptedData._id;
    if (req.userId) {
      return next();//it calls the next middleware function indicating that the user is authenticated.
    }
    res.status(401).send({ message: "Unauthorized" });
  }
  res.status(401).send({ message: "Unauthorized" });
};

