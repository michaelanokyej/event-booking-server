const jwt = require("jsonwebtoken")

module.exports = (req, res, next) => {
  const authHeader = req.get("Authorization");
  if(!authHeader) {
    req.isAuth = false;
    return next()
  }
  // Token will look like Authorization: Bearer #tokenValue 
  const token = authHeader.split(" ")[1];
  if(!token || token === "") {
    req.isAuth = false;
    return next()
  }
  let decodedToken;
  try {
      // we verify the token by using the incoming
  // token and the secret token assigned when creating token
  decodedToken = jwt.verify(token, "somesupersecretkey")
  } catch (error) {
    req.isAuth = false;
    next()
  }
  if(!decodedToken) {
    req.isAuth = false;
    next()
  }
    req.isAuth = true;
    req.userId = decodedToken.userId
    next()
}