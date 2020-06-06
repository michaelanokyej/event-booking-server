const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken")

const User = require("../../models/user");

module.exports = {
  createUser: async (args) => {
    try {
      // first verify that user is not already in database
      const existingUser = await User.findOne({ email: args.userInput.email });
      if (existingUser) {
        throw new Error("User exists already");
      }
      const hashedPassword = await bcrypt.hash(args.userInput.password, 12);
      const user = new User({
        email: args.userInput.email,
        password: hashedPassword,
      });
      const result = await user.save();
      return { ...result._doc, password: null, _id: result.id };
    } catch (err) {
      throw err;
    }
  },
  login: async ({email, password}) => {
    try {
      const user = await User.findOne({email})
      if(!user) {
        throw new Error("User not found!")
      }
      // bcrypt compares the incoming string with
      // our hashed password in the DB
      const isEqual = await bcrypt.compare(password, user.password)
      if(!isEqual) {
        throw new Error("Password is incorrect")
      }
      const token = await jwt.sign({
        userId: user.id, email: user.email
      }, "somesupersecretkey",{
        expiresIn: "1h"
      })
      return {
        userId: user.id,
      token: token,
      tokenExpiration: 1
      }
    } catch (error) {
      throw error
    }
  }
};
