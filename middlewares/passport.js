const User = require("../models/User");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");
const JwtStrategy = require("passport-jwt").Strategy;
const { fromAuthHeaderAsBearerToken } = require("passport-jwt").ExtractJwt;
require("dotenv").config();

const localStrategy = new LocalStrategy(
  {
    usernameField: "username", //because we used username if we said phonenumber we will put phonenumber
    passwordField: "password", //same applies to password
  },
  async (username, password, next) => {
    try {
      const user = await User.findOne({ username: username });
      if (!user) {
        return next({ msg: "Username or password is wrong!" });
      }
      const checkPassword = await bcrypt.compare(password, user.password);
      if (checkPassword == false) {
        return next({ msg: "Username or password is wrong!" });
      }
      next(false, user); //req.user
    } catch (error) {
      next(error);
    }
  }
);

const jwtStrategy = new JwtStrategy(
  {
    jwtFromRequest: fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET,
  },
  async (payload, next) => {
    // here you check if token is exp

    // console.log("EXP:", payload.exp, "Time now", Date.now() / 1000);

    if (Date.now() / 1000 > payload.exp) {
      return next({ msg: "Token expiered!" });
    }

    const user = await User.findById(payload._id);

    if (!user) {
      return next({ msg: "User not found!" });
    }

    next(false, user); // req.user
  }
);

module.exports = { localStrategy, jwtStrategy };
