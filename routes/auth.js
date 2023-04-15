const express = require("express");
const { check, body } = require("express-validator/check");

const authController = require("../controllers/auth");
const User = require("../models/user");

const router = express.Router();

router.get("/login", authController.getLogin);

router.get("/signup", authController.getSignup);

router.post(
  "/login",
  [
    body("email")
      .isEmail()
      .withMessage("Please Enter A Valid Email"),
      body("password", "Password has to be valid")
      .isLength({ min: 5 })
      .withMessage("Email is incorrect, please retry")
      .isAlphanumeric()
  ],
  authController.postLogin
),
  router.post(
    "/signup",
    [
      check("email")
        .isEmail()
        .withMessage("Please Enter A Valid Email")
        .custom((value, { req }) => {
          return User.findOne({ email: value }).then((user) => {
            if (user) {
              return Promise.reject(
                "E-mail exists already, pleace enter a different one."
              );
            }
          });
        }),
      body("password")
        .isLength({ min: 5 })
        .withMessage("Please enter a password with only numbers")
        .isAlphanumeric(),
      body("confirmPassword").custom((value, { req }) => {
        if (value !== req.body.password)
          throw new Error("Passwords have to match.");
        return true;
      }),
    ],
    authController.postSignup
  );

router.post("/logout", authController.postLogout);

router.get("/reset", authController.getReset);

router.post("/reset", authController.postReset);

router.get("/reset/:token", authController.getNewPassword);

router.post("/new-password", authController.postNewPassword);

module.exports = router;
