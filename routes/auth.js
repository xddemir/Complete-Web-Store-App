const express = require("express");
const { check } = require("express-validator/check");

const authController = require("../controllers/auth");

const router = express.Router();

router.get("/login", authController.getLogin);

router.get("/signup", authController.getSignup);

router.post("/login", authController.postLogin);

router.post(
  "/signup",
  [
    check("email")
      .isEmail()
      .withMessage("Please Enter A Valid Email")
      .custom((value, { req }) => {
        if (value === "test@test.com") {
          throw new Error("This Email Address Is Forbidden.");
        }
        return true;
      }),
    body("password")
      .isLength({ min: 5 })
      .withMessage("Please enter a password with only numbers")
      .isAlphanumeric(),
  ],
  authController.postSignup
);

router.post("/logout", authController.postLogout);

router.get("/reset", authController.getReset);

router.post("/reset", authController.postReset);

router.get("/reset/:token", authController.getNewPassword);

router.post("/new-password", authController.postNewPassword);

module.exports = router;
