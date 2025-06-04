import express from "express";
import passport from "passport";
import {
  register,
  loginWithEmail,
   loginWithPhone,
  loginWithMdrId,
  logout,
  resetPassword,
  getProfile,
} from "../controllers/auth.controller";
import { authenticateToken } from "../middlewares/auth.middleware";

const router = express.Router();

router.post("/register", register);
router.post('/login/email', loginWithEmail);
router.post('/login/phone',loginWithPhone);
router.post('/login/mdrId',loginWithMdrId)
// router.post("/login", login);
router.post("/logout", logout);
router.post("/reset-password", resetPassword);
router.get("/profile", authenticateToken, getProfile);

// Google Auth Routes
router.get("/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

router.get("/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    // If using JWT, you can generate token here
    res.send("Google login success");
  }
);

export default router;
