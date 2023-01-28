const router = require("express").Router()

const { authenticateUser } = require("../middleware/authentication")

const {
  register,
  handleTokens,
  login,
  logout,
  verifyEmail,
  forgotPassword,
  resetPassword,
} = require("../controllers/authController")

router.get("/token", handleTokens)

router.post("/register", register)
router.post("/login", login)
router.delete("/logout", authenticateUser, logout)
router.post("/verify-email", verifyEmail)
router.post("/forgot-password", forgotPassword)
router.post("/reset-password", resetPassword)

module.exports = router
