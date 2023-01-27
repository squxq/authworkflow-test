const router = require("express").Router()

// const { authenticateUser } = require("../middleware/authentication")

const { register } = require("../controllers/authController")

router.post("/register", register)

module.exports = router
