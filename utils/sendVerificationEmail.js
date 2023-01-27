const sendEmail = require("./sendEmail")

const sendVerificationEmail = async ({
  name,
  email,
  verificationToken,
  origin,
}) => {
  const verifyEmail = `${origin}/user/verify-email?token=${verificationToken}&email=${email}`

  const message = `<p>Please confirm your e-mail by clicking on the following link: <a href="${verifyEmail}>Verify E-mail</a></p>`

  return sendEmail({
    to: email,
    subject: "Email confirmation",
    html: `<h4>Hello ${name}</h4> ${message}`,
  })
}

module.exports = sendVerificationEmail
