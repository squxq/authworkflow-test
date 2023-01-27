module.exports = {
  host: "smtp.ethereal.email",
  port: 587,
  auth: {
    user: "teagan30@ethereal.email",
    pass: process.env.ETHEREAL,
  },
  tls: {
    rejectUnauthorized: false,
  },
}
