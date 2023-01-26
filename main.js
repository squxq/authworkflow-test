require("dotenv").config()
// instead of patching all methods on an express Router, it wraps the Layer property in one place
require("express-async-errors")

// express
const express = require("express")
const app = express()

// packeges
// morgan is used to log HTTP requests and errors, and simplifies the process - creates access tokens (digital footprints) that record the history of page requests made to the server
const morgan = require("morgan")
const cookieParser = require("cookie-parser")
// rate limit used to limit repeated requests to public APIs such as password reset
const rateLimiter = require("express-rate-limit")
// helmet helps to secure Express apps by setting various HTTP headers
// These headers
/*Content-Security-Policy: default-src 'self';base-uri 'self';font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src 'self';script-src-attr 'none';style-src 'self' https: 'unsafe-inline';upgrade-insecure-requests
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Origin-Agent-Cluster: ?1
Referrer-Policy: no-referrer
Strict-Transport-Security: max-age=15552000; includeSubDomains
X-Content-Type-Options: nosniff
X-DNS-Prefetch-Control: off
X-Download-Options: noopen
X-Frame-Options: SAMEORIGIN
X-Permitted-Cross-Domain-Policies: none
X-XSS-Protection: 0
*/
const helmet = require("helmet")
// xss protects from xss attacks - injection if client-side scripts into web pages viewed by other users - 84% securiry vulnerabilities
const xss = require("xss-clean")
// cors allows various users to access the server
const cors = require("cors")
// searches for keys that have prohibited characters from req.body / req.query / req.params and replaces / removes those - for attackers not to change the context of a database operation
const mongoSanitize = require("express-mongo-sanitize")

// database
const connectDB = require("./db/connect")

app.set("trust proxy", 1)
app.use(
  rateLimiter({
    windowMs: 15 * 60 * 1000,
    max: 60,
  })
)

app.use(helmet())
app.use(cors())
app.use(xss())
app.use(mongoSanitize())

// parses incoming JSON requests and puts the parsed data in req.body
app.use(express.json())
app.use(cookieParser(process.env.JWT_SECRET))

const port = process.env.PORT || 5000
const start = () => {
  connectDB(process.env.MONGO_URL, (err) => {
    if (err) {
      console.log(
        `Server is not connected to db and is not running. Err: ${err}`
      )
    } else {
      app.listen(port, (err) => {
        if (err) {
          console.log(
            `Server is connected to db but is not running. Err: ${err}`
          )
        } else {
          console.log(
            `Server is connected to db and listening on port: ${port}...`
          )
        }
      })
    }
  })
}

start()
