const server = require('./app')
const dbConnect = require('./config/mongo')
require('dotenv').config()

const port = process.env.PORT || 3001

server.listen(port, () => {
    console.log(`PensionToken API running on server: ${port}`)
})

dbConnect()