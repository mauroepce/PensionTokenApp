const morgan = require('morgan')
const express = require('express')
const cors = require('cors')

const app = express()

app.use(cors())
app.use(express.json())
app.use(morgan('dev'))

app.use('/api', require('./routes'))

module.exports = app
