import express from 'express'
import router from './router'
import morgan from 'morgan'
import cors from 'cors'
import { protect } from './modules/auth';
    

const app = express();

const customLogger = (message) => (req, res, next) => { 
    console.log(`Hello I am a : ${message}`)
    next()
}

app.use(cors())
app.use(morgan('dev'))
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(customLogger('Customer logger'))


app.get('/', (req, res) => {
    console.log('GET /');
    res.status(200)
    res.json({ message: 'Hello World' })
});

app.use('/api', protect, router)



export default app