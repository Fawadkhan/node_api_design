import * as dotenv from 'dotenv'
dotenv.config()

import router from './router'
import app from './server';
app.listen(3000, () => { 
    console.log('Server running on port 3000');
});