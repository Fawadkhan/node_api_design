import jwt from "jsonwebtoken";

import * as bcrypt from "bcrypt";

export const comparePasswords = (password, hash) => {
  return bcrypt.compare(password, hash);
};

export const hashPassword = (password) => {
  return bcrypt.hash(password, 5);
};


export const createJWT = (user) => {
  const token = jwt.sign(
    { id: user.id, username: user.username },
    process.env.JWT_SECRET
  );
  return token;
};

export const protect = (req, res, next) => { 
    const bearer = req.headers.authorization
    if(!bearer) {
        res.status(401)
        res.json({message: 'No token found'})
        return
    }
    
    const[, token] = bearer.split(' ')

    if(!token) {
        res.status(401)
        res.json({message: 'No token found'})
        return
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET)
        req.user = decoded
        next()
        return
    } catch (error) { 
        console.error(error)
        res.status(401)
        res.json({message: 'Invalid token'})
        return
    }
}