'use strict';

const bcrypt = require('bcrypt');
const jwt=require('jsonwebtoken')
require('dotenv').config()
const SECRET=process.env.SECRET;
console.log(SECRET,'jfdsakkkkkkkkkkkkkkkkkkl')
const userSchema = (sequelize, DataTypes) => {
  const model = sequelize.define('User', {
    username: { type: DataTypes.STRING, allowNull: false, unique: true },
    password: { type: DataTypes.STRING, allowNull: false, },
    token: {
      type: DataTypes.VIRTUAL,
      get() {
        return jwt.sign({ username: this.username },SECRET);
      }
    }
  });
  this.hashPassword=async (password)=>{
const hashed=await bcrypt.hash(password, 10);
return hashed;
}
  model.beforeCreate('hashing password before creation',async(user,options)=>{
    const hashedPassword=await this.hashPassword(user.password);
    user.password=hashedPassword;
  })
 
  // Basic AUTH: Validating strings (username, password) 
  model.authenticateBasic = async function (username, password) {
    const user=await this.findOne({username});
    console.log(user,'ussssssssssssssssssssssssssssser')
    const valid = await bcrypt.compare(password, user.password)
    if (valid) { return user; }
    throw new Error('Invalid User');
  }

  // Bearer AUTH: Validating a token
  model.authenticateToken = async function (token) {
    try {
      const parsedToken = jwt.verify(token, process.env.SECRET);
      const user = this.findOne({ username: parsedToken.username })
      if (user) { return user; }
      throw new Error("User Not Found");
    } catch (e) {
      throw new Error(e.message)
    }
  }

  return model;
}

module.exports = userSchema;
