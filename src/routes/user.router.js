const { getAll, create, getOne, remove, update, verifyEmail, login, getLoggedUser, reset_password, changePassword} = require('../controllers/user.controllers');
const express = require('express');

const userRouter = express.Router();
const verifyJWT=require("../utils/verifyJWT")

userRouter.route('/users')
    .get(verifyJWT, getAll)
    .post(create);


userRouter.route('/users/verify/:code')
    .get(verifyEmail)

userRouter.route("/users/login")
    .post(login)

userRouter.route("/users/me")
 .get(verifyJWT, getLoggedUser)

 userRouter.route("/users/reset_password")
    .post(reset_password)


userRouter.route("/users/reset_password/:code")
    .post(changePassword)

    
    
userRouter.route('/users/:id')
    .get(verifyJWT, getOne)
    .delete(verifyJWT, remove)
    .put(verifyJWT, update);



module.exports = userRouter;