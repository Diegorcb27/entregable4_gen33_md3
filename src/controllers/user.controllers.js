const catchError = require('../utils/catchError');
const User = require('../models/User');
const bcrypt = require('bcrypt');
const nodemailer = require("nodemailer");
const sendEmail = require("../utils/sendEmail");
const EmailCode = require('../models/EmailCode');
const jwt = require("jsonwebtoken")   

const getAll = catchError(async(req, res) => {
    const results = await User.findAll();
    return res.json(results);
});

const create = catchError(async(req, res) => {
    const {email, firstName, lastName, frontBaseUrl}=req.body


    if(req.body.password==="")  return res.status(401).json({error: "contraseña no puede estar vacio"})
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    // guardamos el usuario, le decimos que la contraseña es la encriptada

const result = await User.create({...req.body, password: hashedPassword})
const code = require('crypto').randomBytes(32).toString('hex')
const link = `${frontBaseUrl}/${code}`

await EmailCode.create({
    code: code, 
    userId: result.id
})

await sendEmail({
    to: email, // Email del receptor
    subject: "Verificate email for user app", // asunto
    html: `
    <h1>HELLO ${firstName} ${lastName}</h1>
    <a href="${link}">${link}</a>
    <p>Thanks for sign up in user app</p>
    `// texto
})
return res.status(201).json(result);
});

const getOne = catchError(async(req, res) => {
    const { id } = req.params;
    const result = await User.findByPk(id);
    if(!result) return res.sendStatus(404);
    return res.json(result);
});

const remove = catchError(async(req, res) => {
    const { id } = req.params;
    await User.destroy({ where: {id} });
    return res.sendStatus(204);
});

const update = catchError(async(req, res) => {
    const { id } = req.params;
    const {email, password, firstName, lastName, country, image}=req.body
    const result = await User.update(
        {email, password, firstName, lastName, country, image},
        { where: {id}, returning: true }
    );
    if(result[0] === 0) return res.sendStatus(404);
    return res.json(result[1][0]);
});

//verificacion del email
const verifyEmail=catchError(async(req, res)=>{
    const {code}=req.params
    const emailCode = await EmailCode.findOne({   //almacena el codigo del usuario del email
        where: {code}
    }) 

    if(!emailCode) return res.status(401).json({message: "Codigo invalido"})
    const user=await User.update(

        {isVerified: true},   //podemos actualizar un campo

        {where: {id: emailCode.userId}, returning: true}) 
    
        await emailCode.destroy() //borra el codigo de la tabla

    return res.json(user)
})



//login

const login=catchError(async(req, res)=>{
    const {email, password}=req.body
    const user=await User.findOne({where: {email}})
    if(!user) return res.status(401).json({error: "invalid credential"})
//comparamos contraseñas

const isValid=await bcrypt.compare(password, user.password)
if(!isValid) return res.status(401).json({error: "invalid credentials"})


if(user.isVerified===false) return res.status(401).json({error: "usuario sin verificar"})

const token = jwt.sign(
    {user},
    process.env.TOKEN_SECRET,
   { expiresIn: '1d' }
)

return res.json({user, token});

})

const getLoggedUser=catchError(async(req, res)=>{
    return res.json(req.user)
})

const reset_password=catchError(async(req, res)=>{
    const {email, frontBaseUrl}=req.body
    const user= await User.findOne({where: {email: email}})
    if(!user) return res.status(401).json({error: "email incorrecto"})
    const code = require('crypto').randomBytes(32).toString('hex')
    const link = `${frontBaseUrl}/${code}`

    await EmailCode.create({
        code: code, 
        userId: user.id
    })

    await sendEmail({
        to: email, // Email del receptor
        subject: "Password reset", // asunto
        html: `
        <h1>HELLO ${user.firstName} ${user.lastName}</h1>
    <a href="${link}">${link}</a>      
        <p>Dale click para resetar tu contraseña</p>
        `// texto
    })

return res.sendStatus(200)

})


const changePassword=catchError(async(req, res)=>{
    const {password}=req.body
    const {code}=req.params  //codigo para verificar el usuario

    const emailCode = await EmailCode.findOne({   //almacena el codigo del usuario del email
        where: {code}
    }) 

    if(!emailCode) return res.status(401).json({message: "este codigo no es valido"})
    const encriptedPassword = await bcrypt.hash(password, 10);

    await User.update(
    {password: encriptedPassword},
    {where: {id: emailCode.userId}}
    ) 


    await emailCode.destroy()

    return res.sendStatus(200)
})

module.exports = {
    getAll,
    create,
    getOne,
    remove,
    update,
    verifyEmail,
    login,
    getLoggedUser,
    reset_password,
    changePassword
}