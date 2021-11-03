const User = require('../models/User')
const bcrypt = require('bcrypt')
const createUserToken = require('../helpers/create-token-user')

module.exports = class UserController{

    static async register(req, res){

        const { name, email, phone, password, confirmpassword } = req.body
        if (!name) {
            res.status(422).json({message: 'O nome é obrigatorio'})
            return
        }

        if (!email) {
            res.status(422).json({message: 'O email é obrigatorio'})
            return
        }

        if (!phone) {
            res.status(422).json({message: 'O telefone é obrigatorio'})
            return
        }

        if (!password) {
            res.status(422).json({message: 'A senha é obrigatorio'})
            return
        }

        if (!confirmpassword) {
            res.status(422).json({message: 'A senha de confirmação é obrigatorio'})
            return
        }

        if (password !== confirmpassword){
            res.status(422).json({message: 'A senha e a confirmação de senha precisam ser iguais'})
        }

        // check email if user exists

        const userExists = await User.findOne({ email: email})


        if(userExists){
            res.status(422).json({
                message: 'Por Favor, utilize outro e-mail',
            })
            return
        }

        const salt = await bcrypt.genSalt(12)
        const passwordHash = await bcrypt.hash(password, salt)

        const user = new User({
            name: name,
            email: email,
            phone: phone,
            password: passwordHash,
        })

        try {

            const newUser = await user.save()

            await createUserToken(newUser, req, res)

            return
        }catch(error) {
            res.status(500).json({message: error})
        }
    }

    // create - login
    static async login(req, res){
    
        const {email, password} = req.body

        if(!email){

            res.status(422).json({ message: 'O e-mail é obrigatorio' })
            return

        }

        if(!password){

            res.status(422).json({message: "O e-mail é obrigatório"})
            return

        }


        // exists user
        const user = await User.findOne({ email: email})


        if(!user){
            res.status(422).json({

                message: 'Por favor faça um cadastro',
            })
            return
        }

        const truePassword = bcrypt.compare(password, user.password)

        if(!truePassword){

            res.status(422).json({ 

                message: "Senha Inválida",

            })

            return

        }

        //

        await createUserToken(user, req, res)
    }

}
