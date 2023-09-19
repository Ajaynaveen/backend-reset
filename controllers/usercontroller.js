const User=require('../models/user')
const bcrypt=require('bcrypt')
const jwt=require('jsonwebtoken')
const SECRET_KEY="forgetresetpassword"
const sendPasswordResetEmail=require('../sendPasswordResetEmail')

//CRETE USER

const createuser=async(req,res)=>{
    try{
        const {fname,email,password,cpassword}=req.body

        const existinguser=await User.findOne({email})

        if(existinguser){
            return res.status(404).json({ message: 'Email already registered' })
        }
        if(password!=cpassword){
            return 	res.status(501).send('Passwords do not match!')
        }
        const newuser=new User({
            fname , email  : email   .toLowerCase(), password,cpassword});
        await newuser.save();

        
    res.json({ message: 'User registered successfully' });

    }
    catch(error){
        console.error('Error:', error);
    res.status(500).json({ message: 'Internal server error' });

    }

}

const loginuser=async(req,res)=>{
    try{
        const {email,password}=req.body;

        const user=await User.findOne({email})
        if(!user){
            return res.status(422).json({message:'Invalid Credentials'})
        }
        const matchpassword=await bcrypt.compare(password,user.password)

        if(!matchpassword){
            return res.status(422).json({message:"invalid password"})
        }

        const token=jwt.sign({userId:user._id,fname:user.fname,email:user.email},SECRET_KEY,{expiresIn:'1hr'})
        localStorage.setItem('token', token);

        res.json(token);

       

    }
    catch(error){
        console.error('Error:', error);
        res.status(500).json({ message: 'Internal server error' });

    }

}

const userprofile=async(req,res)=>{
    try{
        const userId=req.userId;
        const user=await User.findById(userId,'name email')
        res.json(user)
    }catch(error){
        console.error('error fetching user profile',error)
        res.status(500).json({message:"internal server error"})

    }

}

const forgetpassword=async(req,res)=>{
    // Add this route to initiate password reset

    const { email } = req.body;
  
    try {
      const user = await User.findOne({ email });
  
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      // Generate a reset token and set an expiration time
      const resetToken = jwt.sign({ email }, "forgetresetpassword", { expiresIn: '1h' });
    //   console.log(resetToken)
      user.resetPasswordToken = resetToken;
      user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
  
      await user.save();

  
      // Send an email with the reset link (implement this function)
      sendPasswordResetEmail(email, resetToken);
  
      res.json(resetToken);
    } catch (error) {
      console.error('Error sending password reset email:', error);
      res.status(500).json({ message: 'Internal server error' });
    }

  
}


const resetpassword=async(req,res)=>{
    // Add this route to reset the password using the token

    const { token } = req.params;
    const { newPassword } = req.body;
  
    try {
      const user = await User.findOne({
        resetPasswordToken: token,
        resetPasswordExpires: { $gt: Date.now() },
      });
  
      if (!user) {
        return res.status(400).json({ message: 'Invalid or expired token' });
      }
  
      // Update the user's password and clear the reset token
      user.password = await bcrypt.hash(newPassword, 10);
      user.resetPasswordToken = undefined;
      user.resetPasswordExpires = undefined;
  
      await user.save();
  
      res.json({ message: 'Password reset successfully' });
    } catch (error) {
      console.error('Error resetting password:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
 
  

}

module.exports={createuser,loginuser,userprofile,forgetpassword,resetpassword}





