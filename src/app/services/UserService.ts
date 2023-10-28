import UserModel from '../models/UserModel';
import {ExercisePlan} from "../models/ExercisePlanModel";
import {Message} from "../models/MessagModel";

interface RegistrationData {
    email: string;
    password: string;
}

class UserService{
    async registerUser(registrationData: RegistrationData, userInfo: object) {
        const { email, password } = registrationData;

        // Check if the email is already registered
        const existingUser = await UserModel.findOne({ email });
        if (existingUser) {
            throw new Error('Email already registered');
        }

        // Create a new user
        const newUser = new UserModel({
            email,
            password,
            userInfo
        });

        await newUser.save();
        return newUser;
    };

    async getUserById(userId: string) {
        const user = await UserModel.findById(userId);

        if(!user){
            throw new Error("User not found!")
        }

        return user;
    }

    async deleteUserById(userId: string) {

        const user = await UserModel.findById(userId);

        // Delete the previous exercise plan and messages everything related to the user
        if(user?.exercisePlan) {
            await ExercisePlan.findByIdAndDelete(user.exercisePlan);
        }

        /*
        if(user?.messages) {
            await Message.findByIdAndDelete(user.messages);
        }
        */

        if(!user){
            throw new Error("User not found!")
        }

        return user;
    }

    async getAllUsers() {
        const users = await UserModel.find();

        if(!users){
            throw new Error("Users not found!")
        }

        return users;
    }
}

export default new UserService();