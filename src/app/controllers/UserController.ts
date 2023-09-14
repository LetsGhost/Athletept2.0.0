import { Request, Response } from "express";
import userService from "../services/UserService";
import path from "path";
import exercisePlanService from "../services/ExercisePlanService";

class UserController{
    async registerUser(req: Request, res: Response) {
        try {
            const { email, password } = req.body;

            if (!req.file) {
                return res.status(400).json({ message: 'No file provided' });
            }

            const uploadedFilePath = path.join('../public/uploads', req.file.filename);

            // Register the user
            const newUser = await userService.registerUser({ email: email as string, password: password as string });

            // Create exercise plan from Excel file
            await exercisePlanService.createExercisePlanFromExcel(newUser._id, uploadedFilePath);

            res.status(201).json({ message: 'User registered successfully' });
        } catch (error) {
            console.log(error)
            res.status(400).json({ message: 'Registration failed', error: error });
        }
    };

    async deleteUser(req: Request, res: Response) {
        try {
            const { userId } = req.params;

            await userService.deleteUserById(userId);

            res.status(201).json({ message: 'User deleted successfully' });
        } catch (error) {
            console.log(error)
            res.status(400).json({ message: 'Delete failed', error: error });
        }
    }

    async getUserById(req: Request,res: Response ) {
        try {
            const { userId } = req.params;

            const user = await userService.getUserById(userId);
            res.status(200).json(user);
        } catch (error) {
            res.status(404).json({ message: error });
        }
    }
}

export default new UserController();