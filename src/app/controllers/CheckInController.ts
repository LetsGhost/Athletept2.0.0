import { Request, Response } from 'express';
import CheckInService from '../services/CheckInService'; // May need to be changed to CheckInService because the renamed file doesn't get recognized

class CheckInController {
    async createCheckIn(req: Request, res: Response){
        try{
            const {userId} = req.params

            const {success, code, message, checkIn} = await CheckInService.createCheckIn(userId, req.body)

            res.status(code).json({success, message, checkIn})
        } catch(err){
            console.log("Error while creating check-in in CheckInController.createCheckIn: ", err)
            res.status(500).json({cuccess: false, message: "Internal server error"})
        }
    }

    async getCheckIn(req: Request, res: Response){
        try{
            const {userId} = req.params

            const {success, code, message, checkIn} = await CheckInService.getCheckIn(userId)

            res.status(code).json({success, message, checkIn})
        } catch(err){
            console.log("Error while getting check-in in CheckInController.getCheckIn: ", err)
            res.status(500).json({cuccess: false, message: "Internal server error"})
        }
    }
}

export default new CheckInController();