import express from 'express';
import dotenv from 'dotenv';
dotenv.config();

// Multer config
import { upload } from '../../config/multerConfig.js';

// Import Middlewares
// Disable authentication for now
import authenticateRole from "../middleware/AuthenticateRole.js";
import authenticateToken from "../middleware/AuthenticateToken.js";
import asyncMiddleware from '../middleware/asynchroneMiddleware.js';

// Import Controllers
import userController from "../controllers/UserController.js";
import messageController from "../controllers/MessageController.js";
import protocolController from "../controllers/ProtocolController.js";
import exercisePlanController from "../controllers/ExercisePlanController.js";
import weekDisplayController from '../controllers/WeekDisplayController.js';
import checkInController from '../controllers/CheckInController.js';
import trainingDurationController from '../controllers/TrainingDurationController.js';
import adminController from '../controllers/AdminController.js';

// Import routes
const router = express.Router();

if(process.env.ENV === "production"){
    router.use(asyncMiddleware(authenticateRole.authenticateRole));
}

// User
router.post('/register', asyncMiddleware(userController.registerUser)); // Is Documented
router.get("/getUser/:userId", asyncMiddleware(userController.getUserById)) // Is Documented
router.delete("/deleteUser/:userId", asyncMiddleware(userController.deleteUser)) // Is Documented
router.get("/getAllUsers", userController.getAllUsers) // Is Documented
router.post("/createAdmin", userController.createAdmin) 
router.get("/getAdmins", userController.getAdmins) 
router.patch("/updateUserInfo/:userId", userController.updateUserInfo)

// Exercise plan
router.get("/getExercisePlan/:userId", asyncMiddleware(exercisePlanController.getExercisePlan) ) // Is Documented
router.post("/createExercisePlan/:userId", upload.fields([{name: "exerciseFile", maxCount: 1}, {name: "warmupFile", maxCount: 1}]), asyncMiddleware(exercisePlanController.createExercisePlan)) // Is Documented
router.post("/createExercisePlanOnly/:userId", upload.fields([{name: "exerciseFile", maxCount: 1}]), asyncMiddleware(exercisePlanController.createExercisePlanOnly)) // Is Documented
router.post("/createWarmupOnly/:userId", upload.fields([{name: "warmupFile", maxCount: 1}]), asyncMiddleware(exercisePlanController.createWarmupOnly))

// Message
router.post("/createMessage/:userId", messageController.createMessage) // Is Documented
router.get("/getAllMessages/:userId", messageController.getAllMessagesFromUser) // Is Documented
router.delete("/deleteMessageById/:messageId", messageController.deleteMessageById) // Is Documented

// Protocol
router.get("/getProtocol/:userId", asyncMiddleware(protocolController.getProtocol)) // Is Documented

// WeekDisplay
router.post("/createWeekDisplay/:userId", weekDisplayController.createWeekDisplay) // Is Documented
router.get("/getWeekDisplay/:userId", weekDisplayController.getWeekDisplay) // Is Documented
router.patch("/updateWeekDisplay/:userId", weekDisplayController.updateWeekDisplay) // Is Documented

// CheckIn
router.get("/getCheckIn/:userId", checkInController.getCheckIn) // Is Documented

// TrainingDuration
router.get("/getTrainingDuration/:userId", trainingDurationController.getTrainingDuration) // Is Documented

// Admin
router.get("/runDbSchedule", adminController.runDbSchedule)

export default router;
