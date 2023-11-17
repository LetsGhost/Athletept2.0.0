import UserModel from "../models/UserModel";
import {ProtocolExercisePlan} from "../models/ProtocolModel";
import {Document, Model} from "mongoose";
import {ExercisePlan} from "../models/ExercisePlanModel";
import timeUtils from "../utils/timeUtils";
import protocolUtils from "../utils/protocolUtils";
import { WeekDisplay } from "../models/WeekDisplayModel";

interface ProtocolExercise {
    Exercises: string;
    Weight: string;
    Repetitions: string;
}

interface Comment{
    Scale: number;
    Changes: string;
    Problems: string;
}

interface ProtocolExerciseDay {
    dayNumber: number;
    type: string;
    comment: Comment;
    exercises: ProtocolExercise[];
}

interface ProtocolExercisePlanDocument extends Document {
    exerciseDays: ProtocolExerciseDay[];
    createdAt: Date;
}

interface ProtocolExercisePlanModel extends Model<ProtocolExercisePlanDocument> {}

class ProtocolService{
    async createProtocol (userId: string, protocol: Record<string, ProtocolExercise>, comment: Record<string, any>) {
        try {

            const user = await UserModel.findById(userId);

            // Check if the user already has an protocol
            if (user?.protocolExercisePlan) {

                const user = await UserModel.findById(userId).populate("protocolExercisePlan").exec();
                const createdAt = (user?.protocolExercisePlan as any as ProtocolExercisePlanDocument).createdAt;

                // Calculates the date that should be one week ago
                const currentDate = new Date();

                const currentWeekNumber = timeUtils.getWeekNumber(currentDate);
                const createdAtWeekNumber = timeUtils.getWeekNumber(createdAt);

                // If the createdAt date is older than one week, move the protocol to the oldProtocol array and create a new one
                if(createdAtWeekNumber < currentWeekNumber) {
                    console.log("The protocol is older than one week")
                    await UserModel.findByIdAndUpdate(userId, {
                        $push: { oldProtocol: user?.protocolExercisePlan },
                        $unset: { protocolExercisePlan: "" }
                    });

                    const protocolExerciseDays = protocolUtils.processRequest(protocol, comment);

                    // Set the trainingDone property in the exercisePlan to true for the specific day of the protocol
                    const exercisePlan = await ExercisePlan.findById(user?.exercisePlan);
                    const exerciseDay = exercisePlan?.exerciseDays.find((day) => day.dayNumber === protocolExerciseDays[0].dayNumber);
                    if (exerciseDay) {
                        exerciseDay.trainingDone = true;
                        await exercisePlan?.save();
                    }

                    // Pushes the dayNumber of the protocol to the trainingDone array in the weekDisplay
                    const weekDisplay = await WeekDisplay.findById(user?.weekDisplay);
                    if(weekDisplay){
                        weekDisplay.trainingDone.push(protocolExerciseDays[0].dayNumber);
                        await weekDisplay.save();
                    }

                    if (user) {
                        const protocolExercisePlanDocument = new ProtocolExercisePlan({
                            exerciseDays: protocolExerciseDays
                        });

                        // Create and save the exercise plan using the ExercisePlan model
                        const createdExercisePlan = await ProtocolExercisePlan.create(protocolExercisePlanDocument);
                        user.protocolExercisePlan = createdExercisePlan._id;

                        await user.save();

                        return {
                            success: true,
                            code: 201,
                            newProtocol: createdExercisePlan,
                        };
                        
                    }

                    return {
                        success: false,
                        code: 500,
                        message: "Internal Server error"
                    }
                }

                const protocolExerciseDays = protocolUtils.processRequest(protocol, comment);

                // Set the trainingDone property in the exerciseplan to true for the specific day of the protocol
                const exercisePlan = await ExercisePlan.findById(user?.exercisePlan);
                const exerciseDay = exercisePlan?.exerciseDays.find((day) => day.dayNumber === protocolExerciseDays[0].dayNumber);
                if (exerciseDay) {
                    exerciseDay.trainingDone = true;
                    await exercisePlan?.save();
                }

                // Pushes the daynumber of the protocol to the trainingDone array in the weekDisplay
                const weekDisplay = await WeekDisplay.findById(user?.weekDisplay);
                if(weekDisplay){
                    weekDisplay.trainingDone.push(protocolExerciseDays[0].dayNumber);
                    await weekDisplay.save();
                }

                // Append the new protocol to the existing one
                const existingProtocol = await ProtocolExercisePlan.findById(user?.protocolExercisePlan);
                if (existingProtocol) {
                    existingProtocol.exerciseDays = existingProtocol.exerciseDays.concat(protocolExerciseDays);
                    await existingProtocol.save();
                }

                return {
                    success: true,
                    code: 201,
                    newProtocol: existingProtocol,
                }
            }

            const protocolExerciseDays = protocolUtils.processRequest(protocol, comment);

            // Set the trainingDone property in the exerciseplan to true for the specific day of the protocol
            const exercisePlan = await ExercisePlan.findById(user?.exercisePlan);
            const exerciseDay = exercisePlan?.exerciseDays.find((day) => day.dayNumber === protocolExerciseDays[0].dayNumber);
            if (exerciseDay) {
                exerciseDay.trainingDone = true;
                await exercisePlan?.save();
            }

            const weekDisplay = await WeekDisplay.findById(user?.weekDisplay);
            console.log(weekDisplay);
            if(weekDisplay){
                weekDisplay.trainingDone.push(protocolExerciseDays[0].dayNumber);
                console.log(weekDisplay.trainingDone);
                await weekDisplay.save();
            }

            if (user) {
                const protocolExercisePlanDocument = new ProtocolExercisePlan({
                    exerciseDays: protocolExerciseDays
                });

                // Create and save the exercise plan using the ExercisePlan model
                const createdExercisePlan = await ProtocolExercisePlan.create(protocolExercisePlanDocument);
                user.protocolExercisePlan = createdExercisePlan._id;

                await user.save();

                return {
                    success: true,
                    code: 201,
                    newProtocol: createdExercisePlan,
                };
                
            }
        } catch (error) {
            console.log('Error creating ProtocolExercisePlan:', error);
            return {
                success: false,
                code: 500,
                message: 'Error creating ProtocolExercisePlan',
            };
        }
    }

    async getProtocol (userId: string) {
        try {
            const user = await UserModel.findById(userId).populate('protocolExercisePlan');
            if (user) {
                return {
                    success: true,
                    code: 200,
                    protocol: user.protocolExercisePlan,
                }
            }
        } catch (error) {
            console.log('Error getting ProtocolExercisePlan:', error);
            return {
                success: false,
                code: 500,
                message: 'Internal server error',
            };
        }
    }
}

export default new ProtocolService();