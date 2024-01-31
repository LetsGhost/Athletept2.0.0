import ExcelJS, { Row } from "exceljs";
import UserModel from "../models/UserModel.js";
import ExercisePlanModel, { Exercise, warmup, ExerciseDay } from "../models/ExercisePlanModel.js";
import logger from "../../config/winstonLogger.js";
import WeekDisplayModel from "../models/WeekDisplayModel.js";

class ExercisePlanService {


    // TODO: Define some rules for the processed JSON for the excel file
    async createExercisePlanFromExcel(userId: string, exerciseFile: any, warmupFile: any) {
        try {
            // ExerciseFile Workbook
            const workbook = new ExcelJS.Workbook();
            await workbook.xlsx.readFile(exerciseFile);

            // WarmupFile Workbook
            const warmupWorkbook = new ExcelJS.Workbook();
            await warmupWorkbook.xlsx.readFile(warmupFile);

            const exercisePlan: ExerciseDay[] = [];

            const worksheet = workbook.getWorksheet(1);
            const warmupWorksheet = warmupWorkbook.getWorksheet(1);

            let currentDay: ExerciseDay | null = null;
            let previousType: string | null = null; // Store the previous type

            worksheet?.eachRow((row) => {
                if (row.getCell(1).value === 'Name') return; // Skip the first row

                const currentType = row.getCell(1).value as string; // Is the nummer of the day

                if (currentType !== previousType) {
                    // If the training type in the first cell has changed, it's a new day
                    const exercises: Exercise[] = [];
                    const warmup: warmup[] = [];

                    exercises.push({
                        Exercises: row.getCell(3).value as string,
                        Weight: row.getCell(4).value as string,
                        Sets: row.getCell(5).value as number,
                        WarmUpSets: row.getCell(6).value as number,
                        WarmupWeight: row.getCell(7).value as string,
                        WarmupRepetitions: row.getCell(8).value as string,
                        Repetitions: row.getCell(9).value as string,
                        Rest: row.getCell(10).value as string,
                        Execution: row.getCell(11).value as string,
                    });

                    warmupWorksheet?.eachRow((warmupRow) => {
                        if (warmupRow.getCell(1).value === 'Nummer') return; // Skip the first row

                        const warmupType = warmupRow.getCell(1).value as string;
                        console.log("WarmupType " + warmupType)
                        console.log("CurrentType " + currentType)

                        if (warmupType === currentType) {
                            console.log("hi")
                            warmup.push({
                                warmupExercise: [{
                                    Exercises: warmupRow.getCell(2).value as string,
                                    weight: warmupRow.getCell(4).value as string,
                                    repetitions: warmupRow.getCell(5).value as string,
                                }],
                                warmupMaterials: [{
                                    Materials: warmupRow.getCell(3).value as string,
                                    weight: warmupRow.getCell(4).value as string,
                                    repetitions: warmupRow.getCell(5).value as string,
                                }],
                            });
                        }
                        console.log(warmup)
                    });

                    currentDay = {
                        dayNumber: exercisePlan.length + 1,
                        weekDay: row.getCell(2).value as string,
                        type: row.getCell(1).value as string,
                        trainingDone: false,
                        trainingMissed: false,
                        exercises: exercises,
                        warmup: warmup,
                    };
                    exercisePlan.push(currentDay);

                    // Update the previous type
                    previousType = currentType;
                } else {
                    // Append exercises to the current day
                    currentDay?.exercises.push({
                        Exercises: row.getCell(3).value as string,
                        Weight: row.getCell(4).value as string,
                        Sets: row.getCell(5).value as number,
                        WarmUpSets: row.getCell(6).value as number,
                        WarmupWeight: row.getCell(7).value as string,
                        WarmupRepetitions: row.getCell(8).value as string,
                        Repetitions: row.getCell(9).value as string,
                        Rest: row.getCell(10).value as string,
                        Execution: row.getCell(11).value as string,
                    });
                }
            });

            const user = await UserModel.findById(userId);

            // Delete the previous exercise plan
            if (user?.exercisePlan) {
                await ExercisePlanModel.findByIdAndDelete(user.exercisePlan);
            }

            // Define the rules to check if the excel is processed correctly
            if(exercisePlan){
                const exercisePlanDays = exercisePlan;
                // 1. Check if the exercise plan has more than 7 days
                if(exercisePlanDays.length > 7){
                    return {
                        success: false,
                        code: 400,
                        message: "The exercise plan has more than 7 days"
                    }
                }

                // 2. Check if any value is null or undefined
                for (const day of exercisePlanDays) {
                    // Check if any property of day is null or undefined
                    for (const key in day) {
                        const value = (day as { [key: string]: any })[key];
                        if (value === null || value === undefined) {
                            return {
                                success: false,
                                code: 400,
                                message: `The exercise plan contains null or undefined values`
                            }
                        }
                    }

                    // Check if any value in exercises is null or undefined
                    for (const exercise of day.exercises) {
                        for (const key in exercise) {
                            const value = (exercise as { [key: string]: any })[key];
                            if (value === null || value === undefined) {
                                return {
                                    success: false,
                                    code: 400,
                                    message: `The exercise plan contains null or undefined values`
                                }
                            }
                        }
                    }

                    // Check if the warmup has no null or undefined values
                    for (const warmup of day.warmup) {
                        for (const key in warmup) {
                            const value = (warmup as { [key: string]: any })[key];
                            if (value === null || value === undefined) {
                                return {
                                    success: false,
                                    code: 400,
                                    message: `The warmup contains null or undefined values`
                                }
                            }
                        }
                    }
                }
                
                // 3. Check if an exerciseDay has atleast one exercise
                for (const day of exercisePlanDays) {
                    if(day.exercises.length < 1){
                        return {
                            success: false,
                            code: 400,
                            message: `The exercise plan has a day without exercises`
                        }
                    }
                }
            }
            console.log(JSON.stringify(exercisePlan, null, 2));
            if (user) {
                const exercisePlanDocument = new ExercisePlanModel({
                    exerciseDays: exercisePlan,
                });

                // Create and save the exercise plan using the ExercisePlan model
                const createdExercisePlan = await ExercisePlanModel.create(exercisePlanDocument);
                user.exercisePlan = createdExercisePlan._id;
                await user.save();

                // Reset the trainingDone array
                const weekDisplay = await WeekDisplayModel.findById(user.weekDisplay);
                if (weekDisplay) {
                    weekDisplay.trainingDone = [];
                    await weekDisplay.save();
                }

                return {
                    success: true,
                    code: 200,
                    exercisePlan: createdExercisePlan
                }
            }

            return {
                success: false,
                code: 404,
                message: "User not found!"
            }

        } catch (error) {
            logger.error(`Error processing the Excel file: ${error}`, {service: 'ExercisePlanService.createExercisePlanFromExcel'});
            return {
                success: false,
                code: 500,
                message: "Internal Server error"
            }
        }
    };

    async createExercisePlanOnly(userId: string, exerciseFile: any) {
        try {
            // ExerciseFile Workbook
            const workbook = new ExcelJS.Workbook();
            await workbook.xlsx.readFile(exerciseFile);

            const exercisePlan: ExerciseDay[] = [];

            const worksheet = workbook.getWorksheet(1);

            let currentDay: ExerciseDay | null = null;
            let previousType: string | null = null; // Store the previous type

            worksheet?.eachRow((row, rowNumber) => {
                if (row.getCell(1).value === 'Nummer') return; // Skip the first row

                const currentType = row.getCell(1).value as string; // Is the nummer of the day

                if (currentType !== previousType) {
                    // If the training type in the first cell has changed, it's a new day
                    const exercises: Exercise[] = [];
                    const warmup: warmup[] = [];

                    exercises.push({
                        Exercises: row.getCell(4).value as string,
                        Weight: row.getCell(5).value as string,
                        Sets: row.getCell(6).value as number,
                        WarmUpSets: row.getCell(7).value as number,
                        WarmupWeight: row.getCell(8).value as string,
                        WarmupRepetitions: row.getCell(9).value as string,
                        Repetitions: row.getCell(10).value as string,
                        Rest: row.getCell(11).value as string,
                        Execution: row.getCell(12).value as string,
                    });

                    currentDay = {
                        dayNumber: exercisePlan.length + 1,
                        weekDay: row.getCell(3).value as string,
                        type: row.getCell(2).value as string,
                        trainingDone: false,
                        trainingMissed: false,
                        exercises: exercises,
                        warmup: warmup,
                    };
                    exercisePlan.push(currentDay);

                    // Update the previous type
                    previousType = currentType;
                } else {
                    // Append exercises to the current day
                    currentDay?.exercises.push({
                        Exercises: row.getCell(4).value as string,
                        Weight: row.getCell(5).value as string,
                        Sets: row.getCell(6).value as number,
                        WarmUpSets: row.getCell(7).value as number,
                        WarmupWeight: row.getCell(8).value as string,
                        WarmupRepetitions: row.getCell(9).value as string,
                        Repetitions: row.getCell(10).value as string,
                        Rest: row.getCell(11).value as string,
                        Execution: row.getCell(12).value as string,
                    });
                }
            });


            // Define the rules to check if the excel is processed correctly
            if(exercisePlan){
                const exercisePlanDays = exercisePlan;
                // 1. Check if the exercise plan has more than 7 days
                if(exercisePlanDays.length > 7){
                    return {
                        success: false,
                        code: 400,
                        message: "The exercise plan has more than 7 days"
                    }
                }

                // 2. Check if any value is null or undefined
                for (const day of exercisePlanDays) {
                    // Check if any property of day is null or undefined
                    for (const key in day) {
                        const value = (day as { [key: string]: any })[key];
                        if (value === null || value === undefined) {
                            return {
                                success: false,
                                code: 400,
                                message: `The exercise plan contains null or undefined values`
                            }
                        }
                    }

                    // Check if any value in exercises is null or undefined
                    for (const exercise of day.exercises) {
                        for (const key in exercise) {
                            const value = (exercise as { [key: string]: any })[key];
                            if (value === null || value === undefined) {
                                return {
                                    success: false,
                                    code: 400,
                                    message: `The exercise plan contains null or undefined values`
                                }
                            }
                        }
                    }

                    // Check if the warmup has no null or undefined values
                    for (const warmup of day.warmup) {
                        for (const key in warmup) {
                            const value = (warmup as { [key: string]: any })[key];
                            if (value === null || value === undefined) {
                                return {
                                    success: false,
                                    code: 400,
                                    message: `The warmup contains null or undefined values`
                                }
                            }
                        }
                    }
                }
                
                // 3. Check if an exerciseDay has atleast one exercise
                for (const day of exercisePlanDays) {
                    if(day.exercises.length < 1){
                        return {
                            success: false,
                            code: 400,
                            message: `The exercise plan has a day without exercises`
                        }
                    }
                }
            }

            // Find the user and update the exercise plan
            const user = await UserModel.findById(userId);

            // Delete the previous exercise plan
            if (user?.exercisePlan) {
                await ExercisePlanModel.findByIdAndDelete(user.exercisePlan);
            }

            if (user) {
                const exercisePlanDocument = new ExercisePlanModel({
                    exerciseDays: exercisePlan,
                });

                // Create and save the exercise plan using the ExercisePlan model
                const createdExercisePlan = await ExercisePlanModel.create(exercisePlanDocument);
                user.exercisePlan = createdExercisePlan._id;
                await user.save();

                return {
                    success: true,
                    code: 200,
                    exercisePlan: createdExercisePlan
                }
            }

            return {
                success: false,
                code: 404,
                message: "User not found!"
            }
        } catch (error) {
            logger.error(`Error processing the Excel file: ${error}`, {service: 'ExercisePlanService.createExercisePlanOnly'});
            return {
                success: false,
                code: 500,
                message: "Internal Server error"
            }
        }
    }

    // TODO: Needs to be fixed, pls use a completely new approach 
    async createWarmupSingle(userId: string, warmupFile: any) {
        try {
            const user = await UserModel.findById(userId).populate('exercisePlan');
            
            if (!user) {
                return {
                    success: false,
                    code: 404,
                    message: "User not found!"
                }
            }

            if (user.exercisePlan) {
                // Process the warmup Excel file here
                // Set the warmup data into the corresponding day of the exercise plan
    
                // Example code to process the warmup Excel file
                const workbook = new ExcelJS.Workbook();
                await workbook.xlsx.readFile(warmupFile);
                const worksheet = workbook.getWorksheet(1);
    
                // Iterate over the rows of the worksheet and extract the warmup data
                worksheet?.eachRow((row: Row, rowNumber: number) => {
                    // Extract the warmup data from the row and set it into the corresponding day of the exercise plan
                    const dayNumber = row.getCell(1).value;
                    const warmupExercise = row.getCell(2).value;
                    const warmupMaterial = row.getCell(3).value;
                    const warmupWeight = row.getCell(4).value;
                    const repetitions = row.getCell(5).value;
    
                    // Find the corresponding day in the exercise plan
                    const exerciseDay = (user.exercisePlan as any).exerciseDays.find((day: ExerciseDay) => day.dayNumber === dayNumber);
                    if (exerciseDay) {
                        // Set the warmup data into the exercise day
                        exerciseDay.warmup.push({
                            warmupExercise: {
                                Exercises: warmupExercise,
                                weight: warmupWeight,
                                repetitions: repetitions
                            },
                            warmupMaterials: {
                                Materials: warmupMaterial, // Set the materials value here
                            }
                        });
                    }
                });

                await (user.exercisePlan as any).save();
    
                return {
                    success: true,
                    code: 200,
                    exercisePlan: user.exercisePlan
                }
            } else {
                return {
                    success: false,
                    code: 404,
                    message: "Exercise plan not found for the user"
                }
            }
        } catch (error) {
            logger.error(`Error processing the Excel file: ${error}`, { service: 'ExercisePlanService.createWarmupSingle' });
            return {
                success: false,
                code: 500,
                message: "Internal Server error"
            }
        }
    }

    async getExercisePlan(userId: string) {
        try {
            const user = await UserModel.findById(userId).populate('exercisePlan');
            if(!user){
                return {
                    success: false,
                    code: 404,
                    message: "User not found!"
                }
            }

            if (user && user.exercisePlan) {
                return {
                    success: true,
                    code: 200,
                    exercisePlan: user.exercisePlan
                }
            }

            return {
                success: false,
                code: 404,
            }

        } catch (error) {
            logger.error(`Error getting the exercise plan: ${error}`, {service: 'ExercisePlanService.getExercisePlan'});
            return {
                success: false,
                code: 500,
                message: "Internal Server error"
            }
        }
    }
}

export default new ExercisePlanService();