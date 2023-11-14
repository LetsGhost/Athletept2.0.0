import {MessageModel} from "../models/MessagModel";
import UserModel from "../models/UserModel";
import mongoose from "mongoose";

class MessageService{
    async createMessage( message: string, sender: string, userId: string) {
        try {
            // Create a new message
            const newMessage = new MessageModel({
                message,
                sender,
            });

            // Save the message to the database
            await newMessage.save();

            // Update the user's messages array with the message's ObjectId
            const user = await UserModel.findById(userId);
            if (!user) {
                console.log('User not found');
                return {
                    success: false,
                    code: 404,
                    messageo: 'User not found'
                }
            }

            user?.messages.push(newMessage._id);
            await user?.save();

            return {
                success: true,
                code: 201,
                newMessage,
            }
        } catch (error) {
            console.log('Error creating message:', error);
            return {
                success: false,
                code: 500,
                messageo: 'Internal server error'
            }
        }
    };

    async getAllMessagesFromUser(userId: string) {
        try {
            const user = await UserModel.findById(userId).populate('messages');
            if (!user) {
                console.error('User not found');
                return {
                    success: false,
                    code: 404,
                    message: 'User not found'
                }
            }

            return {
                success: true,
                code: 200,
                messages: user.messages,
            }
        } catch (error) {
            console.error('Error getting messages:', error);
            return {
                success: false,
                code: 500,
                message: 'Internal server error'
            }
        }
    }

    async getMessageById(messageId: string) {
        try{
            const messageText = await MessageModel.findById(new mongoose.Types.ObjectId(messageId));
            if(!messageText){
                console.error('Message not found');
                return {
                    success: false,
                    code: 404,
                    message: 'Message not found'
                }
            }
    
            return {
                success: true,
                code: 200,
                messageText,
            }
        } catch(error){
            console.error('Error getting message by id in MessageService.getMessageById:', error);
            return {
                success: false,
                code: 500,
                message: 'Internal server error'
            }
        }
    }

    async deleteMessageById(messageId: string) {
        try{
            // Delete the message from the database
            const deletedMessage = await MessageModel.findByIdAndDelete(messageId);
            if(!deletedMessage){
                console.error('Message not found');
                return {
                    success: false,
                    code: 404,
                    message: 'Message not found'
                }
            }

            // Delete the message from the user's messages array
            const user = await UserModel.findOne({messages: messageId});
            if(!user){
                console.error('User not found');
                return {
                    success: false,
                    code: 404,
                    message: 'User not found'
                }
            }

            user.messages = user.messages.filter(message => message.toString() !== messageId);
            await user.save();

            return {
                success: true,
                code: 200,
                deletedMessage,
            }
        } catch(error){
            console.error('Error deleting message in MessageService.deleteMessageById:', error);
            return {
                success: false,
                code: 500,
                message: 'Internal server error'
            }
        }
    }
}


export default new MessageService();