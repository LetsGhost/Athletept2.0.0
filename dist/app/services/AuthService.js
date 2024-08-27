import jwt from 'jsonwebtoken';
import UserModel from '../models/UserModel.js';
import * as process from "process";
import logger from '../../config/winstonLogger.js';
import dotenv from 'dotenv';
dotenv.config();
class AuthService {
    async loginUser(email, password, alwaysLogedIn) {
        try {
            const user = await UserModel.findOne({ email }).exec();
            const userRole = user;
            if (!user) {
                return {
                    success: false,
                    code: 404,
                    message: 'Authentication failed'
                };
            }
            const passwordMatch = await user.comparePassword(password);
            if (!passwordMatch) {
                return {
                    success: false,
                    code: 401,
                    message: 'Authentication failed'
                };
            }
            // IF TOKEN_SECRET is not set, the user will not be able to login
            if (!process.env.TOKEN_SECRET) {
                logger.error('No token secret found', { service: 'AuthService.loginUser' });
                return {
                    success: false,
                    code: 500,
                    message: 'Internal server error'
                };
            }
            // If the user set alwaysLogedIn to true, the token will be valid for 30 days
            if (alwaysLogedIn) {
                const token = jwt.sign({ userId: user._id, userRole: userRole.role }, process.env.TOKEN_SECRET, { expiresIn: '30d' });
                const userId = user._id;
                return {
                    success: true,
                    code: 200,
                    token,
                    userId,
                    role: userRole.role
                };
            }
            const token = jwt.sign({ userId: user._id, userRole: userRole.role }, process.env.TOKEN_SECRET, { expiresIn: process.env.TOKEN_AGE });
            const userId = user._id;
            return {
                success: true,
                code: 200,
                token,
                userId,
                role: userRole.role
            };
        }
        catch (error) {
            logger.error('Internal server error', { service: 'AuthService.loginUser' });
            return {
                success: false,
                code: 500,
                message: "Internal server error"
            };
        }
    }
    // Maby remove this because it's not used (Ask first)
    async getUserFromToken(token) {
        try {
            const decodedToken = jwt.verify(token, process.env.TOKEN_SECRET);
            const user = await UserModel.findById(decodedToken.userId).exec();
            if (!token) {
                logger.error('No token found', { service: 'AuthService.getUserFromToken' });
                return {
                    success: false,
                    code: 404,
                    message: "No token found"
                };
            }
            return {
                success: true,
                code: 200,
            };
        }
        catch (error) {
            logger.error(`Internal server error: ${error}`, { service: 'AuthService.getUserFromToken' });
            return {
                success: false,
                code: 500,
                message: 'Internal server error'
            };
        }
    }
    async authToken(token, path) {
        try {
            console.log("executed");
            console.log(token);
            // If TOKEN_SECRET is not set, the user will not be able to login
            if (!process.env.TOKEN_SECRET) {
                logger.error('No token secret found', { service: 'AuthService.authToken' });
                return {
                    success: false,
                    code: 500,
                    message: 'Internal server error'
                };
            }
            const keyString = process.env.TOKEN_SECRET;
            const decodedToken = jwt.verify(token, keyString);
            if (!decodedToken) {
                return {
                    success: false,
                    code: 401,
                    message: 'Unauthorized'
                };
            }
            if (decodedToken.userRole != "admin") {
                const slicedPath = path.split('/').slice(-1)[0];
                if (decodedToken.userId != slicedPath) {
                    return {
                        success: false,
                        code: 401,
                        message: 'Unauthorized userIds are not matching'
                    };
                }
                return {
                    success: true,
                    code: 200,
                    message: 'Authorized'
                };
            }
            return {
                success: true,
                code: 200,
                role: decodedToken.userRole,
                userId: decodedToken.userId,
                message: 'Authorized'
            };
        }
        catch (error) {
            logger.error(`Internal server error: ${error}`, { service: 'AuthService.authToken' });
            return {
                success: false,
                code: 500,
                message: 'Internal server error'
            };
        }
    }
    async authRole(token, path) {
        try {
            const decodedToken = jwt.verify(token, process.env.Token_SECRET);
            if (!decodedToken) {
                return {
                    success: false,
                    code: 401,
                    message: 'Unauthorized'
                };
            }
            if (decodedToken.userRole != "admin") {
                return {
                    success: false,
                    code: 401,
                    message: 'Unauthorized userRole is not matching'
                };
            }
            return {
                success: true,
                code: 200,
                message: 'Authorized'
            };
        }
        catch (error) {
            logger.error(`Internal server error: ${error}`, { service: 'AuthService.authRole' });
            return {
                success: false,
                code: 500,
                message: 'Internal server error'
            };
        }
    }
}
export default new AuthService();
