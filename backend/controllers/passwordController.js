require('dotenv').config()
const UserLG = require('../models/userLGModel')
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const forgotPassword = async (req, res) => {
    const { email } = req.body;

    let userLG;
    let resetToken;

    try {
        // 1. Find the user
        userLG = await UserLG.findOne({ email });

        if (!userLG) {
            return res.status(400).json({
                error: 'No account with that email address exists.'
            });
        }

        // 2. Generate a verification code
        resetToken = crypto.randomBytes(3).toString('hex');

        const resetTokenExpiration = Date.now() + 1800000;

        // 3. Save the code and expiration in MongoDB
        userLG.resetPasswordToken = resetToken;
        userLG.resetPasswordExpires = resetTokenExpiration;

        await userLG.save();

        // 4. Send the email through Resend's HTTPS API
        const response = await fetch(
            'https://api.resend.com/emails',
            {
                method: 'POST',

                headers: {
                    'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
                    'Content-Type': 'application/json'
                },

                body: JSON.stringify({
                    from: process.env.EMAIL,
                    to: [userLG.email],
                    subject: 'Password Reset',

                    text: `You requested a password reset for your account.

Your verification code is: ${resetToken}

Please use this code within the next 30 minutes.`,

                    html: `
                        <p>You requested a password reset for your account.</p>

                        <p>
                            Please use this verification code within
                            the next 30 minutes:
                        </p>

                        <h2>${resetToken}</h2>
                    `
                })
            }
        );

        // 5. Check whether Resend accepted the email
        const responseData = await response.json();

        if (!response.ok) {
            console.error('Resend email error:', responseData);

            throw new Error('Unable to send the password reset email.');
        }

        // 6. Return success to the frontend
        return res.status(200).json({
            message: 'Password reset email sent successfully.'
        });

    } catch (error) {
        console.error('Forgot password error:', error);

        // 7. Remove the unused reset code if email sending fails
        if (userLG && resetToken) {
            try {
                userLG.resetPasswordToken = undefined;
                userLG.resetPasswordExpires = undefined;

                await userLG.save();
            } catch (cleanupError) {
                console.error(
                    'Failed to clear reset token:',
                    cleanupError
                );
            }
        }

        return res.status(500).json({
            error: 'Unable to send the password reset email. Please try again later.'
        });
    }
};

module.exports = {
    forgotPassword,
    resetPassword,
};
