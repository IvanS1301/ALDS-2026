require('dotenv').config();

const UserLG = require('../models/userLGModel');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

// =====================================================
// FORGOT PASSWORD
// =====================================================
const forgotPassword = async (req, res) => {
    const { email } = req.body;

    let userLG;
    let resetToken;

    try {
        // 1. Find the user by email
        userLG = await UserLG.findOne({ email });

        if (!userLG) {
            return res.status(400).json({
                error: 'No account with that email address exists.'
            });
        }

        // 2. Generate a verification code
        resetToken = crypto.randomBytes(3).toString('hex');

        // Token expires after 30 minutes
        const resetTokenExpiration = Date.now() + 1800000;

        // 3. Save the verification code in MongoDB
        userLG.resetPasswordToken = resetToken;
        userLG.resetPasswordExpires = resetTokenExpiration;

        await userLG.save();

        // 4. Send the email using Resend's HTTPS API
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

                    text: `You are receiving this because you requested a password reset for your account.

Please use this verification code to reset your password within the next 30 minutes: ${resetToken}`,

                    html: `
                        <div style="font-family: Arial, sans-serif; line-height: 1.6;">
                            <h2>Password Reset</h2>

                            <p>
                                You are receiving this because you requested
                                a password reset for your account.
                            </p>

                            <p>
                                Please use this verification code to reset
                                your password within the next 30 minutes:
                            </p>

                            <h2 style="color: #3e4396; letter-spacing: 4px;">
                                ${resetToken}
                            </h2>

                            <p>
                                If you did not request a password reset,
                                you can safely ignore this email.
                            </p>
                        </div>
                    `
                })
            }
        );

        // 5. Read and check the response from Resend
        const responseData = await response.json();

        if (!response.ok) {
            console.error('Resend email error:', responseData);

            throw new Error(
                'Unable to send the password reset email.'
            );
        }

        // 6. Return success to the frontend
        return res.status(200).json({
            message: 'An email has been sent to ' +
                userLG.email +
                ' with further instructions.'
        });

    } catch (error) {
        console.error('Forgot password error:', error);

        // 7. Clear the reset token if email sending fails
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

// =====================================================
// RESET PASSWORD
// =====================================================
const resetPassword = async (req, res) => {
    const { token, password } = req.body;

    try {
        // 1. Find the user using the verification code
        // and check if the code has expired
        const userLG = await UserLG.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() },
        });

        if (!userLG) {
            return res.status(400).json({
                error: 'Password reset token is invalid or has expired.'
            });
        }

        // 2. Hash the new password
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(password, salt);

        // 3. Update the password
        userLG.password = hash;

        // 4. Remove the used reset token
        userLG.resetPasswordToken = undefined;
        userLG.resetPasswordExpires = undefined;

        await userLG.save();

        // 5. Return success to the frontend
        return res.status(200).json({
            message: 'Password has been reset successfully.'
        });

    } catch (error) {
        console.error('Reset password error:', error);

        return res.status(500).json({
            error: 'Unable to reset the password. Please try again later.'
        });
    }
};

// =====================================================
// EXPORT CONTROLLER FUNCTIONS
// =====================================================
module.exports = {
    forgotPassword,
    resetPassword,
};
