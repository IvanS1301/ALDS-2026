require('dotenv').config();

const UserLG = require('../models/userLGModel');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { google } = require('googleapis');

// =====================================================
// GOOGLE GMAIL API CONFIGURATION
// =====================================================

const oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
);

oauth2Client.setCredentials({
    refresh_token: process.env.GOOGLE_REFRESH_TOKEN
});

const gmail = google.gmail({
    version: 'v1',
    auth: oauth2Client
});

// =====================================================
// SEND PASSWORD RESET EMAIL USING GMAIL API
// =====================================================

const sendPasswordResetEmail = async (recipient, resetToken) => {

    const sender = process.env.EMAIL;

    if (!sender) {
        throw new Error('EMAIL environment variable is missing.');
    }

    // Make sure EMAIL matches the Gmail account authorized
    // through Google OAuth.
    const subject = 'Password Reset';

    const html = `
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
    `;

    // Construct the email message
    const emailMessage = [
        `From: Sortr <${sender}>`,
        `To: ${recipient}`,
        `Subject: ${subject}`,
        'MIME-Version: 1.0',
        'Content-Type: text/html; charset=UTF-8',
        'Content-Transfer-Encoding: 8bit',
        '',
        html
    ].join('\r\n');

    // Gmail API requires a Base64URL-encoded message
    const encodedMessage = Buffer
        .from(emailMessage, 'utf-8')
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');

    // Send the email through Gmail API
    const response = await gmail.users.messages.send({
        userId: 'me',
        requestBody: {
            raw: encodedMessage
        }
    });

    return response.data;
};

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

        // 4. Send email using Gmail API
        const emailResponse = await sendPasswordResetEmail(
            userLG.email,
            resetToken
        );

        console.log(
            'Password reset email sent successfully:',
            emailResponse.id
        );

        // 5. Return success to the frontend
        return res.status(200).json({
            message: 'An email has been sent to ' +
                userLG.email +
                ' with further instructions.'
        });

    } catch (error) {

        console.error('Gmail API email error:', error);

        // 6. Clear the reset token if email sending fails
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
