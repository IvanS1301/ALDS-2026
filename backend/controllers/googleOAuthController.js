const { google } = require('googleapis');

const oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
);

const SCOPES = [
    'https://www.googleapis.com/auth/gmail.send'
];

// Open Google's authorization page
const googleAuth = (req, res) => {
    const authUrl = oauth2Client.generateAuthUrl({
        access_type: 'offline',
        prompt: 'consent',
        scope: SCOPES,
        state: process.env.GOOGLE_OAUTH_STATE
    });

    res.redirect(authUrl);
};

// Receive Google's response and generate refresh token
const googleCallback = async (req, res) => {
    try {
        const { code, state, error } = req.query;

        if (error) {
            return res.status(400).send('Google authorization was denied.');
        }

        if (!code || state !== process.env.GOOGLE_OAUTH_STATE) {
            return res.status(400).send('Invalid authorization request.');
        }

        const { tokens } = await oauth2Client.getToken(code);

        if (!tokens.refresh_token) {
            return res.status(400).send(
                'No refresh token received. Try authorizing again.'
            );
        }

        res.set('Cache-Control', 'no-store');

        res.send(`
            <h2>Google authorization successful!</h2>
            <p>Copy the refresh token below and save it securely.</p>
            <textarea rows="8" cols="80" readonly>${tokens.refresh_token}</textarea>
            <p>Do not share this token or put it in GitHub.</p>
        `);

    } catch (error) {
        console.error('Google OAuth error:', error.message);
        res.status(500).send('Failed to generate Google refresh token.');
    }
};

module.exports = {
    googleAuth,
    googleCallback
};
