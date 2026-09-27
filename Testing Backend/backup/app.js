// app.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const cors = require('cors');
const helmet = require('helmet');

// const clientRoutes = require('./routes/clients');

const app = express();


app.use(cors({
    origin: [
        'http://localhost:5173',
        'http://localhost:5174',
        'http://localhost:5175',
        'http://localhost:5000',
        'https://login-system-testing.netlify.app',
        'https://userloginauthenticationmicroservice.onrender.com'
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                imgSrc: ["'self'", "https:", "data:"],
                // scriptSrc: ["'self'", "'unsafe-inline'"], // Note: 'unsafe-inline' is for development ease
                // styleSrc: ["'self'", "'unsafe-inline'"], // Note: 'unsafe-inline' is for development ease
                connectSrc: ["'self'", "https://userloginauthenticationmicroservice.onrender.com",
                    'http://localhost:5000'
                ],
                // Add other directives as needed for your app
            },
        },
        // Other Helmet settings can go here
    })
);


// Body parsing middleware
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));


// Routes
// app.use('/api/clients', clientRoutes);

// 404 handler
// app.all('/:id', (req, res) => {
//     res.status(404).json({
//         status: 'error',
//         message: `Can't find ${req.originalUrl} on this server!`
//     });
// });

// Global error handler
// app.use((err, req, res, next) => {
//     console.error(err.stack);

//     res.status(err.statusCode || 500).json({
//         status: 'error',
//         message: err.message || 'Internal Server Error'
//     });
// });


// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
}).then(() => {
    console.log('Connected to MongoDB');
}).catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
});




app.get('/api/registrationLink', async (req, res, next) => {
    try {
        const authnestClientApiKey = process.env.CLIENT_AUTHNEST_API_KEY;
        const authnestClientSecretKey = process.env.CLIENT_AUTHNEST_SECRET_KEY;
        const state = crypto.randomBytes(12).toString('hex');

        let redirectUrl;
        if (process.env.NODE_ENV == "production") {
            redirectUrl = `https://userloginauthenticationmicroservice.onrender.com/api/registration-forms/grabApiKeys?client_api_key=${authnestClientApiKey}&client_secret_key=${authnestClientSecretKey}&state=${state}&url=${`UserRegistration`}&redirect_uri=${encodeURIComponent('/api/auth/callback')}`;
        } else {
            redirectUrl = `http://localhost:5000/api/registration-forms/grabApiKeys?client_api_key=${authnestClientApiKey}&client_secret_key=${authnestClientSecretKey}&state=${state}&url=${`UserRegistration`}&redirect_uri=${encodeURIComponent('/api/auth/callback')}`;
        }


        res.redirect(redirectUrl);

    } catch (error) {
        next(error);
    }
});

app.get('/api/loginLink', async (req, res, next) => {
    try {
        const authnestClientApiKey = process.env.CLIENT_AUTHNEST_API_KEY;
        const authnestClientSecretKey = process.env.CLIENT_AUTHNEST_SECRET_KEY;
        const authnestClientBackendURL = process.env.CLIENT_AUTHNEST_BACKEND_URL;
        const state = crypto.randomBytes(12).toString('hex');


        let redirectUrl;
        if (process.env.NODE_ENV == "production") {
            redirectUrl = `${authnestClientBackendURL}/api/registration-forms/grabApiKeys?client_api_key=${authnestClientApiKey}&client_secret_key=${authnestClientSecretKey}&state=${state}&url=${`UserLogin`}&redirect_uri=${encodeURIComponent('/api/auth/callback')}`;
        } else {
            redirectUrl = `http://localhost:5000/api/registration-forms/grabApiKeys?client_api_key=${authnestClientApiKey}&client_secret_key=${authnestClientSecretKey}&state=${state}&url=${`UserLogin`}&redirect_uri=${encodeURIComponent('/api/auth/callback')}`;
        }


        res.redirect(redirectUrl);

    } catch (error) {
        next(error);
    }
});

// Client's server - add this endpoint
app.get('/api/userDataLink', async (req, res, next) => {
    try {
        const authnestClientApiKey = process.env.CLIENT_AUTHNEST_API_KEY;
        const authnestClientSecretKey = process.env.CLIENT_AUTHNEST_SECRET_KEY;
        const authnestClientBackendURL = process.env.CLIENT_AUTHNEST_BACKEND_URL;
        const myBackendServerURL = process.env.MY_BACKEND_SERVER_URL;

        // Optional query parameters for filtering
        const { userId, email, page, limit } = req.query;
        const state = crypto.randomBytes(12).toString('hex');

        // Build query parameters for the SaaS endpoint
        const queryParams = new URLSearchParams({
            client_api_key: authnestClientApiKey,
            client_secret_key: authnestClientSecretKey,
            state: state
        });

        // Add the redirect_uri WITHOUT encoding it here
        // The encoding will happen when we build the final URL
        let redirectUri
        if (process.env.NODE_ENV == "production") {

            redirectUri = `${myBackendServerURL}/api/auth/user-data-callback`;

        } else {
            redirectUri = `http://localhost:9000/api/auth/user-data-callback`;


        }

        // Add optional filters if provided
        if (userId) queryParams.append('user_id', userId);
        if (email) queryParams.append('email', email);
        if (page) queryParams.append('page', page);
        if (limit) queryParams.append('limit', limit);

        // Add redirect_uri as the last parameter
        queryParams.append('redirect_uri', redirectUri);

        let redirectUrl;
        if (process.env.NODE_ENV == "production") {
            redirectUrl = `${authnestClientBackendURL}/api/clients/user-data?${queryParams.toString()}`;
        } else {
            redirectUrl = `http://localhost:5000/api/clients/user-data?${queryParams.toString()}`;
        }

        console.log('Redirecting to:', redirectUrl);
        res.redirect(redirectUrl);

    } catch (error) {
        next(error);
    }
});

// Client's server - callback endpoint for user data
app.get('/api/auth/user-data-callback', async (req, res, next) => {
    try {
        const { token, data, error, state } = req.query;

        console.log('Received callback with token:', token);
        console.log('Has data:', !!data);

        if (error) {
            return res.status(400).json({
                status: 'error',
                message: `Authentication failed: ${error}`,
                state: state
            });
        }

        if (!data) {
            return res.status(400).json({
                status: 'error',
                message: 'No data received',
                state: state
            });
        }

        try {
            // Simply parse the received data (no additional verification needed)
            const userData = JSON.parse(decodeURIComponent(data));

            console.log('Successfully received user data for', userData.users.length, 'users');

            res.json({
                status: 'success',
                message: 'User data retrieved successfully',
                data: userData,
                state: state
            });

        } catch (parseError) {
            console.error('Data parsing failed:', parseError.message);
            res.status(400).json({
                status: 'error',
                message: 'Failed to parse user data',
                error: parseError.message,
                state: state
            });
        }

    } catch (error) {
        console.error('User data callback error:', error);
        next(error);
    }
});

app.get('/api/clientDataLink', async (req, res, next) => {
    try {
        const authnestClientApiKey = process.env.CLIENT_AUTHNEST_API_KEY;
        const authnestClientSecretKey = process.env.CLIENT_AUTHNEST_SECRET_KEY;
        const authnestClientBackendURL = process.env.CLIENT_AUTHNEST_BACKEND_URL;
        const myBackendServerURL = process.env.MY_BACKEND_SERVER_URL;

        const state = crypto.randomBytes(12).toString('hex');

        // Build query parameters for the SaaS endpoint
        const queryParams = new URLSearchParams({
            client_api_key: authnestClientApiKey,
            client_secret_key: authnestClientSecretKey,
            state: state
        });

        // Add the redirect_uri
        let redirectUri;
        if (process.env.NODE_ENV == "production") {
            redirectUri = `${myBackendServerURL}/api/auth/client-data-callback`;
        } else {
            redirectUri = `http://localhost:9000/api/auth/client-data-callback`;
        }

        // Add redirect_uri as the last parameter
        queryParams.append('redirect_uri', redirectUri);

        let redirectUrl;
        if (process.env.NODE_ENV == "production") {
            redirectUrl = `${authnestClientBackendURL}/api/clients/client-data?${queryParams.toString()}`;
        } else {
            redirectUrl = `http://localhost:5000/api/clients/client-data?${queryParams.toString()}`;
        }

        console.log('Redirecting to:', redirectUrl);
        res.redirect(redirectUrl);

    } catch (error) {
        next(error);
    }
});

// Client's server - callback endpoint for client data
app.get('/api/auth/client-data-callback', async (req, res, next) => {
    try {
        const { token, data, error, state } = req.query;

        // console.log('Received callback with token:', token);
        console.log('Has data:', !!data);

        if (error) {
            return res.status(400).json({
                status: 'error',
                message: `Authentication failed: ${error}`,
                state: state
            });
        }

        if (!data) {
            return res.status(400).json({
                status: 'error',
                message: 'No data received',
                state: state
            });
        }

        try {
            // Parse the received client data
            const clientData = JSON.parse(decodeURIComponent(data));

            console.log('Successfully received client data for', clientData.client.name);

            res.json({
                status: 'success',
                message: 'Client data retrieved successfully',
                data: clientData,
                state: state
            });

        } catch (parseError) {
            console.error('Data parsing failed:', parseError.message);
            res.status(400).json({
                status: 'error',
                message: 'Failed to parse client data',
                error: parseError.message,
                state: state
            });
        }

    } catch (error) {
        console.error('Client data callback error:', error);
        next(error);
    }
});
// Start server
const PORT = process.env.PORT || 9000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});


module.exports = app;