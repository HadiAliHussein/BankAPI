// dependencies
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config({ path: './.env' });
const crypto = require('crypto');
const res = require('express/lib/response');
const req = require('express/lib/request');

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(cors({
    origin: '*',
    credentials: true // Allow credentials (cookies, authorization headers)
}));

const mongoURI = process.env.MONGO_URI; // URI for all databases

console.log(mongoURI)






const MainDB = mongoose.createConnection(mongoURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    dbName: 'Main'
});

MainDB.on('error', console.error.bind(console, 'MongoDB connection error for Main'));
MainDB.once('open', () => {
    console.log('Connected to Main database');
});

// Define User Schema and Model
const userSchema = new mongoose.Schema({
    Username: String,
    Password: String,
}, {
    collection: 'Users', // Specify the collection name explicitly
    versionKey: false // Disable the __v field
});

// Pre-save hook to hash the password before saving (could be used for account creation)
userSchema.pre('save', async function(next) {
    try {
        if (this.isModified('password') || this.isNew) {
            const salt = await bcrypt.genSalt(10);
            this.password = await bcrypt.hash(this.password, salt);
        }
        next();
    } catch (err) {
        next(err);
    }
});

const User = MainDB.model('User', userSchema);

// JWT Secret Key
const secretKey = process.env.JWT_SECRET;

// Login Route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ Username: username }).exec();
        if (!user) {
            return res.status(401).send('Invalid username or password');
        }

        // compare text with hashed password in MongoDB
        const isMatch = await bcrypt.compare(password, user.Password);

        if (!isMatch) {
            return res.status(401).send('Invalid username or password');
        }

        // Generate JWT token
        const token = jwt.sign(
            { 
                userId: user._id, 
                username: user.Username, 
                department: user.Password, 
            }, 
            secretKey, 
            { expiresIn: '1h' }
        );

        // Send token to the client
        res.status(200).json({ token });
    } catch (err) {
        console.error(err);
        res.status(500).send('Internal server error');
    }
});



// Middleware to authenticate token
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).send('Unauthorized: No token provided');
    }

    try {
        const decoded = jwt.verify(token, secretKey);

        // Fetch user from database using the _id from the token
        const dbUser = await User.findById(decoded.userId).lean().exec();

        if (!dbUser) {
            return res.status(401).send('Unauthorized: User not found');
        }


        console.log(decoded.username)
        console.log(decoded.userId)
        console.log(dbUser.Username)
        console.log(dbUser._id.toString())
        // Check if user details match the database
        const detailsMatch = dbUser.Username === decoded.username &&
                             dbUser._id.toString() === decoded.userId;

        if (!detailsMatch) {
            return res.status(401).send('Unauthorized: User details do not match');
        }

        req.user = dbUser;
        next();
    } catch (err) {
        console.error('Error verifying token:', err);
        return res.status(403).send('Forbidden: Invalid token');
    }
};

// protected API endpoint
app.get('/api/protected', authenticateToken, (req, res) => {
    res.status(200).json(req.user); // Send the user information
});






// Array to store all database connections
const dbConnections = [];

// Initialize connections to all 10 banks
for (let i = 1; i <= 10; i++) {
    const dbConnection = mongoose.createConnection(mongoURI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        dbName: `Bank_${i}`
    });
    dbConnections.push(dbConnection);

    dbConnection.on('error', console.error.bind(console, `MongoDB connection error for Bank_${i}:`));
    dbConnection.once('open', () => {
        console.log(`Connected to Bank_${i} database`);
    });
}

// Define the Account schema (assuming same structure for all)
const accountSchema = new mongoose.Schema({
    User: { type: Number, required: true },
    Amount: { type: Number, required: true }, // For precise amounts
    Firstname: String,
    Lastname: String
}, { collection: 'Accounts' });

// Store all models
const accountModels = dbConnections.map(db => db.model('Account', accountSchema));

// Function to hash User and Amount
const hashValues = (user, amount) => {
    const hash = crypto.createHash('sha256');
    hash.update(`${user}:${amount}`);
    return hash.digest('hex');
};

let isFetching = false; // Variable to track if fetchAndCompare is running
let lastFetchTime = 0;  // To track the last time fetchAndCompare was called

// Function to fetch and hash Account data from all banks for each User
const fetchAndCompare = async () => {
    isFetching = true; // Set the flag to true indicating the function is running
    try {
        // Step 1: Find the largest User in Bank_1
        const largestUserInBank1 = await accountModels[0].findOne().sort({ User: -1 }).limit(1).exec();
        if (!largestUserInBank1) {
            console.log('No users found in Bank_1.');
            return;
        }

        const largestUser = largestUserInBank1.User;
        console.log(`Largest User in Bank_1: ${largestUser}`);

        // Step 2: Loop over all User IDs from 1 to the largest User
        for (let currentUser = 1; currentUser <= largestUser; currentUser++) {
            console.log(`Processing User: ${currentUser}`);

            const hashes = [];
            const amounts = [];

            // Fetch User and Amount from each bank's Account collection for the current User
            const allUserDatabases = accountModels.map(u => u.findOne({ User: currentUser }));
            const accounts = await Promise.all(allUserDatabases);

            accounts.forEach((account, i) => {
                if (account) {
                    const hash = hashValues(account.User, account.Amount);
                    hashes.push(hash);
                    amounts.push(account.Amount);
                    console.log(`Bank_${i + 1} hash: ${hash}, Amount: ${account.Amount}`);
                } else {
                    console.log(`Bank_${i + 1}: No account found for User ${currentUser}`);
                    hashes.push(null);
                    amounts.push(null);
                }
            });

            // Step 3: Count how many banks have the same hash
            const hashCounts = {};
            for (const hash of hashes) {
                if (hash) {
                    hashCounts[hash] = (hashCounts[hash] || 0) + 1;
                }
            }

            // Step 4: Find the most common hash and corresponding amount
            let acceptedHash = null;
            let acceptedAmount = null;

            // Calculate the dynamic majority based on the number of banks
            const totalBanks = accountModels.length;  // Number of banks (account models)
            const majorityCount = Math.ceil(totalBanks / 2);  // Majority threshold

            for (const [hash, count] of Object.entries(hashCounts)) {
                if (count >= majorityCount) { // Use the dynamic majority count here
                    acceptedHash = hash;
                    // Get the amount corresponding to this hash
                    const index = hashes.indexOf(hash);
                    if (index !== -1) {
                        acceptedAmount = amounts[index];
                    }
                    console.log(`Accepted hash for User ${currentUser}: ${hash} (from ${count} banks)`);
                    break;  // Exit once a majority hash is found
                }
            }

            // If no hash was accepted
            if (!acceptedHash) {
                console.log(`No consensus on hash values for User ${currentUser}.`);
                // If no consensus, take the most common hash
                const maxCount = Math.max(...Object.values(hashCounts));
                const majorityHash = Object.keys(hashCounts).find(key => hashCounts[key] === maxCount);
                if (majorityHash) {
                    // Get the corresponding amount
                    const index = hashes.indexOf(majorityHash);
                    if (index !== -1) {
                        acceptedAmount = amounts[index];
                    }
                }
            }

            // Step 5: Update all databases with the accepted amount for the current User if it is found
            if (acceptedAmount !== null) {
                console.log(`Updating all databases for User ${currentUser} to Amount: ${acceptedAmount}`);

                await Promise.all(accountModels.map(model =>
                    model.updateMany({ User: currentUser }, { Amount: acceptedAmount })
                ));
                console.log(`All databases updated with the accepted Amount for User ${currentUser}.`);
            }
        }

    } catch (err) {
        console.error('Error during hash comparison:', err);
    }finally {
        isFetching = false; // Reset the flag
        lastFetchTime = Date.now(); // Update the last fetch time
    }
};


// Set an interval to run this check every 5 seconds
setInterval(fetchAndCompare, 5000);


app.get('/users', authenticateToken, async (req, res) => {
    try {
        // Select the appropriate database model (e.g., the first one)
        const AccountModel = accountModels[0];

        // Fetch all users from the database
        const users = await AccountModel.find();

        if (!users || users.length === 0) {
            return res.status(404).json({ success: false, message: 'No users found' });
        }

        // Map the users to the desired format
        const result = users.map(user => ({
            id: user.User,
            firstname: user.Firstname,
            name: user.Lastname,
            amount: user.Amount
        }));

        

        // Send the formatted data as a response
        res.status(201).json({ success: true, message: 'User infos sent', data: result });
    } catch (error) {
        console.error('Error getting user infos:', error);
        res.status(500).json({ success: false, message: 'Error getting user infos' });
    }
});

app.post('/users/create', authenticateToken, async (req, res) => {
    try {
        // Destructure id, firstname, and lastname from the request body
        const { id, firstname, lastname } = req.body;

        // Ensure that all required fields are provided
        if (!id || !firstname || !lastname) {
            return res.status(400).json({ success: false, message: 'ID, firstname, and lastname are required' });
        }

        // Prepare the new user document data
        const newUser = {
            User: id,
            Firstname: firstname,
            Lastname: lastname,
            Amount: 100 // Set Amount to 100
        };

        // Create a new document in each bank's Account collection
        const creationPromises = accountModels.map((accountModel, i) => {
            return accountModel.create(newUser)
                .then(() => {
                    console.log(`User created in Bank_${i + 1}`);
                })
                .catch(err => {
                    console.error(`Error creating user in Bank_${i + 1}:`, err);
                    throw new Error(`Bank_${i + 1}: User creation failed`);
                });
        });

        // Wait for all the create operations to complete
        await Promise.all(creationPromises);

        // Send success response
        res.status(201).json({ success: true, message: 'User created in all databases' });
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).json({ success: false, message: 'Error creating user' });
    }
});

app.post('/transaction/receive', async (req, res) => {
    try {
        console.log(req.body);

        const {
            recipient,
            amount,
        } = req.body;

        // Only execute max 500ms after fetchAndCompare has stopped, this provides a timeframe of at least 4.5 seconds
        while (isFetching || (Date.now() - lastFetchTime > 500)) {
            await new Promise(resolve => setTimeout(resolve, 50)); // Wait for 50 ms
        }

        // Add new amount to user's amount
        const updateAmount = accountModels.map(model => model.updateMany({ User: recipient }, { $inc: { Amount: amount}}));
        await Promise.all(updateAmount);

        res.status(201).json({ success: true, message: 'Transaction sent' });
    } catch (error) {
        console.error('Error creating project:', error);
        res.status(500).json({ success: false, message: 'Error creating project' });
    }
});

app.post('/transaction/send', async (req, res) => { // app.post('/transaction/send', authenticateToken, async (req, res) => {
    try {
        console.log(req.body);

        const {
            recipientApiAdress,
            recipientID,
            amount,
            sender,
        } = req.body;

        // Only execute max 500ms after fetchAndCompare has stopped, this provides a timeframe of at least 4.5 seconds
        while (isFetching || (Date.now() - lastFetchTime > 500)) {
            await new Promise(resolve => setTimeout(resolve, 50)); // Wait for 50 ms
        }

        const hashes = [];
        const amounts = [];

        // Fetch User and Amount from each bank's Account collection
        const allUserDatabases = accountModels.map(u => u.findOne({ User: sender }))
        const accounts = await Promise.all(allUserDatabases)
        accounts.forEach((account, i) => {
            if (account) {
                const hash = hashValues(account.User, account.Amount);
                hashes.push(hash);
                amounts.push(account.Amount);
                console.log(`Bank_${i + 1} hash: ${hash}, Amount: ${account.Amount}`);
            } else {
                console.log(`Bank_${i + 1}: No account found`);
                hashes.push(null);
                amounts.push(null);
            }
        });

        // Find the majority amount like in `fetchAndCompare`
        const hashCounts = {};
        for (const hash of hashes) {
            if (hash) {
                hashCounts[hash] = (hashCounts[hash] || 0) + 1;
            }
        }

        let majorityAmount = null;
        let majorityHash = null;

        // Calculate the dynamic majority based on the number of banks
        const totalBanks = accountModels.length;  // Number of banks (account models)
        const majorityCount = Math.ceil(totalBanks / 2); // Calculate the majority threshold


        for (const [hash, count] of Object.entries(hashCounts)) {
            if (count >= majorityCount) { // Use the dynamic majority count here
                majorityHash = hash;
                const index = hashes.indexOf(hash);
                if (index !== -1) {
                    majorityAmount = amounts[index];
                }
                break;  // Exit once a majority hash is found
            }
        }

        // Check if the sender has enough balance
        if (majorityAmount === null || amount > majorityAmount) {
            return res.status(400).json({ success: false, message: 'Insufficient balance' });
        }

        // Deduct the amount from all databases
        const deductAmount = accountModels.map(model => model.updateMany({ User: sender }, { $inc: { Amount: -amount } }));
        await Promise.all(deductAmount);
        console.log(`Deducted ${amount} from sender`);

        // Call the recipient's API
        const axios = require('axios'); // Ensure axios is installed in your project
        await axios.post(recipientApiAdress, {
            recipient: recipientID,
            amount: Number(amount)
        });

        res.status(201).json({ success: true, message: 'Transaction sent successfully' });
    } catch (error) {
        console.error('Error creating project:', error);
        res.status(500).json({ success: false, message: 'Error processing transaction' });
    }
});

// Start server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
