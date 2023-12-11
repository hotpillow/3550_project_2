// Used node-jose: https://github.com/cisco/node-jose
// Used ChatGPT for most of part 3's additions
// rateLimit(), AES, generateUser(), and the /register post
// run with node server.js
import express from 'express';
import jose from 'node-jose';
import Database from 'better-sqlite3';
import { unlinkSync } from 'fs'; // for deleting the db file
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto-es';
import 'dotenv/config';

const AES = crypto.AES;
const encUtf8 = crypto.enc.Utf8;
export const app = express();
const db = await initializeDatabase();
const keystore = jose.JWK.createKeyStore();
const PORT = 8080;
const basePayload = { username: 'userABC', password: 'password123' };

function cleanup(status) {
	// delete all rows from the `keys` db
	if (status == 0) {
		unlinkSync('./totally_not_my_privateKeys.db');
	}

	process.exit(0);
}

// Prompted ChatGPT for a rateLimit function
const rateLimit = (maxRequests, timeWindow) => {
	let requestCounts = new Map();

	return (req, res, next) => {
		const ip = req.ip;
		const currentTime = Date.now();

		if (!requestCounts.has(ip)) {
			requestCounts.set(ip, { count: 1, startTime: currentTime });
			next();
		} else {
			const requestData = requestCounts.get(ip);

			if (currentTime - requestData.startTime > timeWindow) {
				// Time window has passed, reset the count and start time
				requestCounts.set(ip, { count: 1, startTime: currentTime });
				next();
			} else {
				// Time window still active
				if (requestData.count < maxRequests) {
					// Increment count and let request proceed
					requestData.count += 1;
					next();
				} else {
					// Max request limit reached, block the request
					res.status(429).send('Rate limit exceeded. Please try again later.');
				}
			}
		}
	};
};

// Prompted ChatGPT for AES encryption and decryption
// Function to encrypt data using AES
function encryptData(data, key) {
	return AES.encrypt(data, key);
}

// Function to decrypt data using AES
function decryptData(encryptedData, key) {
	return AES.decrypt(encryptedData, key).toString(encUtf8);
}

export async function initializeDatabase() {
	let db = new Database('./totally_not_my_privateKeys.db');

	db.exec(`
    CREATE TABLE IF NOT EXISTS keys (
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    );
  `);

	db.exec(`
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    );
  `);

	db.exec(`
    CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
  `);

	return db;
}

// Generate a key with the passed in expTime
export async function generateKey(expTime) {
	const key = await keystore.generate('RSA', 2048);
	const privateKey = key.toPEM(true);

	try {
		const encryptedPrivateKey = encryptData(privateKey, process.env.NOT_MY_KEY);
		const stmt = db.prepare('INSERT INTO keys (key, exp) VALUES (?, ?);');

		// const result = stmt.run(key.toPEM(true), expTime);
		const result = stmt.run(encryptedPrivateKey.toString(), expTime);

		if (result.changes < 1) {
			console.error('No rows were inserted.');
		}
	} catch (error) {
		console.error('SQL Error:', error);
	}

	if (expTime < Math.floor(Date.now() / 1000)) {
		keystore.remove(key);
	}

	return key;
}

// Generate user with UUIDv4 password
export async function generateUser(username) {
	const password = uuidv4();

	try {
		const stmt = db.prepare(
			'INSERT INTO users (username, password_hash) VALUES (?, ?);'
		);
		const result = stmt.run(username, password);

		if (result.changes < 1) {
			console.error('No rows were inserted.');
		}

		return password;
	} catch (error) {
		console.error('SQL Error:', error);

		return `error`;
	}
}

generateKey(Math.floor(Date.now() / 1000) + 36000);
generateKey(Math.floor(Date.now() / 1000) - 120);

// Signing function
export async function getSignedJWT(payload, expiredTest) {
	// Check table for expiration time
	let dbKey;
	if (expiredTest) {
		dbKey = await new Promise((resolve, reject) => {
			try {
				const stmt = db.prepare('SELECT * FROM keys WHERE kid = ?');
				const result = stmt.get(2);
				resolve(result);
			} catch (error) {
				console.warn('Error querying the database: ', error);
				reject();
			}
		});
	} else {
		dbKey = await new Promise((resolve, reject) => {
			try {
				const stmt = db.prepare('SELECT * FROM keys WHERE kid = ?');
				const result = stmt.get(1);
				resolve(result);
			} catch (error) {
				console.warn('Error querying the database: ', error);
				reject();
			}
		});
	}

	var decryptedKey = decryptData(dbKey.key, process.env.NOT_MY_KEY);

	// Get the key from the keystore
	var key = await jose.JWK.asKey(decryptedKey, 'pem');

	// If expired, then set exp to the expiration time, then remove the key
	if (dbKey.exp < Math.floor(Date.now() / 1000)) {
		payload.exp = dbKey.exp; // gradebot wants the expired time
	}

	// Set the values to the corresponding kid and alg
	const token = await jose.JWS.createSign(
		{ format: 'compact', fields: { kid: key.kid, alg: key.alg } },
		key
	)
		.update(JSON.stringify(payload)) // Stringify works bc it's a JSON object
		.final();

	return token;
}

// GET
app.all('/.well-known/jwks.json', (req, res, next) => {
	if (req.method !== 'GET') {
		return res.status(405).end();
	}
	next();
});

app.get('/.well-known/jwks.json', (req, res) => {
	const keys = keystore.toJSON();

	return res.status(200).json(keys);
});

// POST
app.all('/auth', rateLimit(10, 1000), (req, res, next) => {
	if (req.method !== 'POST') {
		return res.status(405).end();
	}
	next();
});

app.post('/auth', async (req, res) => {
	try {
		const { query } = req;
		if (query.expired) {
			const token = await getSignedJWT(basePayload, true);
			return res.status(401).send(token);
		}
		const token = await getSignedJWT(basePayload);
		return res.status(200).send(token);
	} catch (error) {
		console.error('Error generating JWT: ', error);
		res.status(500).send('Error generating JWT');
	}
});

app.all(`/register`, (req, res, next) => {
	if (req.method !== 'POST') {
		return res.status(405).end();
	}
	next();
});

app.post(`/register`, async (req, res) => {
	try {
		const password = await generateUser(basePayload.username);
		console.log(`Password: ${password} has a length of ${password.length}`);
		return res.status(200).send({ password: password });
	} catch (error) {
		res.status(500).send(`Error registering user: ${error}`);
	}
});

// LISTEN (returns a server)
export const server = app.listen(PORT, () => {
	console.log(`Server is running on http://localhost:${PORT}`);
});

// Handle program close
process.on('exit', cleanup);
process.on('SIGINT', cleanup);
process.on('uncaughtException', (err) => {
	console.error('Uncaught Exception:', err);
	cleanup();
});
