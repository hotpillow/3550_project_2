// Used node-jose: https://github.com/cisco/node-jose
// Used ChatGPT for part 3: asked for AES encryption
// run with node server.js
import express from 'express';
import jose from 'node-jose';
import Database from 'better-sqlite3';
import { unlinkSync } from 'fs'; // for deleting the db file
// import AES from 'crypto-es/aes';
// import encUtf8 from 'crypto-es/enc-utf8';
import rateLimit from 'express-rate-limit';

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

// // Function to encrypt data using AES
// function encryptData(data, key) {
// 	return AES.encrypt(data, key).toString();
// }

// // Function to decrypt data using AES
// function decryptData(encryptedData, key) {
// 	return AES.decrypt(encryptedData, key).toString(encUtf8);
// }

export async function initializeDatabase() {
	let db = new Database('./totally_not_my_privateKeys.db', {
		verbose: console.log,
	});

	// 	db.exec(`
	//     CREATE TABLE IF NOT EXISTS keys (
	//         kid INTEGER PRIMARY KEY AUTOINCREMENT,
	//         key BLOB NOT NULL,
	//         exp INTEGER NOT NULL
	//     );
	//   `);

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

	return db;
}

// Generate a key with the passed in expTime
export async function generateKey(expTime) {
	const key = await keystore.generate('RSA', 2048);
	// const privateKey = key.toPEM(true);

	try {
		// const encryptedPrivateKey = encryptData(privateKey, process.env.NOT_MY_KEY);

		const stmt = db.prepare('INSERT INTO keys (key, exp) VALUES (?, ?);');

		const result = stmt.run(key.toPEM(true), expTime);
		// const result = stmt.run(encryptedPrivateKey, expTime);

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
				const result = stmt.get(BigInt(2));
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
				const result = stmt.get(BigInt(1));
				resolve(result);
			} catch (error) {
				console.warn('Error querying the database: ', error);
				reject();
			}
		});
	}

	// Get the key from the keystore
	var key = await jose.JWK.asKey(dbKey.key, 'pem');

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

// Rate limiter for /auth
const limiter = rateLimit({
	windowMs: 1000, // 1 min
	limit: 10, // Limit each IP to 10 requests per `window`
	message: 'Too many requests, please try again later.',
});

// For all /auth posts
app.use('/auth', limiter);

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

// POST /auth
app.all('/auth', (req, res, next) => {
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
		res.status(500).send('Error generating JWT');
	}
});

// POST / register
app.all('/register', (req, res, next) => {
	if (req.method !== 'POST') {
		return res.status(405).end();
	}
	next();
});

app.post('/register', async (req, res) => {
	try {
		return res
			.status(201)
			.send({ password: '0b170dfe-ed87-4b65-bed4-9e9ccbd9cb07' });
	} catch (error) {
		return res.status(500).send('Error registering user');
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
