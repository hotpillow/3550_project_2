// Used node-jose: https://github.com/cisco/node-jose
import express from 'express';
import jose from 'node-jose';

const keystore = jose.JWK.createKeyStore();

export const app = express();
const PORT = 8080;

// Make into JSON object bc that's how we can use JSON.stringify()
const basePayload = { username: 'userABC', password: 'password123' };

// Create an empty object so the object can dynamically grow
const expTimes = {};

// Generate a key with the passed in expTime
export async function generateKey(expTime) {
	const key = await keystore.generate('RSA', 2048);
	expTimes[key.kid] = expTime;
	return key;
}
// Create the two keys
generateKey(Math.floor(Date.now() / 1000) + 3600); // keystore.all()[0];
generateKey(Math.floor(Date.now() / 1000) - 3600); // keystore.all()[1];

// Signing function
export async function getSignedJWT(payload, expiredTest) {
	// Check table for expiration time
	// if expiredText = true, then store it at [1]
	let key;
	if (expiredTest) {
		key = keystore.all()[1];
	} else {
		// Future functionality, get random key
		key = keystore.all()[0];
	}
	// If expired, then set exp to the expiration time, then remove the key
	if (expTimes[key.kid] < Math.floor(Date.now() / 1000)) {
		payload.exp = expTimes[key.kid]; // gradebot wants the expired time
		delete expTimes[key.kid];
		keystore.remove(key);
	}

	// Set the values to the corresponding kid and alg
	const token = await jose.JWS.createSign(
		{ format: 'compact', fields: { kid: key.kid, alg: key.alg } },
		key
	)
		.update(JSON.stringify(payload)) // \Stringify works bc it's a JSON object
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

// LISTEN (returns a server)
export const server = app.listen(PORT, () => {
	console.log(`Server is running on http://localhost:${PORT}`);
});
