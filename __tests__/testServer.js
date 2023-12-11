// /* eslint-env jest */
// // ^ has to be at the top
// // Got this from ChatGPT after asking it how to use JEST to test this
// // npm run test
// import request from 'supertest';
// import { app, server, generateKey, initializeDatabase } from '../server';

// jest.setTimeout(10000); // Timeout has to be this long otherwise it times out

// describe('Express server', () => {
// 	beforeAll(async () => {
// 		await initializeDatabase();
// 		await generateKey(Math.floor(Date.now() / 1000) + 3600);
// 		await generateKey(Math.floor(Date.now() / 1000) - 360);
// 	});

// 	// Test for the /.well-known/jwks.json endpoint
// 	it('GET /.well-known/jwks.json should return public keys', async () => {
// 		const response = await request(app).get('/.well-known/jwks.json');
// 		expect(response.status).toBe(200);
// 		expect(response.body).toHaveProperty('keys');
// 	});

// 	// Test POST /auth endpoint for valid JWT
// 	it('POST /auth should return valid JWT', async () => {
// 		const response = await request(app).post('/auth').timeout(500);
// 		expect(response.status).toBe(200);
// 	});

// 	// Test POST /auth endpoint for expired JWT
// 	it('POST /auth?expired=true should return expired JWT', async () => {
// 		const response = await request(app).post('/auth?expired=true').timeout(500);
// 		expect(response.status).toBe(401);
// 	});

// 	// Test for invalid HTTP methods
// 	it('PUT /.well-known/jwks.json should return 405', async () => {
// 		const response = await request(app).put('/.well-known/jwks.json');
// 		expect(response.status).toBe(405);
// 	});

// 	it('PUT /auth should return 405', async () => {
// 		const response = await request(app).put('/auth');
// 		expect(response.status).toBe(405);
// 	});
// });

// // Properly closing the server
// afterAll((done) => {
// 	server.close(done);
// });

/* eslint-env jest */
import request from 'supertest';
import { app, server, generateKey, initializeDatabase } from '../server';

jest.setTimeout(10000);

describe('Express server', () => {
	beforeAll(async () => {
		await initializeDatabase(); // Add this line to initialize the database
		await generateKey(Math.floor(Date.now() / 1000) + 3600);
		await generateKey(Math.floor(Date.now() / 1000) - 3600);
	});

	// Test for the /.well-known/jwks.json endpoint
	it('GET /.well-known/jwks.json should return public keys', async () => {
		const response = await request(app).get('/.well-known/jwks.json');
		expect(response.status).toBe(200);
		expect(response.body).toHaveProperty('keys');
	});

	// Test POST /auth endpoint for valid JWT
	it('POST /auth should return valid JWT', async () => {
		const response = await request(app).post('/auth').timeout(500);
		expect(response.status).toBe(200);
		// You might want to add more checks here based on the token or its structure
	});

	// Test POST /auth endpoint for expired JWT
	it('POST /auth?expired=true should return expired JWT', async () => {
		const response = await request(app).post('/auth?expired=true').timeout(500);
		expect(response.status).toBe(401);
		// You might want to add more checks here based on the token or its structure
	});

	// Test for invalid HTTP methods
	it('PUT /.well-known/jwks.json should return 405', async () => {
		const response = await request(app).put('/.well-known/jwks.json');
		expect(response.status).toBe(405);
	});

	it('PUT /auth should return 405', async () => {
		const response = await request(app).put('/auth');
		expect(response.status).toBe(405);
	});

	// Properly closing the server after all tests
	afterAll((done) => {
		server.close(done);
	});
});
