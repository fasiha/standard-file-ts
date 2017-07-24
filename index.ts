const SERVER = 'https://sync.standardnotes.org';
const COST = 100e3;

import { readFileSync, writeFile } from "fs";
import { randomBytes, createHash, pbkdf2, createHmac } from 'crypto';
import fetch from "node-fetch";
const promisify = require("es6-promisify");
const pbkdf2Async = promisify(pbkdf2);
const randomBytesAsync = promisify(randomBytes);

async function generatePasswordKey(userpass: string, pw_cost: number, pw_salt: string) {
    const key = (await pbkdf2Async(userpass, pw_salt, pw_cost, 768 / 8, 'sha512') as Buffer).toString('hex');
    const pw = key.substring(0, key.length / 3);
    const mk = key.substring(key.length / 3, 2 * (key.length / 3));
    const ak = key.substring(2 * (key.length / 3), key.length);
    return { pw, mk, ak };
}

async function registrationRequirements(userpass: string, pw_cost: number) {
    // Generate salt
    const nonce: Buffer = await randomBytesAsync(128 / 8);
    const hashSHA1 = createHash('sha1');
    hashSHA1.update(nonce);
    const pw_salt = hashSHA1.digest('hex');

    // Generate server-side password (stored on server), master key (local), and authentication key (local)
    const { pw, mk, ak } = await generatePasswordKey(userpass, pw_cost, pw_salt);

    // HMAC the salt with the local-only authentication key to get a kind of password digest (stored on server)
    const hmac = createHmac('sha256', pw_cost.toString() + ':' + pw_salt);
    hmac.update(ak);
    const pw_auth = hmac.digest('hex');

    // Server gets server-side password, password digest, cost, and salt during registration.
    return { pw, pw_cost, pw_auth, pw_salt };
}

async function register(email: string, userpass: string, dryrun: boolean = true) {
    const params = Object.assign(await registrationRequirements(userpass, COST), { email });
    console.log(params);
    if (!dryrun) {
        const response = await fetch(`${SERVER}/auth`, {
            headers: { 'Content-Type': 'application/json' },
            method: "POST",
            body: JSON.stringify(params)
        });
        console.log('Server replied with', response.status, response.statusText);
    }
}

interface AuthParamsFromServer {
    pw_cost: number;
    pw_salt: string;
    pw_auth: string;
}

async function login(email: string, userpass: string) {
    // Server tells us the cost, salt, and the password digest (which is used for client-side password verification)
    const parmsResponse = await fetch(`${SERVER}/auth/params?email=${encodeURIComponent(email)}`);
    const authParams: AuthParamsFromServer = await parmsResponse.json();

    // Regenerate the server-side password (NOT provided by server above!), and client-only master and authentication keys
    const { pw, mk, ak } = await generatePasswordKey(userpass, authParams.pw_cost, authParams.pw_salt);

    // Ensure that the password is correct by comparing server-provided and regenerated password digests of `ak`.
    // If this doesn't match, don't even send anything to the server, it won't work.
    const hmacSecret: string = authParams.pw_cost.toString() + ':' + authParams.pw_salt;
    const hmac = createHmac('sha256', hmacSecret)
    hmac.update(ak);
    const local_pw_auth = hmac.digest('hex');

    if (local_pw_auth !== authParams.pw_auth) {
        console.error('Local password did not match server’s record!');
    }

    // Assuming we're sure the password is correct, send the regenerated server-side password to log in.
    const authData = { email, local_pw_auth };
    const signinResponse = await fetch(`${SERVER}/auth/sign_in`, {
        headers: { 'Content-Type': 'application/json' },
        method: "POST",
        body: JSON.stringify(authData)
    });

    // Get a JWT in response
    const authResponse = await signinResponse.json();
    console.log('JWT', authResponse);
}

// register('foo@test.com', 'testing', false)
/*
{ pw: '0f5a1aa43694b894befd341fcb196cc6f4d5c32599754d9be5e089aaee1821ef',
  pw_cost: 100000,
  pw_auth: '81950f19b553375a8b310eb17f0542d69f536e67ce6f0c9903f087d1808f44df',
  pw_salt: 'df360d5557ead0671f8021587a3d340596367860',
  email: 'foo@test.com' }
Server replied with 200
*/

login('foo@test.com', 'testing');
/*
JWT { user:
   { uuid: '38f41c3e-cc90-4384-a969-4337aa160987',
     email: 'foo@test.com' },
  token: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX3V1aWQiOiIzOGY0MWMzZS1jYzkwLTQzODQtYTk2OS00MzM3YWExNjA5ODciLCJwd19oYXNoIjoiNGU5MjVkM2E1ZWRjNjgwMjVhNzNhYTkwZmExNTQ5NjIyMzYzZjFhM2ExYTFkMzNkMmU2NzY1Mjg0NDJlYzgzZSJ9.BbnQQq1Q-sIys_mdU7OObzG4cN3eRFElXFGzFUH-SPU' }
*/
