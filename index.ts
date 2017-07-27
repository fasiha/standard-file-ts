const SERVER = 'https://sync.standardnotes.org';
const COST = 100e3;

import { readFileSync, writeFile } from "fs";
import { randomBytes, createHash, pbkdf2, createHmac, createCipheriv, createDecipheriv } from 'crypto';
import fetch from "node-fetch";
const promisify = require("es6-promisify");
const pbkdf2Async = promisify(pbkdf2);
const randomBytesAsync = promisify(randomBytes);

function hmacSha256(key: Buffer | string, text: string): string {
    const hmac = createHmac('sha256', key)
    hmac.update(text);
    return hmac.digest('hex');
}

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
    const pw_auth = hmacSha256(pw_cost.toString() + ':' + pw_salt, ak);

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
    const local_pw_auth = hmacSha256(hmacSecret, ak);

    if (local_pw_auth !== authParams.pw_auth) {
        throw new Error('Local password did not match server’s record');
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
    console.log('JWT RESPONSE:', authResponse);
    return { authResponse, mk, ak };
}

async function cipherContent(cleartext: string | Buffer, encryption_key: Buffer) {
    const iv = await randomBytesAsync(128 / 8);
    const cipher = createCipheriv('aes-256-cbc', encryption_key, iv);
    let ciphertext;
    if (typeof cleartext === 'string') {
        ciphertext = cipher.update(cleartext, 'utf8', 'base64');
    } else {
        ciphertext = cipher.update(cleartext, 'binary', 'base64');
    }
    ciphertext += cipher.final('base64');
    return { iv: iv.toString('hex'), ciphertext };
}

async function decipherContent(ciphertext: string, encryption_key: Buffer, iv: Buffer) {
    const decipher = createDecipheriv('aes-256-cbc', encryption_key, iv);
    const decrypted = decipher.update(ciphertext, 'base64');
    const final = decipher.final();
    const decryptedFinal = Buffer.concat([decrypted, final]);
    return decryptedFinal;
}

async function encrypt002(cleartext: string | Buffer, uuid: string, encryption_key: Buffer, authentication_key: Buffer) {
    const ciphered = await cipherContent(cleartext, encryption_key);
    const string_to_auth = ['002', ciphered.iv, uuid, ciphered.ciphertext].join(':');

    const auth_hash = hmacSha256(authentication_key, string_to_auth);
    const result = ["002", auth_hash, ciphered.iv, uuid, ciphered.ciphertext].join(":")
    return result;
}

async function decrypt002(input: string, encryption_key: Buffer, authentication_key: Buffer, expectedUuid?: string) {
    const components = input.split(':');
    if (components.length !== 5) {
        throw new Error('Input to decrypt002 lacks five colon-separated units');
    }
    const version = components[0];
    const auth_hash = components[1];
    const iv = components[2];
    const uuid = components[3];
    const ciphertext = components[4];

    if (expectedUuid && uuid !== expectedUuid) {
        console.error(`UUIDs did not match: got ${uuid}, expected ${expectedUuid}`);
        // return null;
    }
    const string_to_auth = [version, iv, uuid, ciphertext].join(":");
    const local_auth_hash = hmacSha256(authentication_key, string_to_auth);
    if (local_auth_hash !== auth_hash) {
        console.error(`Authentication hashes do not match`);
        return null;
    }
    return decipherContent(ciphertext, encryption_key, Buffer.from(iv, 'hex'))
}

interface Item {
    uuid: string;
    content: any; // Any before encryption, string after
    content_type: string;
    enc_item_key: string; // None before encryption, string after
    deleted: boolean;
    created_at: Date;
    updated_at: Date;
}

interface WebToken {
    user: any;
    token: string;
}

type SyncResult = { itemsReceived: any, itemsDecrypted: any };
async function sync(origItems: Item[], mk: string, ak: string, jwt: WebToken, sync_token: string = null): Promise<SyncResult> {
    let items: Item[] = [];
    try {
        // Encrypt each item
        for (const origItem of origItems) {
            // Encryption key
            const item_ek: Buffer = await randomBytesAsync(512 / 8 / 2);
            // Authentication key
            const item_ak: Buffer = await randomBytesAsync(512 / 8 / 2);
            // Combined key
            const item_key = Buffer.concat([item_ek, item_ak]);

            let newItem: Item = Object.assign(
                origItem,
                {
                    content: await encrypt002(JSON.stringify(origItem), origItem.uuid, item_ek, item_ak),
                    enc_item_key: await encrypt002(
                        item_key,
                        origItem.uuid,
                        Buffer.from(mk, 'hex'),
                        Buffer.from(ak, 'hex'))
                });
            items.push(newItem);
        }
        console.log('ITEMS TO SEND:', items);

        // Sync with server
        const response = await fetch(`${SERVER}/items/sync`, {
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${jwt.token}` },
            method: "POST",
            body: JSON.stringify({ items, sync_token })
        });
        const itemsReceived = await response.json();
        console.log('ITEMS RECEIVED:', itemsReceived);

        // if (origItems.length > 0) {
        //     return { itemsReceived, itemsDecrypted: [] };
        // }

        // Decrypt received items

        let itemsDecrypted = [];
        for (const item of itemsReceived.retrieved_items) {
            const item_key = await decrypt002(item.enc_item_key, Buffer.from(mk, 'hex'), Buffer.from(ak, 'hex'), item.uuid);
            if (!item_key) {
                console.error(`Skipping ${item.uuid} because of item_key error`)
                itemsDecrypted.push(null);
                continue;
            }
            const item_ek = item_key.slice(0, item_key.length / 2);
            const item_ak = item_key.slice(item_key.length / 2, item_key.length);
            const contents = await decrypt002(item.content, item_ek, item_ak, item.uuid);
            if (!contents) {
                console.error(`Skipping ${item.uuid} because of contents decryption error`)
                itemsDecrypted.push(null);
                continue;
            }
            // console.log(contents.toString('utf8').length);
            itemsDecrypted.push(JSON.parse(contents.toString('utf8')));
        }
        console.log('DECRYPTED:', itemsDecrypted);
        return { itemsDecrypted, itemsReceived }
    }
    catch (e) {
        console.error('Error', e)
    }
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

// const authResponse = login('foo@test.com', 'testing');
/*
JWT { user:
   { uuid: '38f41c3e-cc90-4384-a969-4337aa160987',
     email: 'foo@test.com' },
  token: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX3V1aWQiOiIzOGY0MWMzZS1jYzkwLTQzODQtYTk2OS00MzM3YWExNjA5ODciLCJwd19oYXNoIjoiNGU5MjVkM2E1ZWRjNjgwMjVhNzNhYTkwZmExNTQ5NjIyMzYzZjFhM2ExYTFkMzNkMmU2NzY1Mjg0NDJlYzgzZSJ9.BbnQQq1Q-sIys_mdU7OObzG4cN3eRFElXFGzFUH-SPU' }
*/

function makeItem(uuid: string,
    content: any,
    content_type: string,
    deleted: boolean,
    created_at: Date,
    updated_at: Date): Item {
    return { uuid, content, content_type, deleted, created_at, updated_at: updated_at || new Date(), enc_item_key: null }
}

async function testing() {
    let item: Item = makeItem('222', { just: "Updates are ok!" }, 'testing', false, new Date('2017-07-27T01:23:25.860Z'), new Date());

    const authResponse = await login('foo@test.com', 'testing');

    let syncResult = await sync([], authResponse.mk, authResponse.ak, authResponse.authResponse);
    let sync2 = await sync([item], authResponse.mk, authResponse.ak, authResponse.authResponse, syncResult.itemsReceived.sync_token);
}
testing()
