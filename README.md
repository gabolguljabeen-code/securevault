# SecureVault — File Encryption & Decryption System

SecureVault is a Vercel-compatible Next.js App Router project for encrypting and decrypting files in the browser. It uses the Web Crypto API directly: AES-256-GCM for authenticated encryption, with a new random 256-bit key for each encrypted file. Turso stores only operation-history metadata. No file-processing API, paid service, or external encryption provider is used.

The standalone GitHub repository has the Next.js app at its root. In Vercel, leave **Root Directory** at `./`. If deploying from the original MUET Transport repository instead, set it to `securevault`.

## Architecture and file format

The Next.js app serves the interface and educational information page. All cryptographic operations run in a browser client component through `crypto.subtle`; file bytes and encryption keys are never sent to the server. New files use an independent random 256-bit key generated in the browser. SecureVault shows the key after encryption and offers copy and download controls; save it securely because the app cannot recover it. Next.js route handlers write operation metadata to Turso using the server-only `TURSO_DATABASE_URL` and `TURSO_AUTH_TOKEN` environment variables. The database contains each operation's filename, type, size, algorithm, timestamp, and an anonymous browser identifier. It keeps the latest 50 records per browser. A random, HTTP-only cookie scopes history to that browser; it does not create an account or sync history across devices. The browser owner can clear that browser's history in the app. Treat filenames as potentially sensitive because they are stored in Turso.

An encrypted `.svault` file is laid out as:

1. 8-byte `SVAULT01` format marker.
2. 4-byte big-endian JSON header length.
3. UTF-8 JSON header with format version, AES-256-GCM and 64-character hex key-format identifiers, 12-byte random nonce, original filename, MIME type, and creation time.
4. AES-256-GCM ciphertext and its 128-bit authentication tag.

The format prefix and header are also authenticated as AES-GCM additional data. If the key is wrong or ciphertext/header bytes change, authentication fails and the app does not offer a plaintext download. The header is readable without a key; it contains no key. Version 1 files remain decryptable with their original password.

## Run locally

Requirements: Node.js 20.9 or newer and npm.

```bash
npm install
npm run dev
```

If running from the original MUET Transport repository, first `cd securevault`. For persistent history locally, create `.env.local` from `.env.example` and set valid Turso credentials. Without those values, encryption remains usable and history is only kept in memory for the current visit. Open [http://localhost:3000](http://localhost:3000). For a production build, run `npm run build` and then `npm start`.

## Connect Turso

Create a Turso database using the [Turso Cloud quickstart](https://docs.turso.tech/quickstart). The project uses the `@libsql/client` TypeScript SDK with a server-side client suitable for serverless functions such as Vercel.

```bash
turso auth login
turso db create securevault
turso db show --url securevault
turso db tokens create securevault
```

Copy the database URL and generated token into `.env.local` as `TURSO_DATABASE_URL` and `TURSO_AUTH_TOKEN`. Add those same two variables in Vercel under **Project Settings → Environment Variables** for Production and Preview, then redeploy. Keep the token secret; do not add it to `NEXT_PUBLIC_*` variables or commit `.env.local`. The app creates its history table automatically on its first API request.

## Quality checks

```bash
npm test
npm run typecheck
npm run lint
npm run build
```

The crypto-format test suite checks key generation, encrypt/decrypt round trips, binary and empty files, Unicode and unsafe filenames, wrong keys, modified ciphertext, malformed headers, and the configured file-size limit.

## Deploy to Vercel through GitHub

1. In Vercel, choose **Add New → Project** and import `gabolguljabeen-code/securevault`.
2. Keep **Root Directory** at `./` and the detected framework as **Next.js**. Use the standard `npm install` install command and `npm run build` build command; leave the output directory at its default.
3. Add `TURSO_DATABASE_URL` and `TURSO_AUTH_TOKEN` to the Vercel project environment variables. Do not add any other variables.
4. Deploy. Future pushes to the connected branch trigger a new deployment. Use the HTTPS deployment URL for the browser Web Crypto API.

The app includes restrictive baseline security headers in `next.config.ts`. Review the Content Security Policy if adding future scripts, analytics, remote assets, or integrations; none are needed by the current app.

## Demonstration for an Information Security class

1. Open the HTTPS deployment or run the app locally. Choose **Encrypt a file** and select a small text or binary file.
2. Encrypt the file and save the `.svault` download. Copy or download the newly generated decryption key and keep it safe.
3. Open the downloaded file in a text editor or inspect its first bytes: the header is visible, while file content is ciphertext.
4. Choose **Decrypt a file**, select that `.svault`, enter its key, and compare the downloaded original with the source.
5. Repeat with a wrong key and with a copy of the vault whose ciphertext has been changed. Both must fail authentication and produce no decrypted file.
6. Reload the page in the same browser and see that operation history is restored from Turso. Clear it with **Clear history**. The downloaded encrypted file can still be decrypted in another browser, because its non-secret parameters travel inside the authenticated file header.

## Limitations and safe use

- The default configurable cap is 64 MiB (`FILE_SIZE_LIMIT` in `lib/crypto.ts`). Web Crypto currently processes an entire file buffer at once, so peak memory use can be several times the file size. Devices with limited memory may fail below this limit; errors are shown and no streaming is simulated.
- Browser memory clearing is best effort in JavaScript. The app overwrites temporary typed arrays when possible, but garbage collection and browser internals control final memory release.
- Keep a separate copy of every generated key. SecureVault cannot recover a lost key. Anyone with a key and its `.svault` file can decrypt it.
- Browser-based encryption does not protect against malware, a compromised device, malicious browser extensions, or a compromised site/deployment that serves altered JavaScript. A secure connection and trusted device matter.
- Metadata such as the original filename and MIME type is visible in the `.svault` header. Do not use sensitive information in filenames if that metadata must remain private.
- Turso stores operation filenames and file sizes for history; do not encrypt files with sensitive names if this metadata must not leave the browser. The database credentials are used only by server-side routes. History is associated with an anonymous browser cookie, not a verified account, and is not shared across devices.
- No encryption tool guarantees that the entire device or application is secure. Do not treat this educational project as a substitute for a reviewed, audited product or an organizational backup policy.
