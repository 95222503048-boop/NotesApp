# Auth App

This project uses Express, MongoDB, bcrypt, and JWT authentication.

## Terminal Commands Used

### Check the project files

```powershell
git status --short
Get-Content .gitignore -ErrorAction SilentlyContinue
```

### Check JavaScript syntax

These commands check that the files can be parsed without syntax errors.

```powershell
node --check main.js
node --check auth.js
```

### Remove the old session dependency

JWT authentication replaced `express-session`, so this package was removed.

```powershell
npm uninstall express-session
```

### Restore tracked local package files

The project tracks some files inside `node_modules`, so this command restored the local package files without adding the dependency back to `package.json`.

```powershell
npm install express-session --no-save --package-lock=false
```

### Test JWT signing and verification

This creates a test token and then verifies it using the JWT secret from `.env`.

```powershell
node -e "require('dotenv').config(); const jwt=require('jsonwebtoken'); const token=jwt.sign({userId:'demo-user',role:'user'},process.env.JWT_SECRET,{expiresIn:'1h'}); const decoded=jwt.verify(token,process.env.JWT_SECRET); if(decoded.userId !== 'demo-user') process.exit(1); console.log('JWT sign/verify check passed')"
```

### Search for old session authentication code

```powershell
grep_search: req.session | express-session | WelcomeBuddy | connect.sid
```

### Check whether `.env` is ignored by Git

```powershell
git check-ignore -v .env
```

### Check for old session references in the lockfile

```powershell
Select-String -Path package-lock.json -Pattern 'express-session' | Select-Object -First 10
```

### Review changed files

```powershell
git status --short
git diff --stat
git diff -- package.json package-lock.json
```

## Start the Application

Make sure MongoDB is running, then start the application with:

```powershell
node main.js
```

The application runs at:

```text
http://localhost:3000
```

## Environment Variables

Copy `.env.example` to `.env` if needed, then set these values:

```env
PORT=3000
DATABASE_URL=mongodb://localhost:27017/auth-app
JWT_SECRET=replace-this-with-a-long-random-secret
JWT_EXPIRES_IN=1h
NODE_ENV=development
```

Never commit `.env` because it contains the JWT secret.
