# 🌐 Full Stack App — Backend (Node.js) + Frontend (React Native with Expo)

![Node.js](https://img.shields.io/badge/Node.js-v18+-green?logo=node.js)
![React Native](https://img.shields.io/badge/React%20Native-Latest-blue?logo=react)
![Expo](https://img.shields.io/badge/Expo-Latest-black?logo=expo)
![License](https://img.shields.io/badge/License-MIT-yellow)

This repository contains both the **Backend (Node.js)** and **Frontend (React Native using Expo)** parts of the application.

---

## 🗂️ Project Structure

```
project-root/
│
├── Backend/                    # Node.js backend API
│   ├── app.js
│   ├── package.json
│   ├── .env
│   ├── .gitignore
│   └── ...
│
└── Frontend/                   # React Native (Expo) mobile app
    ├── App.js
    ├── package.json
    ├── app.json
    ├── .gitignore
    └── ...
```

---

## 📋 Table of Contents

- [Prerequisites](#-prerequisites)
- [Backend Setup](#-backend-setup-nodejs)
- [Frontend Setup](#-frontend-setup-react-native-with-expo)
- [Connecting Frontend & Backend](#-connect-frontend-and-backend)
- [Common Commands](#-common-commands)
- [Tech Stack](#-tech-stack)
- [License](#-license)

---

## ⚙️ Prerequisites

Make sure the following are installed on your system:

- [Node.js](https://nodejs.org/) (v18 or above)
- [npm](https://www.npmjs.com/) or [yarn](https://yarnpkg.com/)
- [Expo CLI](https://docs.expo.dev/get-started/installation/)
- A mobile emulator or [Expo Go app](https://expo.dev/client) on your phone

---

## 🚀 Backend Setup (Node.js)

### Step 1: Navigate to the backend folder

```bash
cd Backend
```

### Step 2: Install dependencies

```bash
npm install
```

### Step 3: Create a `.env` file

Create a `.env` file in the `Backend/` directory with the following variables:

```
PORT=5000
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_secret_key
NODE_ENV=development
```

### Step 4: Run the backend server

```bash
npm start
```

Or during development with auto-reload:

```bash
npx nodemon app.js
```

✅ Backend runs on: `http://localhost:5000`

---

## 📱 Frontend Setup (React Native with Expo)

### Step 1: Navigate to the frontend folder

```bash
cd ../Frontend
```

### Step 2: Install dependencies

```bash
npm install
```

### Step 3: Start the Expo development server

```bash
npx expo start
```

This opens the Expo Dev Tools in your terminal. You can run the app on:

- **Physical Device**: Scan the QR code with Expo Go app
- **Android Emulator**: Press `a`
- **iOS Simulator**: Press `i` (macOS only)
- **Web Browser**: Press `w`

---

## 🔗 Connect Frontend and Backend

Update your API configuration in the frontend (e.g., in `api.js` or `config.js`):

```javascript
// Frontend/api/config.js
export const BASE_URL = "http://<your-local-ip>:5000";

// Example: http://192.168.1.10:5000
```

### Find your local IP address:

**Windows:**
```bash
ipconfig
```

**macOS/Linux:**
```bash
ifconfig
```

Look for **IPv4 Address** or **inet** in the output.

---

## 🧰 Common Commands

### Backend

| Task | Command |
|------|---------|
| Install dependencies | `npm install` |
| Run server | `npm start` |
| Run with auto-reload | `npx nodemon app.js` |
| Run tests | `npm test` |

### Frontend

| Task | Command |
|------|---------|
| Install dependencies | `npm install` |
| Start Expo app | `npx expo start` |
| Run on Android | `a` (after `npx expo start`) |
| Run on iOS | `i` (after `npx expo start`) |
| Run on Web | `w` (after `npx expo start`) |
| Clear cache | `npx expo start --clear` |

---

## 🧠 Tech Stack

### Backend
- **Node.js** - JavaScript runtime
- **Express.js** - Web framework
- **MongoDB** / **PostgreSQL** - Database
- **JWT** - Authentication
- **dotenv** - Environment variables

### Frontend
- **React Native** - Mobile framework
- **Expo** - Development platform
- **React Navigation** - Navigation library
- **Axios** - HTTP client for API calls
- **Redux** / **Context API** - State management

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a new branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add some feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

---

## 🧾 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 📞 Support

If you encounter any issues, please open an [issue](../../issues) on GitHub or contact the maintainers.

---

**Happy Coding! 🚀**
