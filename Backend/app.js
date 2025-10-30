const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require("bcrypt");
const jwt = require('jsonwebtoken');
const SALT_ROUNDS = 10;
require('dotenv').config();
const JWT_SECRET = process.env.JWT_SECRET || "fallback_secret_key";
const { OAuth2Client } = require('google-auth-library');
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB Configuration
const MONGODB_URI = 'mongodb+srv://2rajatd6_db_user:pUg4E9HaGKYz848R@cluster0.y1jptdd.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';

// Connect to MongoDB with improved options
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 30000, // 30 seconds
    socketTimeoutMS: 45000, // 45 seconds
    maxPoolSize: 10, // Maximum number of connections
    minPoolSize: 1, // Minimum number of connections
    maxIdleTimeMS: 30000 // Close connections after 30 seconds of inactivity
});

const db = mongoose.connection;
db.on('error', (error) => {
    console.error('MongoDB connection error:', error);
    console.log('\n❌ MongoDB Connection Failed!');
    console.log('📋 Troubleshooting Steps:');
    console.log('1. Check if MongoDB is running: mongod --version');
    console.log('2. Start MongoDB service:');
    console.log('   - Windows: net start MongoDB');
    console.log('   - macOS: brew services start mongodb-community');
    console.log('   - Linux: sudo systemctl start mongod');
    console.log('3. Check MongoDB status: mongosh (MongoDB Shell)');
    console.log('4. Verify connection string:', MONGODB_URI);
    console.log('\n💡 Alternative: Use MongoDB Atlas (cloud database)');
    console.log('   Sign up at: https://cloud.mongodb.com');
});

db.once('open', () => {
    console.log('📦 Connected to MongoDB:', MONGODB_URI);
});

db.on('disconnected', () => {
    console.log('📦 MongoDB disconnected');
});

db.on('reconnected', () => {
    console.log('📦 MongoDB reconnected');
});

// ====================== MONGODB SCHEMAS ======================

// User Schema
const userSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }, 
    role: { type: String, default: 'user' },
    privateKey: { type: String, required: true },
    publicKey: { type: String, required: true },
    blockchainAddress: { type: String, required: true },
    fileCount: { type: Number, default: 0 },
    lastActive: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now },
    lastLogin: { type: Date }, // NEW: Track last login
    tokenVersion: { type: Number, default: 0 },
}, {
    timestamps: true
});


// File Schema
const fileSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    userId: { type: String, required: true },
    originalName: { type: String, required: true },
    description: { type: String, default: 'No description provided' },
    size: { type: Number, required: true },
    mimetype: { type: String, required: true },
    encryptedData: {
        encrypted: { type: String, required: true },
        algorithm: { type: String, required: true },
        publicKeyHash: { type: String, required: true }
    },
    fileHash: { type: String, required: true, unique: true },
    downloadCount: { type: Number, default: 0 },
    accessCount: { type: Number, default: 0 },
    ipfsHash: { type: String, required: true },
    uploadTime: { type: Date, default: Date.now }
}, {
    timestamps: true
});

// Access Permission Schema
const accessPermissionSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    fileId: { type: String, required: true },
    ownerId: { type: String, required: true },
    recipientId: { type: String, required: true },
    purpose: { type: String, default: 'File access via proxy re-encryption' },
    grantedTime: { type: Date, default: Date.now },
    expirationTime: { type: Date, required: true },
    durationHours: { type: Number, required: true },
    isActive: { type: Boolean, default: true },
    accessCount: { type: Number, default: 0 },
    revokedAt: { type: Date },
    revokedBy: { type: String },
    updatedAt: { type: Date }
}, {
    timestamps: true
});

// Re-encryption Key Schema
const reEncryptionKeySchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true }, // accessId
    reEncryptionKey: { type: String, required: true },
    salt: { type: String, required: true },
    fromUserPublicKey: { type: String, required: true },
    toUserPublicKey: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
}, {
    timestamps: true
});

// Blockchain Block Schema
const blockchainBlockSchema = new mongoose.Schema({
    blockNumber: { type: Number, required: true, unique: true },
    operation: { type: String, required: true },
    data: { type: mongoose.Schema.Types.Mixed, required: true },
    hash: { type: String, required: true },
    previousHash: { type: String, required: true },
    gasUsed: { type: Number, required: true },
    transactionHash: { type: String, required: true },
    timestamp: { type: Date, default: Date.now }
}, {
    timestamps: true
});

// Smart Contract Schema
const smartContractSchema = new mongoose.Schema({
    address: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    deployer: { type: String, required: true },
    deployedAt: { type: Date, default: Date.now },
    functions: { type: [String], required: true }
}, {
    timestamps: true
});

// Proxy Node Stats Schema
const proxyNodeSchema = new mongoose.Schema({
    nodeId: { type: String, required: true, unique: true },
    transformationCount: { type: Number, default: 0 },
    isActive: { type: Boolean, default: true },
    startTime: { type: Date, default: Date.now },
    lastTransformation: { type: Date }
}, {
    timestamps: true
});

const accessRequestSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    fileId: { type: String, required: true },
    requesterId: { type: String, required: true },
    ownerId: { type: String, required: true },
    status: { 
        type: String, 
        enum: ['pending', 'approved', 'rejected'], 
        default: 'pending' 
    },
    purpose: { type: String, default: '' },
    requestedDuration: { type: Number, default: 24 }, // hours
    requestTime: { type: Date, default: Date.now },
    responseTime: { type: Date },
    responseMessage: { type: String },
    respondedBy: { type: String }
});


// Create MongoDB Models
const User = mongoose.model('User', userSchema);
const File = mongoose.model('File', fileSchema);
const AccessPermission = mongoose.model('AccessPermission', accessPermissionSchema);
const ReEncryptionKey = mongoose.model('ReEncryptionKey', reEncryptionKeySchema);
const BlockchainBlock = mongoose.model('BlockchainBlock', blockchainBlockSchema);
const SmartContract = mongoose.model('SmartContract', smartContractSchema);
const ProxyNodeStats = mongoose.model('ProxyNodeStats', proxyNodeSchema);
const AccessRequest = mongoose.model('AccessRequest', accessRequestSchema);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = './uploads';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
        cb(null, uniqueName);
    }
});

const upload = multer({ 
    storage,
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    console.log('Auth Header:', authHeader); // DEBUG
    console.log('Token:', token); // DEBUG

    if (!token) {
        return res.status(401).json({
            success: false,
            error: 'Access token required'
        });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
        console.log('JWT Error:', err); // DEBUG
        console.log('Decoded User:', user); // DEBUG
        
        if (err) {
            return res.status(403).json({
                success: false,
                error: 'Invalid or expired token',
                details: err.message
            });
        }
        req.user = user; // Attach user info to request
        next();
    });
};

// ====================== BLOCKCHAIN SIMULATION WITH MONGODB ======================

class BlockchainSimulator {
    constructor() {
        this.gasPrice = 20000000000; // 20 gwei
        this.initialize();
    }

    async initialize() {
        try {
            // Check if genesis block exists
            const genesisBlock = await BlockchainBlock.findOne({ blockNumber: 1 });
            if (!genesisBlock) {
                await this.addBlock('GENESIS', { message: 'Blockchain initialized' });
                console.log('🔗 Blockchain initialized with genesis block');
            } else {
                console.log('🔗 Blockchain already initialized');
            }
        } catch (error) {
            console.error('Blockchain initialization error:', error);
        }
    }

    async addBlock(operation, data) {
        try {
            const latestBlock = await BlockchainBlock.findOne().sort({ blockNumber: -1 });
            const blockNumber = latestBlock ? latestBlock.blockNumber + 1 : 1;
            const previousHash = latestBlock ? latestBlock.hash : '0x0';

            const block = new BlockchainBlock({
                blockNumber,
                operation,
                data,
                hash: crypto.createHash('sha256').update(JSON.stringify(data) + Date.now()).digest('hex'),
                previousHash,
                gasUsed: Math.floor(Math.random() * 100000) + 21000,
                transactionHash: '0x' + crypto.randomBytes(32).toString('hex'),
                timestamp: new Date()
            });

            await block.save();
            return block;
        } catch (error) {
            console.error('Add block error:', error);
            throw error;
        }
    }

    async deployContract(contractName, deployer) {
        try {
            const contractAddress = '0x' + crypto.randomBytes(20).toString('hex');
            
            const contract = new SmartContract({
                address: contractAddress,
                name: contractName,
                deployer,
                deployedAt: new Date(),
                functions: this.getContractFunctions(contractName)
            });

            await contract.save();
            
            await this.addBlock('CONTRACT_DEPLOYED', {
                contractName,
                contractAddress,
                deployer
            });
            
            return contractAddress;
        } catch (error) {
            console.error('Deploy contract error:', error);
            throw error;
        }
    }

    getContractFunctions(contractName) {
        switch(contractName) {
            case 'FileStorage':
                return ['uploadFile', 'grantAccess', 'revokeAccess', 'verifyAccess', 'getFileInfo'];
            default:
                return [];
        }
    }

    async executeFileUpload(fileHash, owner, metadata) {
        const txHash = '0x' + crypto.randomBytes(32).toString('hex');
        await this.addBlock('FILE_UPLOADED', {
            fileHash,
            owner,
            metadata,
            transactionHash: txHash
        });
        return { success: true, transactionHash: txHash };
    }

    async executeGrantAccess(fileHash, grantee, duration) {
        const txHash = '0x' + crypto.randomBytes(32).toString('hex');
        const expirationTime = new Date(Date.now() + duration * 60 * 60 * 1000);
        
        await this.addBlock('ACCESS_GRANTED', {
            fileHash,
            grantee,
            duration,
            expirationTime: expirationTime.toISOString(),
            transactionHash: txHash
        });
        return { success: true, transactionHash: txHash, expirationTime };
    }

    async executeRevokeAccess(fileHash, grantee) {
        const txHash = '0x' + crypto.randomBytes(32).toString('hex');
        await this.addBlock('ACCESS_REVOKED', {
            fileHash,
            grantee,
            transactionHash: txHash
        });
        return { success: true, transactionHash: txHash };
    }

    async executeVerifyAccess(fileHash, user) {
        try {
            const accessBlocks = await BlockchainBlock.find({
                operation: 'ACCESS_GRANTED',
                'data.fileHash': fileHash,
                'data.grantee': user
            }).sort({ blockNumber: -1 }).limit(1);

            if (accessBlocks.length === 0) {
                return { hasAccess: false };
            }

            const accessBlock = accessBlocks[0];

            const revokeBlock = await BlockchainBlock.findOne({
                operation: 'ACCESS_REVOKED',
                'data.fileHash': fileHash,
                'data.grantee': user,
                blockNumber: { $gt: accessBlock.blockNumber }
            });

            if (revokeBlock) return { hasAccess: false };

            const isExpired = new Date() > new Date(accessBlock.data.expirationTime);
            return { 
                hasAccess: !isExpired, 
                expirationTime: accessBlock.data.expirationTime,
                grantedAt: accessBlock.timestamp
            };
        } catch (error) {
            console.error('Verify access error:', error);
            return { hasAccess: false };
        }
    }

    async executeGetFileInfo(fileHash) {
        try {
            const fileBlock = await BlockchainBlock.findOne({
                operation: 'FILE_UPLOADED',
                'data.fileHash': fileHash
            });
            return fileBlock ? fileBlock.data : null;
        } catch (error) {
            console.error('Get file info error:', error);
            return null;
        }
    }

    async getBlocks(limit = 10) {
        try {
            const blocks = await BlockchainBlock.find()
                .sort({ blockNumber: -1 })
                .limit(limit);
            return blocks;
        } catch (error) {
            console.error('Get blocks error:', error);
            return [];
        }
    }

    async getBlockCount() {
        try {
            return await BlockchainBlock.countDocuments();
        } catch (error) {
            console.error('Get block count error:', error);
            return 0;
        }
    }
}

// ====================== PROXY RE-ENCRYPTION ======================

class ProxyReEncryption {
    constructor() {
        this.keySize = 32; // 256 bits
        this.nonceSize = 16; // 128 bits
    }

    generateKeyPair() {
        const privateKey = crypto.randomBytes(this.keySize);
        const publicKey = this.derivePublicKey(privateKey);
        return {
            privateKey: privateKey.toString('hex'),
            publicKey: publicKey.toString('hex')
        };
    }

    derivePublicKey(privateKey) {
        return crypto.pbkdf2Sync(privateKey, 'public_derivation_salt', 10000, this.keySize, 'sha256');
    }

    encrypt(data, publicKey) {
        try {
            const publicKeyBuffer = Buffer.from(publicKey, 'hex');
            const encryptionKey = crypto.pbkdf2Sync(publicKeyBuffer, 'encryption_salt', 10000, 32, 'sha256');
            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, iv);
            
            let encrypted = cipher.update(data, 'utf8');
            encrypted = Buffer.concat([encrypted, cipher.final()]);
            
            const result = {
                encrypted: Buffer.concat([iv, encrypted]).toString('base64'),
                algorithm: 'aes-256-cbc',
                publicKeyHash: crypto.createHash('sha256').update(publicKeyBuffer).digest('hex').substring(0, 16)
            };
            
            return result;
        } catch (error) {
            throw new Error('Encryption failed: ' + error.message);
        }
    }

    decrypt(encryptedData, privateKey) {
        try {
            const privateKeyBuffer = Buffer.from(privateKey, 'hex');
            const publicKey = this.derivePublicKey(privateKeyBuffer);
            const decryptionKey = crypto.pbkdf2Sync(publicKey, 'encryption_salt', 10000, 32, 'sha256');
            
            const combined = Buffer.from(encryptedData.encrypted, 'base64');
            const iv = combined.slice(0, 16);
            const encrypted = combined.slice(16);
            
            const decipher = crypto.createDecipheriv('aes-256-cbc', decryptionKey, iv);
            let decrypted = decipher.update(encrypted);
            decrypted = Buffer.concat([decrypted, decipher.final()]);
            
            return decrypted.toString('utf8');
        } catch (error) {
            throw new Error('Decryption failed: ' + error.message);
        }
    }

    generateReEncryptionKey(alicePrivateKey, bobPublicKey) {
        try {
            const alicePrivateBuffer = Buffer.from(alicePrivateKey, 'hex');
            const bobPublicBuffer = Buffer.from(bobPublicKey, 'hex');
            const alicePublicKey = this.derivePublicKey(alicePrivateBuffer);
            
            const salt = crypto.randomBytes(16);
            const info = Buffer.from('proxy-re-encryption-key', 'utf8');
            const ikm = Buffer.concat([alicePrivateBuffer, bobPublicBuffer]);
            const prk = crypto.createHmac('sha256', salt).update(ikm).digest();
            const reKey = crypto.createHmac('sha256', prk).update(info).digest();
            
            return {
                reEncryptionKey: reKey.toString('hex'),
                salt: salt.toString('hex'),
                fromUserPublicKey: alicePublicKey.toString('hex'),
                toUserPublicKey: bobPublicKey,
                createdAt: new Date().toISOString()
            };
        } catch (error) {
            throw new Error('Re-encryption key generation failed: ' + error.message);
        }
    }

    proxyReEncrypt(aliceEncryptedData, reEncryptionKeyData, bobPublicKey) {
        try {
            const aliceData = this.decryptForTransformation(aliceEncryptedData, reEncryptionKeyData);
            const bobEncrypted = this.encrypt(aliceData, bobPublicKey);
            
            const result = {
                ...bobEncrypted,
                isReEncrypted: true,
                originalEncryption: aliceEncryptedData,
                reEncryptionKeyHash: crypto.createHash('sha256')
                    .update(reEncryptionKeyData.reEncryptionKey)
                    .digest('hex')
                    .substring(0, 16),
                transformedAt: new Date().toISOString(),
                transformedFor: bobPublicKey
            };
            
            return result;
        } catch (error) {
            throw new Error('Proxy re-encryption failed: ' + error.message);
        }
    }

    decryptForTransformation(encryptedData, reEncryptionKeyData) {
        try {
            const fromPublicKey = Buffer.from(reEncryptionKeyData.fromUserPublicKey, 'hex');
            const decryptionKey = crypto.pbkdf2Sync(fromPublicKey, 'encryption_salt', 10000, 32, 'sha256');
            
            const combined = Buffer.from(encryptedData.encrypted, 'base64');
            const iv = combined.slice(0, 16);
            const encrypted = combined.slice(16);
            
            const decipher = crypto.createDecipheriv('aes-256-cbc', decryptionKey, iv);
            let decrypted = decipher.update(encrypted);
            decrypted = Buffer.concat([decrypted, decipher.final()]);
            
            return decrypted.toString('utf8');
        } catch (error) {
            throw new Error('Transformation decryption failed: ' + error.message);
        }
    }

    decryptReEncrypted(reEncryptedData, bobPrivateKey) {
        try {
            return this.decrypt(reEncryptedData, bobPrivateKey);
        } catch (error) {
            throw new Error('Re-encrypted decryption failed: ' + error.message);
        }
    }

    verifyReEncryptionKey(reKeyData, alicePublicKey, bobPublicKey) {
        try {
            return reKeyData.fromUserPublicKey === alicePublicKey && 
                   reKeyData.toUserPublicKey === bobPublicKey;
        } catch (error) {
            return false;
        }
    }
}

// ====================== PROXY NODE WITH MONGODB ======================

class ProxyNode {
    constructor(nodeId) {
        this.nodeId = nodeId;
        this.pre = new ProxyReEncryption();
        this.initializeInDB();
    }

    async initializeInDB() {
        try {
            const existingNode = await ProxyNodeStats.findOne({ nodeId: this.nodeId });
            if (!existingNode) {
                const nodeStats = new ProxyNodeStats({
                    nodeId: this.nodeId,
                    transformationCount: 0,
                    isActive: true,
                    startTime: new Date()
                });
                await nodeStats.save();
                console.log(`Proxy node ${this.nodeId} initialized in database`);
            }
        } catch (error) {
            console.error(`Error initializing proxy node ${this.nodeId}:`, error);
        }
    }

    async transformData(encryptedData, reEncryptionKeyData, targetPublicKey) {
        try {
            const nodeStats = await ProxyNodeStats.findOne({ nodeId: this.nodeId });
            if (!nodeStats || !nodeStats.isActive) {
                throw new Error(`Proxy node ${this.nodeId} is inactive`);
            }

            if (!reEncryptionKeyData.reEncryptionKey || !reEncryptionKeyData.fromUserPublicKey) {
                throw new Error('Invalid re-encryption key data');
            }

            const transformedData = this.pre.proxyReEncrypt(
                encryptedData, 
                reEncryptionKeyData, 
                targetPublicKey
            );
            
            // Update transformation count
            await ProxyNodeStats.updateOne(
                { nodeId: this.nodeId },
                { 
                    $inc: { transformationCount: 1 },
                    $set: { lastTransformation: new Date() }
                }
            );
            
            const result = {
                success: true,
                transformedData,
                nodeId: this.nodeId,
                transformationId: uuidv4(),
                timestamp: new Date().toISOString(),
                transformationCount: nodeStats.transformationCount + 1
            };

            console.log(`Proxy node ${this.nodeId} completed transformation #${nodeStats.transformationCount + 1}`);
            
            return result;
        } catch (error) {
            console.error(`Proxy node ${this.nodeId} transformation error:`, error.message);
            throw new Error(`Proxy transformation failed on node ${this.nodeId}: ${error.message}`);
        }
    }

    async getStats() {
        try {
            const nodeStats = await ProxyNodeStats.findOne({ nodeId: this.nodeId });
            if (!nodeStats) return null;

            const uptime = Date.now() - nodeStats.startTime.getTime();
            return {
                nodeId: this.nodeId,
                transformationCount: nodeStats.transformationCount,
                isActive: nodeStats.isActive,
                uptimeMs: uptime,
                uptimeHours: Math.round(uptime / (1000 * 60 * 60) * 100) / 100,
                lastTransformation: nodeStats.lastTransformation
            };
        } catch (error) {
            console.error(`Error getting stats for node ${this.nodeId}:`, error);
            return null;
        }
    }

    async activate() {
        try {
            await ProxyNodeStats.updateOne(
                { nodeId: this.nodeId },
                { $set: { isActive: true } }
            );
            console.log(`Proxy node ${this.nodeId} activated`);
        } catch (error) {
            console.error(`Error activating node ${this.nodeId}:`, error);
        }
    }

    async deactivate() {
        try {
            await ProxyNodeStats.updateOne(
                { nodeId: this.nodeId },
                { $set: { isActive: false } }
            );
            console.log(`Proxy node ${this.nodeId} deactivated`);
        } catch (error) {
            console.error(`Error deactivating node ${this.nodeId}:`, error);
        }
    }
}

// Initialize components
let blockchain;
let contractAddress;
const pre = new ProxyReEncryption();
const proxyNodes = new Map();

// Initialize system asynchronously
async function initializeSystem() {
    try {
        // Wait for MongoDB connection before initializing system
        if (mongoose.connection.readyState !== 1) {
            console.log('⏳ Waiting for MongoDB connection...');
            await new Promise((resolve, reject) => {
                const timeout = setTimeout(() => {
                    reject(new Error('MongoDB connection timeout after 30 seconds'));
                }, 30000);

                if (mongoose.connection.readyState === 1) {
                    clearTimeout(timeout);
                    resolve();
                } else {
                    mongoose.connection.once('open', () => {
                        clearTimeout(timeout);
                        resolve();
                    });
                    mongoose.connection.once('error', (error) => {
                        clearTimeout(timeout);
                        reject(error);
                    });
                }
            });
        }

        blockchain = new BlockchainSimulator();
        await blockchain.initialize();

        // Deploy smart contract
        contractAddress = await blockchain.deployContract('FileStorage', 'system');
        console.log(`📜 Smart Contract deployed at: ${contractAddress}`);

        // Initialize proxy nodes
        const nodeIds = ['proxy-node-1', 'proxy-node-2', 'proxy-node-3'];
        for (const nodeId of nodeIds) {
            const proxyNode = new ProxyNode(nodeId);
            proxyNodes.set(nodeId, proxyNode);
        }

        console.log('🔧 System initialization completed');
    } catch (error) {
        console.error('❌ System initialization error:', error.message);
        console.log('\n💡 System will continue running but some features may not work properly');
        console.log('Please fix the MongoDB connection and restart the application');
    }
}

// Call initialization
initializeSystem();



// ====================== UTILITY FUNCTIONS ======================


function generateFileHash(content) {
    return crypto.createHash('sha256').update(content).digest('hex');
}

async function selectProxyNode() {
    try {
        const activeNodes = await ProxyNodeStats.find({ isActive: true });
        if (activeNodes.length === 0) {
            throw new Error('No active proxy nodes available');
        }
        
        // Select node with least transformations for load balancing
        const leastBusyNode = activeNodes.reduce((least, current) => 
            current.transformationCount < least.transformationCount ? current : least
        );
        
        return proxyNodes.get(leastBusyNode.nodeId);
    } catch (error) {
        console.error('Error selecting proxy node:', error);
        throw error;
    }
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

function getFileType(mimetype) {
    if (!mimetype) return 'Unknown';
    
    if (mimetype.startsWith('image/')) return 'Image';
    if (mimetype.startsWith('video/')) return 'Video';
    if (mimetype.startsWith('audio/')) return 'Audio';
    if (mimetype.startsWith('text/')) return 'Text';
    if (mimetype.includes('pdf')) return 'PDF';
    if (mimetype.includes('word') || mimetype.includes('document')) return 'Document';
    if (mimetype.includes('sheet') || mimetype.includes('excel')) return 'Spreadsheet';
    if (mimetype.includes('presentation') || mimetype.includes('powerpoint')) return 'Presentation';
    if (mimetype.includes('zip') || mimetype.includes('rar') || mimetype.includes('compressed')) return 'Archive';
    
    return 'Other';
}

//=======Google Signin=======
async function verifyGoogleToken(token) {
    try {
        const ticket = await googleClient.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID,
        });

        const payload = ticket.getPayload();
        return {
            success: true,
            data: {
                googleId: payload.sub,
                email: payload.email,
                name: payload.name,
                picture: payload.picture,
                email_verified: payload.email_verified,
            }
        };
    } catch (error) {
        return {
            success: false,
            error: 'Invalid Google token: ' + error.message
        };
    }
}

// ====================== API ROUTES WITH MONGODB ======================

// Health Check
app.get('/api/health', async (req, res) => {
    try {
        const [
            userCount,
            fileCount,
            permissionCount,
            activePermissionCount,
            blockCount,
            proxyStats
        ] = await Promise.all([
            User.countDocuments(),
            File.countDocuments(),
            AccessPermission.countDocuments(),
            AccessPermission.countDocuments({ 
                isActive: true, 
                expirationTime: { $gt: new Date() } 
            }),
            blockchain.getBlockCount(),
            ProxyNodeStats.find()
        ]);

        const totalTransformations = proxyStats.reduce((sum, node) => sum + node.transformationCount, 0);

        res.json({
            success: true,
            message: 'MongoDB-Only PRE File Upload API is running',
            timestamp: new Date().toISOString(),
            database: {
                connected: mongoose.connection.readyState === 1,
                uri: MONGODB_URI.replace(/\/\/.*@/, '//***:***@') // Hide credentials
            },
            stats: {
                totalUsers: userCount,
                totalFiles: fileCount,
                totalPermissions: permissionCount,
                activePermissions: activePermissionCount,
                blockchainBlocks: blockCount,
                smartContract: contractAddress,
                proxyNodes: proxyStats.map(node => ({
                    nodeId: node.nodeId,
                    transformationCount: node.transformationCount,
                    isActive: node.isActive,
                    lastTransformation: node.lastTransformation
                })),
                totalTransformations
            }
        });
    } catch (error) {
        console.error('Health check error:', error);
        res.status(500).json({
            success: false,
            error: 'Health check failed: ' + error.message
        });
    }
});

// Register User
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password, role } = req.body;
        
        // Validation
        if (!username || !email || !password) {
            return res.status(400).json({
                success: false,
                error: 'Username, email, and password are required'
            });
        }

        // Email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid email format'
            });
        }

        // Password validation
        if (password.length < 8) {
            return res.status(400).json({
                success: false,
                error: 'Password must be at least 8 characters long'
            });
        }

        // Check password strength (optional but recommended)
        const passwordStrengthRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/;
        if (!passwordStrengthRegex.test(password)) {
            return res.status(400).json({
                success: false,
                error: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
            });
        }

        // Check if user exists
        const existingUser = await User.findOne({
            $or: [{ email: email.toLowerCase() }, { username: username }]
        });

        if (existingUser) {
            return res.status(409).json({
                success: false,
                error: 'Username or email already exists'
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

        const userId = uuidv4();
        const keyPair = pre.generateKeyPair();
        
        const user = new User({
            id: userId,
            username: username.trim(),
            email: email.toLowerCase().trim(),
            password: hashedPassword, // Store hashed password
            role: role || 'user',
            privateKey: keyPair.privateKey,
            publicKey: keyPair.publicKey,
            blockchainAddress: '0x' + crypto.randomBytes(20).toString('hex'),
            fileCount: 0,
            lastActive: new Date()
        });

        await user.save();

        // Record on blockchain
        await blockchain.addBlock('USER_REGISTERED', {
            userId,
            username: user.username,
            email: user.email,
            role: user.role,
            blockchainAddress: user.blockchainAddress,
            publicKey: keyPair.publicKey
        });

        console.log(`New user registered: ${username} (${email})`);

        const token = jwt.sign(
            { id: user.id, username: user.username, email: user.email },
            JWT_SECRET,
            { expiresIn: "7d" }
        );
        

        res.json({
            success: true,
            message: "User registered successfully",
            data: {
              user: {
                id: userId,
                username: user.username,
                email: user.email,
                role: user.role,
                blockchainAddress: user.blockchainAddress,
                publicKey: keyPair.publicKey,
                createdAt: user.createdAt
              },
              token, 
            },
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            success: false,
            error: 'Registration failed: ' + error.message
        });
    }
});

// ====================== NEW LOGIN ENDPOINT ======================

app.post('/api/login', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        // Validation
        if ((!username && !email) || !password) {
            return res.status(400).json({
                success: false,
                error: 'Username/email and password are required'
            });
        }

        // Find user by username or email
        const user = await User.findOne({
            $or: [
                { username: username },
                { email: email ? email.toLowerCase() : undefined }
            ].filter(Boolean)
        });

        if (!user) {
            return res.status(401).json({
                success: false,
                error: 'Invalid credentials'
            });
        }

        // Verify password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        
        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                error: 'Invalid credentials'
            });
        }

        // Update last login and last active
        await User.updateOne(
            { id: user.id },
            { 
                $set: { 
                    lastLogin: new Date(),
                    lastActive: new Date() 
                }
            }
        );

        // Record on blockchain
        await blockchain.addBlock('USER_LOGIN', {
            userId: user.id,
            username: user.username,
            email: user.email,
            loginTime: new Date().toISOString(),
            blockchainAddress: user.blockchainAddress
        });

        const token = jwt.sign(
        { id: user.id, username: user.username, email: user.email },
            JWT_SECRET,
            { expiresIn: "7d" }
        );

        console.log(`User logged in: ${user.username} (${user.email})`);

        res.json({
        success: true,
        message: "Login successful",
        data: {
            user: {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
            blockchainAddress: user.blockchainAddress,
            publicKey: user.publicKey,
            },
            token, 
        }, 
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            error: 'Login failed: ' + error.message
        });
    }
});

//========Google Sigin Code==========


app.post('/api/google-signin', async (req, res) => {
    try {
        const { googleToken, email, name, picture } = req.body;

        // Validation
        if (!googleToken || !email) {
            return res.status(400).json({
                success: false,
                error: 'Google token and email are required'
            });
        }

        // Verify Google token
        const tokenVerification = await verifyGoogleToken(googleToken);
        if (!tokenVerification.success) {
            return res.status(401).json({
                success: false,
                error: tokenVerification.error
            });
        }

        const googleData = tokenVerification.data;

        // Check if user exists by email
        let user = await User.findOne({ email: email.toLowerCase().trim() });

        if (!user) {
            // User doesn't exist, create a new one
            const userId = uuidv4();
            const keyPair = pre.generateKeyPair();
            
            // Generate username from email or name
            let username = name 
                ? name.replace(/\s+/g, '_').toLowerCase() 
                : email.split('@')[0];
            
            // Ensure username is unique
            let baseUsername = username;
            let counter = 1;
            let existingUser = await User.findOne({ username });
            while (existingUser) {
                username = `${baseUsername}${counter}`;
                existingUser = await User.findOne({ username });
                counter++;
            }

            // Create a random password (user won't need it since they use Google)
            const randomPassword = crypto.randomBytes(32).toString('hex');
            const hashedPassword = await bcrypt.hash(randomPassword, 10);

            user = new User({
                id: userId,
                username: username,
                email: email.toLowerCase().trim(),
                password: hashedPassword,
                googleId: googleData.googleId,
                role: 'user',
                privateKey: keyPair.privateKey,
                publicKey: keyPair.publicKey,
                blockchainAddress: '0x' + crypto.randomBytes(20).toString('hex'),
                profilePicture: picture || null,
                fileCount: 0,
                lastActive: new Date(),
                lastLogin: new Date(),
                googleVerified: googleData.email_verified
            });

            await user.save();

            // Record on blockchain
            await blockchain.addBlock('USER_REGISTERED_GOOGLE', {
                userId,
                username: user.username,
                email: user.email,
                googleId: googleData.googleId,
                blockchainAddress: user.blockchainAddress,
                publicKey: keyPair.publicKey
            });

            console.log(`New Google user registered: ${username} (${email})`);
        } else {
            // User exists, update last login
            if (!user.googleId) {
                user.googleId = googleData.googleId;
            }
            
            user.lastLogin = new Date();
            user.lastActive = new Date();
            
            if (picture && !user.profilePicture) {
                user.profilePicture = picture;
            }
            
            await user.save();

            // Record on blockchain
            await blockchain.addBlock('USER_LOGIN_GOOGLE', {
                userId: user.id,
                username: user.username,
                email: user.email,
                loginTime: new Date().toISOString(),
                blockchainAddress: user.blockchainAddress
            });

            console.log(`Google user logged in: ${user.username} (${email})`);
        }

        // Generate JWT token
        const token = jwt.sign(
            { 
                id: user.id, 
                username: user.username, 
                email: user.email,
                googleId: user.googleId 
            },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        res.json({
            success: true,
            message: user.lastLogin === new Date() ? "User registered successfully via Google" : "Login successful via Google",
            data: {
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    role: user.role,
                    blockchainAddress: user.blockchainAddress,
                    publicKey: user.publicKey,
                    profilePicture: user.profilePicture,
                    createdAt: user.createdAt
                },
                token
            }
        });

    } catch (error) {
        console.error('Google Sign-In error:', error);
        res.status(500).json({
            success: false,
            error: 'Google sign-in failed: ' + error.message
        });
    }
});

// ====================== GOOGLE SIGN-UP ENDPOINT ======================

app.post('/api/google-signup', async (req, res) => {
    try {
        const { googleToken, email, name, picture } = req.body;

        // Validation
        if (!googleToken || !email) {
            return res.status(400).json({
                success: false,
                error: 'Google token and email are required'
            });
        }

        // Verify Google token
        const tokenVerification = await verifyGoogleToken(googleToken);
        if (!tokenVerification.success) {
            return res.status(401).json({
                success: false,
                error: tokenVerification.error
            });
        }

        const googleData = tokenVerification.data;
        const emailLower = email.toLowerCase().trim();

        // Check if user already exists
        const existingUser = await User.findOne({
            $or: [
                { email: emailLower },
                { googleId: googleData.googleId }
            ]
        });

        if (existingUser) {
            return res.status(409).json({
                success: false,
                error: 'Account already exists with this email. Please sign in instead.'
            });
        }

        // Create new user
        const userId = uuidv4();
        const keyPair = pre.generateKeyPair();
        
        // Generate username from email or name
        let username = name 
            ? name.replace(/\s+/g, '_').toLowerCase() 
            : email.split('@')[0];
        
        // Ensure username is unique
        let baseUsername = username;
        let counter = 1;
        let userCheck = await User.findOne({ username });
        while (userCheck) {
            username = `${baseUsername}${counter}`;
            userCheck = await User.findOne({ username });
            counter++;
        }

        // Create a random password (user won't need it since they use Google)
        const randomPassword = crypto.randomBytes(32).toString('hex');
        const hashedPassword = await bcrypt.hash(randomPassword, 10);

        const user = new User({
            id: userId,
            username: username,
            email: emailLower,
            password: hashedPassword,
            googleId: googleData.googleId,
            role: 'user',
            privateKey: keyPair.privateKey,
            publicKey: keyPair.publicKey,
            blockchainAddress: '0x' + crypto.randomBytes(20).toString('hex'),
            profilePicture: picture || null,
            fileCount: 0,
            lastActive: new Date(),
            lastLogin: new Date(),
            googleVerified: googleData.email_verified
        });

        await user.save();

        // Record on blockchain
        await blockchain.addBlock('USER_REGISTERED_GOOGLE', {
            userId,
            username: user.username,
            email: user.email,
            googleId: googleData.googleId,
            blockchainAddress: user.blockchainAddress,
            publicKey: keyPair.publicKey
        });

        console.log(`New Google user registered: ${username} (${email})`);

        // Generate JWT token
        const token = jwt.sign(
            { 
                id: user.id, 
                username: user.username, 
                email: user.email,
                googleId: user.googleId 
            },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        res.json({
            success: true,
            message: "User registered successfully via Google",
            data: {
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    role: user.role,
                    blockchainAddress: user.blockchainAddress,
                    publicKey: keyPair.publicKey,
                    profilePicture: user.profilePicture,
                    createdAt: user.createdAt
                },
                token
            }
        });

    } catch (error) {
        console.error('Google Sign-Up error:', error);
        res.status(500).json({
            success: false,
            error: 'Google sign-up failed: ' + error.message
        });
    }
});

// ====================== LINK EXISTING ACCOUNT WITH GOOGLE ======================

app.post('/api/link-google', authenticateToken, async (req, res) => {
    try {
        const { googleToken } = req.body;
        const userId = req.user.id;

        if (!googleToken) {
            return res.status(400).json({
                success: false,
                error: 'Google token is required'
            });
        }

        // Verify Google token
        const tokenVerification = await verifyGoogleToken(googleToken);
        if (!tokenVerification.success) {
            return res.status(401).json({
                success: false,
                error: tokenVerification.error
            });
        }

        const googleData = tokenVerification.data;

        // Find user
        const user = await User.findOne({ id: userId });
        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        // Check if Google ID is already linked to another account
        const existingGoogleUser = await User.findOne({ 
            googleId: googleData.googleId,
            id: { $ne: userId }
        });

        if (existingGoogleUser) {
            return res.status(409).json({
                success: false,
                error: 'This Google account is already linked to another user'
            });
        }

        // Link Google account
        user.googleId = googleData.googleId;
        user.googleVerified = googleData.email_verified;
        if (googleData.picture && !user.profilePicture) {
            user.profilePicture = googleData.picture;
        }
        
        await user.save();

        // Record on blockchain
        await blockchain.addBlock('GOOGLE_ACCOUNT_LINKED', {
            userId: user.id,
            username: user.username,
            email: user.email,
            googleId: googleData.googleId,
            linkedAt: new Date().toISOString()
        });

        console.log(`Google account linked for user: ${user.username}`);

        res.json({
            success: true,
            message: 'Google account linked successfully',
            data: {
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    googleId: user.googleId,
                    profilePicture: user.profilePicture
                }
            }
        });

    } catch (error) {
        console.error('Link Google error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to link Google account: ' + error.message
        });
    }
});

// ====================== VERIFY GOOGLE TOKEN (PUBLIC ENDPOINT) ======================

app.post('/api/verify-google-token', async (req, res) => {
    try {
        const { googleToken } = req.body;

        if (!googleToken) {
            return res.status(400).json({
                success: false,
                error: 'Google token is required'
            });
        }

        const tokenVerification = await verifyGoogleToken(googleToken);
        
        if (!tokenVerification.success) {
            return res.status(401).json({
                success: false,
                error: tokenVerification.error
            });
        }

        res.json({
            success: true,
            message: 'Google token verified successfully',
            data: tokenVerification.data
        });

    } catch (error) {
        console.error('Token verification error:', error);
        res.status(500).json({
            success: false,
            error: 'Token verification failed: ' + error.message
        });
    }
});

// ====================== CHANGE PASSWORD ENDPOINT (BONUS) ======================

app.post('/api/change-password', async (req, res) => {
    try {
        const { userId, currentPassword, newPassword } = req.body;
        
        // Validation
        if (!userId || !currentPassword || !newPassword) {
            return res.status(400).json({
                success: false,
                error: 'User ID, current password, and new password are required'
            });
        }

        // New password validation
        if (newPassword.length < 8) {
            return res.status(400).json({
                success: false,
                error: 'New password must be at least 8 characters long'
            });
        }

        const passwordStrengthRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/;
        if (!passwordStrengthRegex.test(newPassword)) {
            return res.status(400).json({
                success: false,
                error: 'New password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
            });
        }

        // Find user
        const user = await User.findOne({ id: userId });
        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        // Verify current password
        const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
        if (!isCurrentPasswordValid) {
            return res.status(401).json({
                success: false,
                error: 'Current password is incorrect'
            });
        }

        // Check if new password is same as current
        const isSamePassword = await bcrypt.compare(newPassword, user.password);
        if (isSamePassword) {
            return res.status(400).json({
                success: false,
                error: 'New password must be different from current password'
            });
        }

        // Hash new password
        const hashedNewPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);

        // Update password
        await User.updateOne(
            { id: userId },
            { $set: { password: hashedNewPassword } }
        );

        // Record on blockchain
        await blockchain.addBlock('PASSWORD_CHANGED', {
            userId: user.id,
            username: user.username,
            changedAt: new Date().toISOString()
        });

        console.log(`Password changed for user: ${user.username}`);

        res.json({
            success: true,
            message: 'Password changed successfully'
        });

    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to change password: ' + error.message
        });
    }
});

// ====================== FORGOT PASSWORD / RESET (BASIC) ======================

app.post('/api/reset-password', async (req, res) => {
    try {
        const { email, username, oldPassword, newPassword } = req.body;
        
        // Validation
        if ((!email && !username) || !oldPassword || !newPassword) {
            return res.status(400).json({
                success: false,
                error: 'Email/username, old password, and new password are required'
            });
        }

        // New password validation
        if (newPassword.length < 8) {
            return res.status(400).json({
                success: false,
                error: 'New password must be at least 8 characters long'
            });
        }

        const passwordStrengthRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/;
        if (!passwordStrengthRegex.test(newPassword)) {
            return res.status(400).json({
                success: false,
                error: 'New password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
            });
        }

        // Find user
        const user = await User.findOne({
            $or: [
                { email: email ? email.toLowerCase() : undefined },
                { username: username }
            ].filter(Boolean)
        });

        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        // Verify old password
        const isOldPasswordValid = await bcrypt.compare(oldPassword, user.password);
        if (!isOldPasswordValid) {
            return res.status(401).json({
                success: false,
                error: 'Old password is incorrect'
            });
        }

        // Check if new password is same as old one
        const isSamePassword = await bcrypt.compare(newPassword, user.password);
        if (isSamePassword) {
            return res.status(400).json({
                success: false,
                error: 'New password must be different from old password'
            });
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);

        // Update password
        await User.updateOne(
            { id: user.id },
            { $set: { password: hashedPassword } }
        );

        // Record on blockchain
        await blockchain.addBlock('PASSWORD_RESET', {
            userId: user.id,
            username: user.username,
            resetAt: new Date().toISOString()
        });

        console.log(`Password reset successfully for user: ${user.username}`);

        res.json({
            success: true,
            message: 'Password has been reset successfully'
        });

    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to reset password: ' + error.message
        });
    }
});

app.get('/api/me', authenticateToken, async (req, res) => {
    try {
        // `req.user` comes from your JWT payload
        const user = await User.findOne({ id: req.user.id }).select('-password -privateKey');

        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        res.json({
            success: true,
            message: 'User details fetched successfully',
            data: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role,
                blockchainAddress: user.blockchainAddress,
                publicKey: user.publicKey,
                createdAt: user.createdAt,
                lastActive: user.lastActive
            }
        });
    } catch (error) {
        console.error('Fetch user error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch user: ' + error.message
        });
    }
});


// Upload File
app.post('/api/upload', upload.single('file'), async (req, res) => {
    try {
        const { userId, description } = req.body;
        
        if (!req.file) {
            return res.status(400).json({
                success: false,
                error: 'No file uploaded'
            });
        }

        const user = await User.findOne({ id: userId });
        if (!user) {
            fs.unlinkSync(req.file.path);
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        const fileBuffer = fs.readFileSync(req.file.path);
        const fileBase64 = fileBuffer.toString('base64');
        const encryptedData = pre.encrypt(fileBase64, user.publicKey);
        const fileHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
        
        const fileId = uuidv4();
        const fileRecord = new File({
            id: fileId,
            userId,
            originalName: req.file.originalname,
            description: description || 'No description provided',
            size: req.file.size,
            mimetype: req.file.mimetype,
            encryptedData,
            fileHash,
            downloadCount: 0,
            accessCount: 0,
            ipfsHash: 'Qm' + crypto.randomBytes(32).toString('base64').replace(/[^a-zA-Z0-9]/g, '').substring(0, 44),
            uploadTime: new Date()
        });

        await fileRecord.save();

        // Update user file count
        await User.updateOne({ id: userId }, { 
            $inc: { fileCount: 1 },
            $set: { lastActive: new Date() }
        });

        // Record on blockchain via smart contract
        const contractResult = await blockchain.executeFileUpload(fileHash, user.blockchainAddress, {
            fileId,
            originalName: req.file.originalname,
            description: fileRecord.description,
            size: req.file.size,
            mimetype: req.file.mimetype,
            ipfsHash: fileRecord.ipfsHash,
            encryptionAlgorithm: encryptedData.algorithm
        });

        // Clean up temp file
        fs.unlinkSync(req.file.path);

        console.log(`File uploaded by ${user.username}: ${req.file.originalname} (${req.file.size} bytes)`);

        res.json({
            success: true,
            message: 'File uploaded and encrypted successfully',
            file: {
                id: fileId,
                originalName: req.file.originalname,
                description: fileRecord.description,
                size: req.file.size,
                mimetype: req.file.mimetype,
                uploadTime: fileRecord.uploadTime,
                fileHash,
                ipfsHash: fileRecord.ipfsHash,
                encryptionAlgorithm: encryptedData.algorithm
            },
            blockchain: {
                transactionHash: contractResult.transactionHash,
                contractAddress
            }
        });

    } catch (error) {
        if (req.file && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }
        console.error('Upload error:', error);
        res.status(500).json({
            success: false,
            error: 'File upload failed: ' + error.message
        });
    }
});

// Grant Access with improved PRE
app.post('/api/grant-access', async (req, res) => {
    try {
        const { ownerId, recipientId, fileId, durationHours, purpose } = req.body;

        const [owner, recipient, file] = await Promise.all([
            User.findOne({ id: ownerId }),
            User.findOne({ id: recipientId }),
            File.findOne({ id: fileId })
        ]);

        if (!owner || !recipient || !file) {
            return res.status(404).json({
                success: false,
                error: 'Owner, recipient, or file not found'
            });
        }

        if (file.userId !== ownerId) {
            return res.status(403).json({
                success: false,
                error: 'Only file owner can grant access'
            });
        }

        if (ownerId === recipientId) {
            return res.status(400).json({
                success: false,
                error: 'Cannot grant access to yourself'
            });
        }

        // Generate re-encryption key
        const reKeyData = pre.generateReEncryptionKey(owner.privateKey, recipient.publicKey);
        
        if (!pre.verifyReEncryptionKey(reKeyData, owner.publicKey, recipient.publicKey)) {
            return res.status(500).json({
                success: false,
                error: 'Invalid re-encryption key generated'
            });
        }
        
        const accessId = `${fileId}_${recipientId}`;
        const duration = durationHours || 24;
        const expirationTime = new Date(Date.now() + duration * 60 * 60 * 1000);

        // Check if permission already exists
        let permission = await AccessPermission.findOne({ id: accessId });
        
        if (permission) {
            // Update existing permission
            permission.expirationTime = expirationTime;
            permission.durationHours = duration;
            permission.isActive = true;
            permission.purpose = purpose || 'File access via proxy re-encryption';
            permission.updatedAt = new Date();
            await permission.save();
        } else {
            // Create new permission
            permission = new AccessPermission({
                id: accessId,
                fileId,
                ownerId,
                recipientId,
                purpose: purpose || 'File access via proxy re-encryption',
                grantedTime: new Date(),
                expirationTime,
                durationHours: duration,
                isActive: true,
                accessCount: 0
            });
            await permission.save();
        }

        // Store/update re-encryption key
        await ReEncryptionKey.findOneAndUpdate(
            { id: accessId },
            {
                id: accessId,
                reEncryptionKey: reKeyData.reEncryptionKey,
                salt: reKeyData.salt,
                fromUserPublicKey: reKeyData.fromUserPublicKey,
                toUserPublicKey: reKeyData.toUserPublicKey,
                createdAt: new Date()
            },
            { upsert: true }
        );

        // Record on blockchain
        const contractResult = await blockchain.executeGrantAccess(file.fileHash, recipient.blockchainAddress, duration);

        console.log(`Access granted: ${owner.username} -> ${recipient.username} for file ${file.originalName}`);

        res.json({
            success: true,
            message: 'Access granted successfully via proxy re-encryption',
            permission: {
                id: accessId,
                ownerName: owner.username,
                recipientName: recipient.username,
                fileName: file.originalName,
                purpose: permission.purpose,
                grantedTime: permission.grantedTime,
                expirationTime: expirationTime.toISOString(),
                durationHours: duration
            },
            blockchain: {
                transactionHash: contractResult.transactionHash,
                contractAddress
            },
            preDetails: {
                reEncryptionKeyHash: crypto.createHash('sha256')
                    .update(reKeyData.reEncryptionKey)
                    .digest('hex')
                    .substring(0, 16),
                fromUserPublicKey: reKeyData.fromUserPublicKey.substring(0, 20) + '...',
                toUserPublicKey: reKeyData.toUserPublicKey.substring(0, 20) + '...'
            }
        });

    } catch (error) {
        console.error('Grant access error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to grant access: ' + error.message
        });
    }
});

// Access File via PRE
app.post('/api/access-file', async (req, res) => {
    try {
        const { userId, fileId } = req.body;

        const [user, file] = await Promise.all([
            User.findOne({ id: userId }),
            File.findOne({ id: fileId })
        ]);

        if (!user || !file) {
            return res.status(404).json({
                success: false,
                error: 'User or file not found'
            });
        }

        let decryptedContent;
        let accessMethod;

        // Update user activity
        await User.updateOne({ id: userId }, { $set: { lastActive: new Date() } });

        if (file.userId === userId) {
            // Direct access - user owns the file
            decryptedContent = pre.decrypt(file.encryptedData, user.privateKey);
            accessMethod = 'direct_owner';
            
            await File.updateOne(
                { id: fileId },
                { $inc: { downloadCount: 1, accessCount: 1 } }
            );
            
            console.log(`Direct access: ${user.username} accessed own file: ${file.originalName}`);
        } else {
            // PRE access logic
            const accessId = `${fileId}_${userId}`;
            const permission = await AccessPermission.findOne({ id: accessId });

            if (!permission || !permission.isActive) {
                return res.status(403).json({
                    success: false,
                    error: 'Access permission not found or has been revoked'
                });
            }

            if (new Date() > new Date(permission.expirationTime)) {
                await AccessPermission.updateOne({ id: accessId }, { $set: { isActive: false } });
                return res.status(403).json({
                    success: false,
                    error: 'Access permission has expired'
                });
            }

            // Verify blockchain permission
            const blockchainAccess = await blockchain.executeVerifyAccess(file.fileHash, user.blockchainAddress);
            if (!blockchainAccess.hasAccess) {
                return res.status(403).json({
                    success: false,
                    error: 'Blockchain access verification failed'
                });
            }

            // Get re-encryption key data
            const reKeyData = await ReEncryptionKey.findOne({ id: accessId });
            if (!reKeyData) {
                return res.status(500).json({
                    success: false,
                    error: 'Re-encryption key not found - permission may be corrupted'
                });
            }

            // Select and use proxy node for transformation
            const proxyNode = await selectProxyNode();
            console.log(`Using proxy node: ${proxyNode.nodeId} for transformation`);

            const transformResult = await proxyNode.transformData(
                file.encryptedData,
                reKeyData,
                user.publicKey
            );

            // User decrypts the transformed data with their private key
            decryptedContent = pre.decryptReEncrypted(
                transformResult.transformedData,
                user.privateKey
            );

            accessMethod = 'proxy_re_encryption';
            
            await Promise.all([
                File.updateOne({ id: fileId }, { $inc: { downloadCount: 1, accessCount: 1 } }),
                AccessPermission.updateOne({ id: accessId }, { $inc: { accessCount: 1 } })
            ]);

            // Log successful PRE access on blockchain
            await blockchain.addBlock('FILE_ACCESSED_VIA_PRE', {
                fileId,
                fileHash: file.fileHash,
                userId,
                userAddress: user.blockchainAddress,
                proxyNodeId: proxyNode.nodeId,
                transformationId: transformResult.transformationId,
                accessTime: new Date().toISOString(),
                fileName: file.originalName,
                accessMethod: 'proxy_re_encryption'
            });

            console.log(`PRE access: ${user.username} accessed ${file.originalName} via proxy node ${proxyNode.nodeId}`);
        }

        res.json({
            success: true,
            message: `File accessed successfully via ${accessMethod.replace('_', ' ')}`,
            file: {
                id: file.id,
                originalName: file.originalName,
                description: file.description,
                size: file.size,
                mimetype: file.mimetype,
                uploadTime: file.uploadTime,
                downloadCount: file.downloadCount + 1,
                accessCount: file.accessCount + 1
            },
            content: decryptedContent,
            accessDetails: {
                method: accessMethod,
                accessTime: new Date().toISOString(),
                userId: user.id,
                username: user.username
            }
        });

    } catch (error) {
        console.error('File access error:', error);
        res.status(500).json({
            success: false,
            error: 'File access failed: ' + error.message
        });
    }
});

// Revoke Access
app.post('/api/revoke-access', async (req, res) => {
    try {
        const { ownerId, recipientId, fileId } = req.body;

        const [owner, recipient, file] = await Promise.all([
            User.findOne({ id: ownerId }),
            User.findOne({ id: recipientId }),
            File.findOne({ id: fileId })
        ]);

        if (!owner || !recipient || !file) {
            return res.status(404).json({
                success: false,
                error: 'Owner, recipient, or file not found'
            });
        }

        if (file.userId !== ownerId) {
            return res.status(403).json({
                success: false,
                error: 'Only file owner can revoke access'
            });
        }

        const accessId = `${fileId}_${recipientId}`;
        const permission = await AccessPermission.findOne({ id: accessId });

        if (!permission) {
            return res.status(404).json({
                success: false,
                error: 'Access permission not found'
            });
        }

        if (!permission.isActive) {
            return res.status(400).json({
                success: false,
                error: 'Permission is already revoked'
            });
        }

        // Revoke permission
        await AccessPermission.updateOne(
            { id: accessId },
            {
                $set: {
                    isActive: false,
                    revokedAt: new Date(),
                    revokedBy: ownerId
                }
            }
        );

        // Remove re-encryption key
        await ReEncryptionKey.deleteOne({ id: accessId });

        // Record on blockchain
        const contractResult = await blockchain.executeRevokeAccess(file.fileHash, recipient.blockchainAddress);

        console.log(`Access revoked: ${owner.username} revoked ${recipient.username}'s access to ${file.originalName}`);

        res.json({
            success: true,
            message: 'Access revoked successfully',
            permission: {
                id: accessId,
                ownerName: owner.username,
                recipientName: recipient.username,
                fileName: file.originalName,
                revokedAt: new Date()
            },
            blockchain: {
                transactionHash: contractResult.transactionHash,
                contractAddress
            }
        });

    } catch (error) {
        console.error('Revoke access error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to revoke access: ' + error.message
        });
    }
});

// Get User Files
app.get('/api/user/:userId/files', async (req, res) => {
    try {
        const { userId } = req.params;
        const { includeShared } = req.query;
        
        const user = await User.findOne({ id: userId });
        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        // Get files owned by user
        const ownedFiles = await File.find({ userId }).select('-encryptedData');
        const ownedFilesList = ownedFiles.map(file => ({
            id: file.id,
            originalName: file.originalName,
            description: file.description,
            size: file.size,
            mimetype: file.mimetype,
            uploadTime: file.uploadTime,
            downloadCount: file.downloadCount,
            accessCount: file.accessCount,
            fileHash: file.fileHash,
            ipfsHash: file.ipfsHash,
            type: 'owned'
        }));

        let sharedFiles = [];
        if (includeShared === 'true') {
            const userPermissions = await AccessPermission.find({
                recipientId: userId,
                isActive: true,
                expirationTime: { $gt: new Date() }
            });

            const sharedFilePromises = userPermissions.map(async permission => {
                const [file, owner] = await Promise.all([
                    File.findOne({ id: permission.fileId }).select('-encryptedData'),
                    User.findOne({ id: permission.ownerId })
                ]);

                if (!file || !owner) return null;

                return {
                    id: file.id,
                    originalName: file.originalName,
                    description: file.description,
                    size: file.size,
                    mimetype: file.mimetype,
                    uploadTime: file.uploadTime,
                    downloadCount: file.downloadCount,
                    accessCount: file.accessCount,
                    fileHash: file.fileHash,
                    type: 'shared',
                    sharedBy: owner.username,
                    sharedByEmail: owner.email,
                    grantedTime: permission.grantedTime,
                    expirationTime: permission.expirationTime,
                    purpose: permission.purpose,
                    accessCount: permission.accessCount
                };
            });

            sharedFiles = (await Promise.all(sharedFilePromises)).filter(Boolean);
        }

        res.json({
            success: true,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role,
                blockchainAddress: user.blockchainAddress,
                fileCount: user.fileCount,
                lastActive: user.lastActive
            },
            files: {
                owned: ownedFilesList,
                shared: sharedFiles,
                totalOwned: ownedFilesList.length,
                totalShared: sharedFiles.length
            }
        });

    } catch (error) {
        console.error('Get user files error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get user files: ' + error.message
        });
    }
});

// Get File Permissions
app.get('/api/file/:fileId/permissions', async (req, res) => {
    try {
        const { fileId } = req.params;
        const { ownerId } = req.query;

        const [owner, file] = await Promise.all([
            User.findOne({ id: ownerId }),
            File.findOne({ id: fileId }).select('-encryptedData')
        ]);

        if (!owner || !file) {
            return res.status(404).json({
                success: false,
                error: 'Owner or file not found'
            });
        }

        if (file.userId !== ownerId) {
            return res.status(403).json({
                success: false,
                error: 'Only file owner can view permissions'
            });
        }

        const filePermissions = await AccessPermission.find({ fileId }).sort({ grantedTime: -1 });
        
        const permissionsWithUsers = await Promise.all(
            filePermissions.map(async permission => {
                const recipient = await User.findOne({ id: permission.recipientId });
                const isExpired = new Date() > new Date(permission.expirationTime);
                const reKeyExists = await ReEncryptionKey.exists({ id: permission.id });
                
                return {
                    id: permission.id,
                    recipientId: permission.recipientId,
                    recipientName: recipient ? recipient.username : 'Unknown User',
                    recipientEmail: recipient ? recipient.email : 'Unknown Email',
                    purpose: permission.purpose,
                    grantedTime: permission.grantedTime,
                    expirationTime: permission.expirationTime,
                    durationHours: permission.durationHours,
                    isActive: permission.isActive,
                    isExpired,
                    revokedAt: permission.revokedAt,
                    accessCount: permission.accessCount || 0,
                    hasReEncryptionKey: !!reKeyExists,
                    status: permission.isActive ? (isExpired ? 'expired' : 'active') : 'revoked'
                };
            })
        );

        const stats = {
            totalPermissions: permissionsWithUsers.length,
            activePermissions: permissionsWithUsers.filter(p => p.status === 'active').length,
            expiredPermissions: permissionsWithUsers.filter(p => p.status === 'expired').length,
            revokedPermissions: permissionsWithUsers.filter(p => p.status === 'revoked').length,
            totalAccessCount: permissionsWithUsers.reduce((sum, p) => sum + p.accessCount, 0)
        };

        res.json({
            success: true,
            file: {
                id: file.id,
                originalName: file.originalName,
                description: file.description,
                uploadTime: file.uploadTime,
                downloadCount: file.downloadCount,
                accessCount: file.accessCount
            },
            permissions: permissionsWithUsers,
            stats
        });

    } catch (error) {
        console.error('Get permissions error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get file permissions: ' + error.message
        });
    }
});

// Download File
app.get('/api/download/:fileId/:userId', async (req, res) => {
    try {
        const { fileId, userId } = req.params;
        
        const [user, file] = await Promise.all([
            User.findOne({ id: userId }),
            File.findOne({ id: fileId })
        ]);

        if (!user || !file) {
            return res.status(404).json({
                success: false,
                error: 'User or file not found'
            });
        }

        let decryptedBase64Content;
        let accessMethod;

        if (file.userId === userId) {
            // Direct access
            decryptedBase64Content = pre.decrypt(file.encryptedData, user.privateKey);
            accessMethod = 'direct_owner';
            
            await File.updateOne({ id: fileId }, { $inc: { downloadCount: 1 } });
            
            console.log(`Direct download: ${user.username} downloaded own file: ${file.originalName}`);
        } else {
            // Check PRE access permission
            const accessId = `${fileId}_${userId}`;
            const permission = await AccessPermission.findOne({ id: accessId });

            if (!permission || !permission.isActive) {
                return res.status(403).json({
                    success: false,
                    error: 'Access permission not found or revoked'
                });
            }

            if (new Date() > new Date(permission.expirationTime)) {
                await AccessPermission.updateOne({ id: accessId }, { $set: { isActive: false } });
                return res.status(403).json({
                    success: false,
                    error: 'Access permission has expired'
                });
            }

            // Verify blockchain permission
            const blockchainAccess = await blockchain.executeVerifyAccess(file.fileHash, user.blockchainAddress);
            if (!blockchainAccess.hasAccess) {
                return res.status(403).json({
                    success: false,
                    error: 'Blockchain access verification failed'
                });
            }

            // Get re-encryption key
            const reKeyData = await ReEncryptionKey.findOne({ id: accessId });
            if (!reKeyData) {
                return res.status(500).json({
                    success: false,
                    error: 'Re-encryption key not found'
                });
            }

            // Use proxy node for re-encryption
            const proxyNode = await selectProxyNode();
            const transformResult = await proxyNode.transformData(
                file.encryptedData,
                reKeyData,
                user.publicKey
            );

            // User decrypts with their private key
            decryptedBase64Content = pre.decryptReEncrypted(
                transformResult.transformedData,
                user.privateKey
            );
            
            accessMethod = 'proxy_re_encryption';
            
            await Promise.all([
                File.updateOne({ id: fileId }, { $inc: { downloadCount: 1 } }),
                AccessPermission.updateOne({ id: accessId }, { $inc: { accessCount: 1 } })
            ]);

            // Log download on blockchain
            await blockchain.addBlock('FILE_DOWNLOADED_VIA_PRE', {
                fileId,
                fileHash: file.fileHash,
                userId,
                userAddress: user.blockchainAddress,
                proxyNodeId: proxyNode.nodeId,
                transformationId: transformResult.transformationId,
                downloadTime: new Date().toISOString(),
                fileName: file.originalName,
                accessMethod
            });

            console.log(`PRE download: ${user.username} downloaded ${file.originalName} via ${proxyNode.nodeId}`);
        }

        // Convert base64 back to binary buffer
        const fileBuffer = Buffer.from(decryptedBase64Content, 'base64');

        // Set proper HTTP headers for file download
        res.setHeader('Content-Type', file.mimetype || 'application/octet-stream');
        res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(file.originalName)}"`);
        res.setHeader('Content-Length', fileBuffer.length);
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        res.setHeader('X-Access-Method', accessMethod);
        res.setHeader('X-File-Hash', file.fileHash);

        // Send the binary file data
        res.send(fileBuffer);

    } catch (error) {
        console.error('Download error:', error);
        res.status(500).json({
            success: false,
            error: 'File download failed: ' + error.message
        });
    }
});

// Test PRE Functionality (comprehensive test)
app.post('/api/test/pre', async (req, res) => {
    try {
        const { testMessage = "Hello, this is a comprehensive PRE test message! 🔐✨" } = req.body;

        console.log('Starting comprehensive PRE test...');

        // Step 1: Generate test users (Alice and Bob)
        const aliceKeys = pre.generateKeyPair();
        const bobKeys = pre.generateKeyPair();
        
        console.log('✅ Generated key pairs for Alice and Bob');

        // Step 2: Alice encrypts the message
        const aliceEncrypted = pre.encrypt(testMessage, aliceKeys.publicKey);
        console.log('✅ Alice encrypted the message');

        // Step 3: Alice can decrypt her own message
        const aliceDecrypted = pre.decrypt(aliceEncrypted, aliceKeys.privateKey);
        const aliceCanDecrypt = (aliceDecrypted === testMessage);
        console.log(`✅ Alice self-decryption: ${aliceCanDecrypt ? 'SUCCESS' : 'FAILED'}`);

        // Step 4: Bob cannot decrypt Alice's message directly
        let bobDirectDecryptFailed = false;
        try {
            pre.decrypt(aliceEncrypted, bobKeys.privateKey);
        } catch (error) {
            bobDirectDecryptFailed = true;
            console.log('✅ Bob cannot decrypt Alice\'s message directly (as expected)');
        }

        // Step 5: Generate re-encryption key (Alice -> Bob)
        const reKeyData = pre.generateReEncryptionKey(aliceKeys.privateKey, bobKeys.publicKey);
        console.log('✅ Generated re-encryption key');

        // Step 6: Verify re-encryption key
        const reKeyValid = pre.verifyReEncryptionKey(reKeyData, aliceKeys.publicKey, bobKeys.publicKey);
        console.log(`✅ Re-encryption key validation: ${reKeyValid ? 'VALID' : 'INVALID'}`);

        // Step 7: Select proxy node and perform transformation
        const proxyNode = await selectProxyNode();
        const transformResult = await proxyNode.transformData(
            aliceEncrypted,
            reKeyData,
            bobKeys.publicKey
        );
        console.log(`✅ Proxy transformation completed by ${proxyNode.nodeId}`);

        // Step 8: Bob decrypts the transformed data
        const bobDecrypted = pre.decryptReEncrypted(
            transformResult.transformedData,
            bobKeys.privateKey
        );
        const bobCanDecrypt = (bobDecrypted === testMessage);
        console.log(`✅ Bob PRE decryption: ${bobCanDecrypt ? 'SUCCESS' : 'FAILED'}`);

        // Step 9: Test with different message types
        const testCases = [
            'Simple text',
            'Special chars: !@#$%^&*()_+{}[]|\\:";\'<>?,./',
            'Unicode: 🚀🔒🌟💫🔑',
            'Numbers: 123456789',
            'Mixed: Hello123!@# 🌟'
        ];

        const additionalTests = [];
        for (const testCase of testCases) {
            try {
                const encrypted = pre.encrypt(testCase, aliceKeys.publicKey);
                const reKey = pre.generateReEncryptionKey(aliceKeys.privateKey, bobKeys.publicKey);
                const transformed = await proxyNode.transformData(encrypted, reKey, bobKeys.publicKey);
                const decrypted = pre.decryptReEncrypted(transformed.transformedData, bobKeys.privateKey);
                additionalTests.push({
                    input: testCase,
                    success: decrypted === testCase,
                    output: decrypted.substring(0, 50) + (decrypted.length > 50 ? '...' : '')
                });
            } catch (error) {
                additionalTests.push({
                    input: testCase,
                    success: false,
                    error: error.message
                });
            }
        }

        const allTestsPassed = aliceCanDecrypt && 
                              bobDirectDecryptFailed && 
                              reKeyValid && 
                              bobCanDecrypt && 
                              additionalTests.every(test => test.success);

        console.log(`🎯 PRE test completed: ${allTestsPassed ? 'ALL TESTS PASSED' : 'SOME TESTS FAILED'}`);

        res.json({
            success: true,
            message: 'Comprehensive PRE test completed',
            results: {
                overallSuccess: allTestsPassed,
                mainTest: {
                    originalMessage: testMessage,
                    aliceCanDecryptOwn: aliceCanDecrypt,
                    bobCannotDecryptDirectly: bobDirectDecryptFailed,
                    reEncryptionKeyValid: reKeyValid,
                    bobCanDecryptViaRE: bobCanDecrypt,
                    finalDecryptedMessage: bobDecrypted,
                    messagesMatch: testMessage === bobDecrypted
                },
                additionalTests: additionalTests,
                testsPassed: additionalTests.filter(t => t.success).length,
                totalTests: additionalTests.length
            },
            technicalDetails: {
                alicePublicKey: aliceKeys.publicKey.substring(0, 20) + '...',
                bobPublicKey: bobKeys.publicKey.substring(0, 20) + '...',
                reEncryptionKeyHash: crypto.createHash('sha256')
                    .update(reKeyData.reEncryptionKey)
                    .digest('hex')
                    .substring(0, 16),
                proxyNodeId: proxyNode.nodeId,
                transformationId: transformResult.transformationId,
                encryptionAlgorithm: aliceEncrypted.algorithm
            }
        });

    } catch (error) {
        console.error('PRE test error:', error);
        res.status(500).json({
            success: false,
            error: 'PRE test failed: ' + error.message,
            details: error.stack
        });
    }
});

// Get blockchain logs
app.get('/api/blockchain/logs', async (req, res) => {
    try {
        const { limit = 20, operation } = req.query;
        const queryLimit = parseInt(limit);
        
        let query = {};
        if (operation) {
            query.operation = operation;
        }

        const logs = await BlockchainBlock.find(query)
            .sort({ blockNumber: -1 })
            .limit(queryLimit);

        const totalBlocks = await BlockchainBlock.countDocuments();
        const availableOperations = await BlockchainBlock.distinct('operation');

        res.json({
            success: true,
            totalBlocks,
            contractAddress,
            requestedLimit: queryLimit,
            returnedLogs: logs.length,
            availableOperations,
            logs
        });

    } catch (error) {
        console.error('Get blockchain logs error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get blockchain logs: ' + error.message
        });
    }
});

// Get proxy statistics
app.get('/api/proxy/stats', async (req, res) => {
    try {
        const proxyStats = await ProxyNodeStats.find();
        const statsPromises = proxyStats.map(async (nodeData) => {
            const node = proxyNodes.get(nodeData.nodeId);
            if (node) {
                return await node.getStats();
            }
            return {
                nodeId: nodeData.nodeId,
                transformationCount: nodeData.transformationCount,
                isActive: nodeData.isActive,
                uptimeMs: Date.now() - nodeData.startTime.getTime(),
                uptimeHours: Math.round((Date.now() - nodeData.startTime.getTime()) / (1000 * 60 * 60) * 100) / 100,
                lastTransformation: nodeData.lastTransformation
            };
        });

        const stats = await Promise.all(statsPromises);
        const totalTransformations = stats.reduce((sum, node) => sum + node.transformationCount, 0);
        const activeNodes = stats.filter(node => node.isActive).length;

        res.json({
            success: true,
            summary: {
                totalNodes: proxyNodes.size,
                activeNodes,
                inactiveNodes: proxyNodes.size - activeNodes,
                totalTransformations,
                averageTransformationsPerNode: Math.round(totalTransformations / proxyNodes.size * 100) / 100
            },
            nodes: stats
        });

    } catch (error) {
        console.error('Get proxy stats error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get proxy stats: ' + error.message
        });
    }
});

// Get smart contract information
app.get('/api/contract/info', async (req, res) => {
    try {
        const contract = await SmartContract.findOne({ address: contractAddress });
        
        if (!contract) {
            return res.status(404).json({
                success: false,
                error: 'Smart contract not found'
            });
        }

        const [totalBlocks, contractOperationsCount] = await Promise.all([
            BlockchainBlock.countDocuments(),
            BlockchainBlock.countDocuments({
                operation: { $in: ['FILE_UPLOADED', 'ACCESS_GRANTED', 'ACCESS_REVOKED'] }
            })
        ]);

        const latestBlock = await BlockchainBlock.findOne().sort({ blockNumber: -1 });

        res.json({
            success: true,
            contract: {
                address: contract.address,
                name: contract.name,
                deployer: contract.deployer,
                deployedAt: contract.deployedAt,
                functions: contract.functions
            },
            blockchain: {
                totalBlocks,
                latestBlock,
                contractOperations: contractOperationsCount
            }
        });

    } catch (error) {
        console.error('Get contract info error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get contract info: ' + error.message
        });
    }
});

// Get all users (admin endpoint)
app.get('/api/users', async (req, res) => {
    try {
        const users = await User.find().select('-privateKey -password'); 
        
        const userList = users.map(user => ({
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
            blockchainAddress: user.blockchainAddress,
            fileCount: user.fileCount,
            createdAt: user.createdAt,
            lastActive: user.lastActive,
            lastLogin: user.lastLogin,
            publicKey: user.publicKey.substring(0, 20) + '...'
        }));

        res.json({
            success: true,
            totalUsers: users.length,
            users: userList
        });

    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get users: ' + error.message
        });
    }
});

// Get system statistics
app.get('/api/stats', async (req, res) => {
    try {
        const [
            userStats,
            fileStats,
            permissionStats,
            blockchainStats,
            proxyStats
        ] = await Promise.all([
            User.aggregate([
                {
                    $group: {
                        _id: null,
                        totalUsers: { $sum: 1 },
                        totalFiles: { $sum: '$fileCount' },
                        avgFilesPerUser: { $avg: '$fileCount' }
                    }
                }
            ]),
            File.aggregate([
                {
                    $group: {
                        _id: null,
                        totalFiles: { $sum: 1 },
                        totalSize: { $sum: '$size' },
                        avgFileSize: { $avg: '$size' },
                        totalDownloads: { $sum: '$downloadCount' },
                        totalAccesses: { $sum: '$accessCount' }
                    }
                }
            ]),
            AccessPermission.aggregate([
                {
                    $group: {
                        _id: '$isActive',
                        count: { $sum: 1 }
                    }
                }
            ]),
            BlockchainBlock.aggregate([
                {
                    $group: {
                        _id: '$operation',
                        count: { $sum: 1 }
                    }
                }
            ]),
            ProxyNodeStats.aggregate([
                {
                    $group: {
                        _id: null,
                        totalTransformations: { $sum: '$transformationCount' },
                        activeNodes: { $sum: { $cond: ['$isActive', 1, 0] } },
                        totalNodes: { $sum: 1 }
                    }
                }
            ])
        ]);

        const permissionsByStatus = permissionStats.reduce((acc, stat) => {
            acc[stat._id ? 'active' : 'inactive'] = stat.count;
            return acc;
        }, { active: 0, inactive: 0 });

        const blockchainByOperation = blockchainStats.reduce((acc, stat) => {
            acc[stat._id] = stat.count;
            return acc;
        }, {});

        res.json({
            success: true,
            timestamp: new Date().toISOString(),
            users: userStats[0] || { totalUsers: 0, totalFiles: 0, avgFilesPerUser: 0 },
            files: fileStats[0] || { totalFiles: 0, totalSize: 0, avgFileSize: 0, totalDownloads: 0, totalAccesses: 0 },
            permissions: permissionsByStatus,
            blockchain: blockchainByOperation,
            proxy: proxyStats[0] || { totalTransformations: 0, activeNodes: 0, totalNodes: 0 },
            database: {
                connected: mongoose.connection.readyState === 1,
                uri: MONGODB_URI.replace(/\/\/.*@/, '//***:***@')
            }
        });

    } catch (error) {
        console.error('Get stats error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get system statistics: ' + error.message
        });
    }
});

// Delete user (admin endpoint)
app.delete('/api/user/:userId', async (req, res) => {
    try {
        const { userId } = req.params;

        const user = await User.findOne({ id: userId });
        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        // Delete user's files
        await File.deleteMany({ userId });

        // Delete user's permissions (both owned and received)
        await AccessPermission.deleteMany({
            $or: [{ ownerId: userId }, { recipientId: userId }]
        });

        // Delete user's re-encryption keys
        const userPermissionIds = await AccessPermission.find({
            $or: [{ ownerId: userId }, { recipientId: userId }]
        }).distinct('id');
        
        await ReEncryptionKey.deleteMany({
            id: { $in: userPermissionIds }
        });

        // Delete the user
        await User.deleteOne({ id: userId });

        // Log on blockchain
        await blockchain.addBlock('USER_DELETED', {
            userId,
            username: user.username,
            email: user.email,
            deletedAt: new Date().toISOString()
        });

        console.log(`User deleted: ${user.username} (${user.email})`);

        res.json({
            success: true,
            message: 'User and all associated data deleted successfully',
            deletedUser: {
                id: userId,
                username: user.username,
                email: user.email
            }
        });

    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to delete user: ' + error.message
        });
    }
});


app.get('/api/files', async (req, res) => {
    try {
        const { 
            limit = 50, 
            page = 1, 
            sortBy = 'uploadTime', 
            order = 'desc',
            mimetype,
            search 
        } = req.query;

        const queryLimit = parseInt(limit);
        const pageNum = parseInt(page);
        const skip = (pageNum - 1) * queryLimit;

        // Build query
        let query = {};
        
        if (mimetype) {
            query.mimetype = { $regex: mimetype, $options: 'i' };
        }
        
        if (search) {
            query.$or = [
                { originalName: { $regex: search, $options: 'i' } },
                { description: { $regex: search, $options: 'i' } }
            ];
        }

        // Get total count for pagination
        const totalFiles = await File.countDocuments(query);
        const totalPages = Math.ceil(totalFiles / queryLimit);

        // Sort options
        const sortOptions = {};
        sortOptions[sortBy] = order === 'asc' ? 1 : -1;

        // Get files without encrypted data
        const files = await File.find(query)
            .select('-encryptedData') // Exclude encrypted data
            .sort(sortOptions)
            .limit(queryLimit)
            .skip(skip);

        // Enrich with owner information
        const filesWithOwners = await Promise.all(
            files.map(async (file) => {
                const owner = await User.findOne({ id: file.userId }).select('username email blockchainAddress');
                
                // Get permission count
                const permissionCount = await AccessPermission.countDocuments({ 
                    fileId: file.id,
                    isActive: true,
                    expirationTime: { $gt: new Date() }
                });

                return {
                    id: file.id,
                    originalName: file.originalName,
                    description: file.description,
                    size: file.size,
                    sizeFormatted: formatBytes(file.size),
                    mimetype: file.mimetype,
                    fileType: getFileType(file.mimetype),
                    uploadTime: file.uploadTime,
                    downloadCount: file.downloadCount,
                    accessCount: file.accessCount,
                    fileHash: file.fileHash,
                    ipfsHash: file.ipfsHash,
                    owner: {
                        userId: file.userId,
                        username: owner ? owner.username : 'Unknown',
                        email: owner ? owner.email : 'Unknown',
                        blockchainAddress: owner ? owner.blockchainAddress : 'Unknown'
                    },
                    permissions: {
                        activeShares: permissionCount
                    },
                    canAccess: false, // User cannot access without proper permissions
                    accessNote: 'You need permission from the owner to access this file'
                };
            })
        );

        // Get statistics
        const stats = {
            totalFiles,
            totalPages,
            currentPage: pageNum,
            filesPerPage: queryLimit,
            filesOnPage: filesWithOwners.length,
            totalSize: await File.aggregate([
                { $match: query },
                { $group: { _id: null, total: { $sum: '$size' } } }
            ]).then(result => result[0]?.total || 0),
            fileTypes: await File.aggregate([
                { $match: query },
                { $group: { _id: '$mimetype', count: { $sum: 1 } } },
                { $sort: { count: -1 } },
                { $limit: 10 }
            ])
        };

        res.json({
            success: true,
            message: 'Files retrieved successfully (view only)',
            pagination: {
                currentPage: pageNum,
                totalPages,
                totalFiles,
                limit: queryLimit,
                hasNextPage: pageNum < totalPages,
                hasPrevPage: pageNum > 1
            },
            stats: {
                ...stats,
                totalSizeFormatted: formatBytes(stats.totalSize)
            },
            files: filesWithOwners,
            note: 'These are view-only file details. To access file content, you need permission from the owner.'
        });

    } catch (error) {
        console.error('Get all files error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get files: ' + error.message
        });
    }
});

// ====================== GET SINGLE FILE DETAILS (VIEW ONLY) ======================

app.get('/api/file/:userId/:fileId', async (req, res) => {
    try {
        const { fileId, userId } = req.params;

        if (!userId) {
            return res.status(400).json({
                success: false,
                error: 'User ID is required in URL'
            });
        }

        const file = await File.findOne({ id: fileId }).select('-encryptedData');
        if (!file) {
            return res.status(404).json({
                success: false,
                error: 'File not found'
            });
        }

        // Determine if requesting user can access
        let canAccess = false;
        let accessMethod = null;

        if (file.userId === userId) {
            canAccess = true;
            accessMethod = 'owner';
        } else {
            const permission = await AccessPermission.findOne({ fileId, recipientId: userId });
            if (permission && permission.isActive && new Date() < new Date(permission.expirationTime)) {
                canAccess = true;
                accessMethod = 'granted_permission';
            }
        }

        // ❌ If user cannot access, return 401 Unauthorized
        if (!canAccess) {
            const owner = await User.findOne({ id: file.userId }).select('email username');
            return res.status(401).json({
                success: false,
                error: `Unauthorized user. You do not have permission to access this file. Contact owner: ${owner ? owner.email : 'Unknown'}`
            });
        }

        // ✅ User can access → proceed with details
        const owner = await User.findOne({ id: file.userId })
            .select('username email blockchainAddress role createdAt');

        const permissions = await AccessPermission.find({ fileId: file.id });
        const permissionDetails = await Promise.all(
            permissions.map(async (perm) => {
                const recipient = await User.findOne({ id: perm.recipientId }).select('username email');
                const isExpired = new Date() > new Date(perm.expirationTime);
                return {
                    recipientUsername: recipient ? recipient.username : 'Unknown',
                    recipientEmail: recipient ? recipient.email : 'Unknown',
                    grantedTime: perm.grantedTime,
                    expirationTime: perm.expirationTime,
                    isActive: perm.isActive,
                    isExpired,
                    status: perm.isActive ? (isExpired ? 'expired' : 'active') : 'revoked',
                    accessCount: perm.accessCount || 0
                };
            })
        );

        const blockchainRecords = await BlockchainBlock.find({
            $or: [
                { 'data.fileId': fileId },
                { 'data.fileHash': file.fileHash }
            ]
        }).sort({ blockNumber: -1 }).limit(10);

        res.json({
            success: true,
            message: 'File details retrieved',
            file: {
                id: file.id,
                originalName: file.originalName,
                description: file.description,
                size: file.size,
                sizeFormatted: formatBytes(file.size),
                mimetype: file.mimetype,
                fileType: getFileType(file.mimetype),
                uploadTime: file.uploadTime,
                downloadCount: file.downloadCount,
                accessCount: file.accessCount,
                fileHash: file.fileHash,
                ipfsHash: file.ipfsHash
            },
            owner: {
                userId: file.userId,
                username: owner ? owner.username : 'Unknown',
                email: owner ? owner.email : 'Unknown',
                blockchainAddress: owner ? owner.blockchainAddress : 'Unknown',
                role: owner ? owner.role : 'Unknown',
                memberSince: owner ? owner.createdAt : null
            },
            permissions: {
                total: permissions.length,
                active: permissionDetails.filter(p => p.status === 'active').length,
                expired: permissionDetails.filter(p => p.status === 'expired').length,
                revoked: permissionDetails.filter(p => p.status === 'revoked').length,
                details: permissionDetails
            },
            blockchain: {
                recordCount: blockchainRecords.length,
                recentActivity: blockchainRecords.map(block => ({
                    operation: block.operation,
                    blockNumber: block.blockNumber,
                    timestamp: block.timestamp,
                    transactionHash: block.transactionHash
                }))
            },
            canAccess,
            accessMethod,
            accessNote: `You can access this file via ${accessMethod === 'owner' ? 'direct ownership' : 'granted permission'}`
        });

    } catch (error) {
        console.error('Get file details error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get file details: ' + error.message
        });
    }
});


// Delete file (owner only)
app.delete('/api/file/:fileId', async (req, res) => {
    try {
        const { fileId } = req.params;
        const { userId } = req.query;

        const [user, file] = await Promise.all([
            User.findOne({ id: userId }),
            File.findOne({ id: fileId })
        ]);

        if (!user || !file) {
            return res.status(404).json({
                success: false,
                error: 'User or file not found'
            });
        }

        if (file.userId !== userId) {
            return res.status(403).json({
                success: false,
                error: 'Only file owner can delete the file'
            });
        }

        // Delete all permissions for this file
        await AccessPermission.deleteMany({ fileId });

        // Delete all re-encryption keys for this file
        const filePermissionIds = await AccessPermission.find({ fileId }).distinct('id');
        await ReEncryptionKey.deleteMany({ id: { $in: filePermissionIds } });

        // Delete the file
        await File.deleteOne({ id: fileId });

        // Update user file count
        await User.updateOne({ id: userId }, { $inc: { fileCount: -1 } });

        // Log on blockchain
        await blockchain.addBlock('FILE_DELETED', {
            fileId,
            fileName: file.originalName,
            fileHash: file.fileHash,
            ownerId: userId,
            ownerAddress: user.blockchainAddress,
            deletedAt: new Date().toISOString()
        });

        console.log(`File deleted: ${file.originalName} by ${user.username}`);

        res.json({
            success: true,
            message: 'File and all associated permissions deleted successfully',
            deletedFile: {
                id: fileId,
                originalName: file.originalName,
                size: file.size,
                uploadTime: file.uploadTime
            }
        });

    } catch (error) {
        console.error('Delete file error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to delete file: ' + error.message
        });
    }
});

app.post('/api/request-access', async (req, res) => {
    try {
        const { userId, fileId, purpose, requestedDuration } = req.body;
        
        // Validation
        if (!userId || !fileId) {
            return res.status(400).json({
                success: false,
                error: 'User ID and File ID are required'
            });
        }

        const [user, file] = await Promise.all([
            User.findOne({ id: userId }),
            File.findOne({ id: fileId })
        ]);

        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        if (!file) {
            return res.status(404).json({
                success: false,
                error: 'File not found'
            });
        }

        // Check if user is the owner
        if (file.userId === userId) {
            return res.status(400).json({
                success: false,
                error: 'You already own this file'
            });
        }

        // Check if user already has active access
        const existingPermission = await AccessPermission.findOne({
            fileId,
            recipientId: userId,
            isActive: true,
            expirationTime: { $gt: new Date() }
        });

        if (existingPermission) {
            return res.status(400).json({
                success: false,
                error: 'You already have active access to this file'
            });
        }

        // Check if there's already a pending request
        const existingRequest = await AccessRequest.findOne({
            fileId,
            requesterId: userId,
            status: 'pending'
        });

        if (existingRequest) {
            return res.status(400).json({
                success: false,
                error: 'You already have a pending access request for this file',
                request: {
                    id: existingRequest.id,
                    requestTime: existingRequest.requestTime,
                    purpose: existingRequest.purpose
                }
            });
        }

        // Get file owner
        const owner = await User.findOne({ id: file.userId });
        if (!owner) {
            return res.status(404).json({
                success: false,
                error: 'File owner not found'
            });
        }

        // Create access request
        const requestId = uuidv4();
        const accessRequest = new AccessRequest({
            id: requestId,
            fileId,
            requesterId: userId,
            ownerId: file.userId,
            purpose: purpose || 'No purpose provided',
            requestedDuration: requestedDuration || 24,
            requestTime: new Date(),
            status: 'pending'
        });

        await accessRequest.save();

        // Record on blockchain
        await blockchain.addBlock('ACCESS_REQUESTED', {
            requestId,
            fileId,
            fileName: file.originalName,
            fileHash: file.fileHash,
            requesterId: userId,
            requesterUsername: user.username,
            requesterEmail: user.email,
            ownerId: file.userId,
            ownerUsername: owner.username,
            purpose: accessRequest.purpose,
            requestedDuration: accessRequest.requestedDuration,
            requestTime: new Date().toISOString()
        });

        console.log(`Access request created: ${user.username} requested access to ${file.originalName} from ${owner.username}`);

        res.json({
            success: true,
            message: 'Access request sent successfully',
            request: {
                id: requestId,
                fileId,
                fileName: file.originalName,
                requester: {
                    id: user.id,
                    username: user.username,
                    email: user.email
                },
                owner: {
                    id: owner.id,
                    username: owner.username,
                    email: owner.email
                },
                purpose: accessRequest.purpose,
                requestedDuration: accessRequest.requestedDuration,
                requestTime: accessRequest.requestTime,
                status: 'pending'
            }
        });

    } catch (error) {
        console.error('Request access error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to request access: ' + error.message
        });
    }
});

// ====================== GET RECEIVED ACCESS REQUESTS (FOR FILE OWNER) ======================

app.get('/api/access-requests/received/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const { status, limit = 50 } = req.query;

        const user = await User.findOne({ id: userId });
        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        // Build query
        let query = { ownerId: userId };
        if (status && ['pending', 'approved', 'rejected'].includes(status)) {
            query.status = status;
        }

        const requests = await AccessRequest.find(query)
            .sort({ requestTime: -1 })
            .limit(parseInt(limit));

        // Enrich with requester and file information
        const requestsWithDetails = await Promise.all(
            requests.map(async (request) => {
                const [requester, file] = await Promise.all([
                    User.findOne({ id: request.requesterId }).select('username email blockchainAddress'),
                    File.findOne({ id: request.fileId }).select('originalName description size mimetype fileHash')
                ]);

                return {
                    id: request.id,
                    requester: {
                        id: request.requesterId,
                        username: requester ? requester.username : 'Unknown',
                        email: requester ? requester.email : 'Unknown',
                        blockchainAddress: requester ? requester.blockchainAddress : 'Unknown'
                    },
                    file: {
                        id: request.fileId,
                        name: file ? file.originalName : 'Unknown',
                        description: file ? file.description : 'Unknown',
                        size: file ? file.size : 0,
                        sizeFormatted: file ? formatBytes(file.size) : '0 B',
                        mimetype: file ? file.mimetype : 'Unknown'
                    },
                    purpose: request.purpose,
                    requestedDuration: request.requestedDuration,
                    requestTime: request.requestTime,
                    status: request.status,
                    responseTime: request.responseTime,
                    responseMessage: request.responseMessage
                };
            })
        );

        // Get statistics
        const stats = {
            total: requests.length,
            pending: requests.filter(r => r.status === 'pending').length,
            approved: requests.filter(r => r.status === 'approved').length,
            rejected: requests.filter(r => r.status === 'rejected').length
        };

        res.json({
            success: true,
            message: 'Received access requests retrieved successfully',
            stats,
            requests: requestsWithDetails
        });

    } catch (error) {
        console.error('Get received requests error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get received requests: ' + error.message
        });
    }
});

// ====================== GET SENT ACCESS REQUESTS (FOR REQUESTER) ======================

app.get('/api/access-requests/sent/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const { status, limit = 50 } = req.query;

        const user = await User.findOne({ id: userId });
        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        // Build query
        let query = { requesterId: userId };
        if (status && ['pending', 'approved', 'rejected'].includes(status)) {
            query.status = status;
        }

        const requests = await AccessRequest.find(query)
            .sort({ requestTime: -1 })
            .limit(parseInt(limit));

        // Enrich with owner and file information
        const requestsWithDetails = await Promise.all(
            requests.map(async (request) => {
                const [owner, file] = await Promise.all([
                    User.findOne({ id: request.ownerId }).select('username email blockchainAddress'),
                    File.findOne({ id: request.fileId }).select('originalName description size mimetype fileHash')
                ]);

                return {
                    id: request.id,
                    owner: {
                        id: request.ownerId,
                        username: owner ? owner.username : 'Unknown',
                        email: owner ? owner.email : 'Unknown',
                        blockchainAddress: owner ? owner.blockchainAddress : 'Unknown'
                    },
                    file: {
                        id: request.fileId,
                        name: file ? file.originalName : 'Unknown',
                        description: file ? file.description : 'Unknown',
                        size: file ? file.size : 0,
                        sizeFormatted: file ? formatBytes(file.size) : '0 B',
                        mimetype: file ? file.mimetype : 'Unknown'
                    },
                    purpose: request.purpose,
                    requestedDuration: request.requestedDuration,
                    requestTime: request.requestTime,
                    status: request.status,
                    responseTime: request.responseTime,
                    responseMessage: request.responseMessage
                };
            })
        );

        // Get statistics
        const stats = {
            total: requests.length,
            pending: requests.filter(r => r.status === 'pending').length,
            approved: requests.filter(r => r.status === 'approved').length,
            rejected: requests.filter(r => r.status === 'rejected').length
        };

        res.json({
            success: true,
            message: 'Sent access requests retrieved successfully',
            stats,
            requests: requestsWithDetails
        });

    } catch (error) {
        console.error('Get sent requests error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get sent requests: ' + error.message
        });
    }
});

// ====================== RESPOND TO ACCESS REQUEST (APPROVE/REJECT) ======================

app.post('/api/access-requests/respond', async (req, res) => {
    try {
        const { requestId, ownerId, action, responseMessage, durationHours } = req.body;
        
        // Validation
        if (!requestId || !ownerId || !action) {
            return res.status(400).json({
                success: false,
                error: 'Request ID, Owner ID, and action are required'
            });
        }

        if (!['approve', 'reject'].includes(action)) {
            return res.status(400).json({
                success: false,
                error: 'Action must be either "approve" or "reject"'
            });
        }

        const [owner, request] = await Promise.all([
            User.findOne({ id: ownerId }),
            AccessRequest.findOne({ id: requestId })
        ]);

        if (!owner) {
            return res.status(404).json({
                success: false,
                error: 'Owner not found'
            });
        }

        if (!request) {
            return res.status(404).json({
                success: false,
                error: 'Access request not found'
            });
        }

        // Verify owner
        if (request.ownerId !== ownerId) {
            return res.status(403).json({
                success: false,
                error: 'Only the file owner can respond to this request'
            });
        }

        // Check if already responded
        if (request.status !== 'pending') {
            return res.status(400).json({
                success: false,
                error: `Request has already been ${request.status}`,
                request: {
                    id: request.id,
                    status: request.status,
                    responseTime: request.responseTime,
                    responseMessage: request.responseMessage
                }
            });
        }

        const [requester, file] = await Promise.all([
            User.findOne({ id: request.requesterId }),
            File.findOne({ id: request.fileId })
        ]);

        if (!requester || !file) {
            return res.status(404).json({
                success: false,
                error: 'Requester or file not found'
            });
        }

        let permissionResult = null;

        if (action === 'approve') {
            // Grant access using the existing grant-access logic
            const duration = durationHours || request.requestedDuration || 24;
            
            // Generate re-encryption key
            const reKeyData = pre.generateReEncryptionKey(owner.privateKey, requester.publicKey);
            
            if (!pre.verifyReEncryptionKey(reKeyData, owner.publicKey, requester.publicKey)) {
                return res.status(500).json({
                    success: false,
                    error: 'Invalid re-encryption key generated'
                });
            }
            
            const accessId = `${file.id}_${requester.id}`;
            const expirationTime = new Date(Date.now() + duration * 60 * 60 * 1000);

            // Create or update permission
            let permission = await AccessPermission.findOne({ id: accessId });
            
            if (permission) {
                permission.expirationTime = expirationTime;
                permission.durationHours = duration;
                permission.isActive = true;
                permission.purpose = request.purpose || 'Access granted via request';
                permission.updatedAt = new Date();
                await permission.save();
            } else {
                permission = new AccessPermission({
                    id: accessId,
                    fileId: file.id,
                    ownerId,
                    recipientId: requester.id,
                    purpose: request.purpose || 'Access granted via request',
                    grantedTime: new Date(),
                    expirationTime,
                    durationHours: duration,
                    isActive: true,
                    accessCount: 0
                });
                await permission.save();
            }

            // Store re-encryption key
            await ReEncryptionKey.findOneAndUpdate(
                { id: accessId },
                {
                    id: accessId,
                    reEncryptionKey: reKeyData.reEncryptionKey,
                    salt: reKeyData.salt,
                    fromUserPublicKey: reKeyData.fromUserPublicKey,
                    toUserPublicKey: reKeyData.toUserPublicKey,
                    createdAt: new Date()
                },
                { upsert: true }
            );

            // Record on blockchain
            await blockchain.executeGrantAccess(file.fileHash, requester.blockchainAddress, duration);

            permissionResult = {
                accessId,
                expirationTime,
                durationHours: duration
            };

            console.log(`Access request approved: ${owner.username} granted ${requester.username} access to ${file.originalName}`);
        } else {
            console.log(`Access request rejected: ${owner.username} rejected ${requester.username}'s request for ${file.originalName}`);
        }

        // Update request status
        await AccessRequest.updateOne(
            { id: requestId },
            {
                $set: {
                    status: action === 'approve' ? 'approved' : 'rejected',
                    responseTime: new Date(),
                    responseMessage: responseMessage || (action === 'approve' ? 'Access granted' : 'Access denied'),
                    respondedBy: ownerId
                }
            }
        );

        // Record on blockchain
        await blockchain.addBlock('ACCESS_REQUEST_RESPONDED', {
            requestId,
            fileId: file.id,
            fileName: file.originalName,
            fileHash: file.fileHash,
            requesterId: requester.id,
            requesterUsername: requester.username,
            ownerId,
            ownerUsername: owner.username,
            action,
            responseTime: new Date().toISOString(),
            responseMessage: responseMessage || (action === 'approve' ? 'Access granted' : 'Access denied'),
            ...(permissionResult && { 
                permissionGranted: true,
                expirationTime: permissionResult.expirationTime.toISOString(),
                durationHours: permissionResult.durationHours
            })
        });

        res.json({
            success: true,
            message: `Access request ${action === 'approve' ? 'approved' : 'rejected'} successfully`,
            request: {
                id: requestId,
                status: action === 'approve' ? 'approved' : 'rejected',
                responseTime: new Date(),
                responseMessage: responseMessage || (action === 'approve' ? 'Access granted' : 'Access denied')
            },
            ...(action === 'approve' && permissionResult && {
                permission: {
                    accessId: permissionResult.accessId,
                    expirationTime: permissionResult.expirationTime,
                    durationHours: permissionResult.durationHours
                }
            }),
            file: {
                id: file.id,
                name: file.originalName
            },
            requester: {
                id: requester.id,
                username: requester.username,
                email: requester.email
            }
        });

    } catch (error) {
        console.error('Respond to request error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to respond to access request: ' + error.message
        });
    }
});

// ====================== CANCEL ACCESS REQUEST (BY REQUESTER) ======================

app.delete('/api/access-requests/:requestId', async (req, res) => {
    try {
        const { requestId } = req.params;
        const { userId } = req.query;

        if (!userId) {
            return res.status(400).json({
                success: false,
                error: 'User ID is required'
            });
        }

        const [user, request] = await Promise.all([
            User.findOne({ id: userId }),
            AccessRequest.findOne({ id: requestId })
        ]);

        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        if (!request) {
            return res.status(404).json({
                success: false,
                error: 'Access request not found'
            });
        }

        // Verify requester
        if (request.requesterId !== userId) {
            return res.status(403).json({
                success: false,
                error: 'Only the requester can cancel this request'
            });
        }

        // Check if already responded
        if (request.status !== 'pending') {
            return res.status(400).json({
                success: false,
                error: `Cannot cancel a request that has already been ${request.status}`
            });
        }

        // Delete the request
        await AccessRequest.deleteOne({ id: requestId });

        // Record on blockchain
        await blockchain.addBlock('ACCESS_REQUEST_CANCELLED', {
            requestId,
            fileId: request.fileId,
            requesterId: userId,
            requesterUsername: user.username,
            ownerId: request.ownerId,
            cancelledTime: new Date().toISOString()
        });

        console.log(`Access request cancelled: ${user.username} cancelled request ${requestId}`);

        res.json({
            success: true,
            message: 'Access request cancelled successfully',
            request: {
                id: requestId,
                fileId: request.fileId,
                cancelledTime: new Date()
            }
        });

    } catch (error) {
        console.error('Cancel request error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to cancel access request: ' + error.message
        });
    }
});


// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
    });
});

// Handle 404 errors - catch all unmatched routes
app.use((req, res, next) => {
    res.status(404).json({
        success: false,
        error: 'Endpoint not found',
        requestedPath: req.path,
        requestedMethod: req.method,
        availableEndpoints: [
            'POST /api/register',
            'POST /api/upload',
            'POST /api/grant-access',
            'POST /api/access-file',
            'POST /api/revoke-access',
            'GET /api/download/:fileId/:userId',
            'GET /api/user/:userId/files',
            'GET /api/file/:fileId/permissions',
            'POST /api/test/pre',
            'GET /api/blockchain/logs',
            'GET /api/proxy/stats',
            'GET /api/contract/info',
            'GET /api/users',
            'GET /api/stats',
            'DELETE /api/user/:userId',
            'DELETE /api/file/:fileId',
            'GET /api/health'
        ]
    });
});

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('\n🛑 Shutting down gracefully...');
    
    try {
        // Close MongoDB connection
        await mongoose.connection.close();
        console.log('📦 MongoDB connection closed');
        
        // Deactivate all proxy nodes
        const proxyNodeIds = Array.from(proxyNodes.keys());
        for (const nodeId of proxyNodeIds) {
            const node = proxyNodes.get(nodeId);
            if (node) {
                await node.deactivate();
            }
        }
        console.log('🔄 Proxy nodes deactivated');
        
        process.exit(0);
    } catch (error) {
        console.error('Error during shutdown:', error);
        process.exit(1);
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 MongoDB-Only PRE File Upload API running on port ${PORT}`);
    console.log(`🔗 Health check: http://localhost:${PORT}/api/health`);
    console.log(`📜 Smart Contract: ${contractAddress}`);
    console.log(`🔄 Proxy Nodes: ${proxyNodes.size} active`);
    console.log(`📦 Database: MongoDB (${MONGODB_URI.replace(/\/\/.*@/, '//***:***@')})`);
    console.log('\n📋 Available endpoints:');
    console.log('POST /api/register - Register user with password and PRE key pair');
    console.log('POST /api/login - User login with username/email and password');
    console.log('POST /api/change-password - Change user password');
    console.log('POST /api/reset-password - Reset forgotten password');
    console.log('POST /api/upload - Upload and encrypt file');
    console.log('POST /api/grant-access - Grant PRE access permission');
    console.log('POST /api/access-file - Access file via PRE');
    console.log('POST /api/revoke-access - Revoke PRE access');
    console.log('GET  /api/download/:fileId/:userId - Download file');
    console.log('GET  /api/user/:id/files - Get user files');
    console.log('GET  /api/file/:id/permissions - Get file permissions');
    console.log('POST /api/test/pre - Comprehensive PRE test');
    console.log('GET  /api/blockchain/logs - Get blockchain logs');
    console.log('GET  /api/proxy/stats - Get proxy statistics');
    console.log('GET  /api/contract/info - Get contract info');
    console.log('GET  /api/users - Get all users');
    console.log('GET  /api/stats - Get system statistics');
    console.log('DELETE /api/user/:id - Delete user (admin)');
    console.log('DELETE /api/file/:id - Delete file (owner)');
    console.log('GET  /api/health - System health check');
    
    console.log('\n🔐 PRE Features:');
    console.log('✅ Secure key generation with PBKDF2');
    console.log('✅ AES-256-CBC encryption');
    console.log('✅ Proxy re-encryption with HKDF');
    console.log('✅ Load-balanced proxy nodes');
    console.log('✅ Blockchain access control');
    console.log('✅ Comprehensive error handling');
    console.log('✅ Binary file support');
    console.log('✅ Access permission management');
    console.log('✅ MongoDB-only storage (no fallback)');
});

module.exports = app;