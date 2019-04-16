const assert = require('assert')
const ChildProcess = require('child_process')
const { expect } = require('chai')
const fs = require('fs')
const path = require('path')
const os = require('os')
const { ipcRenderer, remote } = require('electron')
const features = process.atomBinding('features')

const isCI = remote.getGlobal('isCi')

describe('node feature', () => {
  const fixtures = path.join(__dirname, 'fixtures')

  describe('child_process', () => {
    beforeEach(function () {
      if (!features.isRunAsNodeEnabled()) {
        this.skip()
      }
    })

    describe('child_process.fork', () => {
      it('works in current process', (done) => {
        const child = ChildProcess.fork(path.join(fixtures, 'module', 'ping.js'))
        child.on('message', (msg) => {
          assert.strictEqual(msg, 'message')
          done()
        })
        child.send('message')
      })

      it('preserves args', (done) => {
        const args = ['--expose_gc', '-test', '1']
        const child = ChildProcess.fork(path.join(fixtures, 'module', 'process_args.js'), args)
        child.on('message', (msg) => {
          assert.deepStrictEqual(args, msg.slice(2))
          done()
        })
        child.send('message')
      })

      it('works in forked process', (done) => {
        const child = ChildProcess.fork(path.join(fixtures, 'module', 'fork_ping.js'))
        child.on('message', (msg) => {
          assert.strictEqual(msg, 'message')
          done()
        })
        child.send('message')
      })

      it('works in forked process when options.env is specifed', (done) => {
        const child = ChildProcess.fork(path.join(fixtures, 'module', 'fork_ping.js'), [], {
          path: process.env['PATH']
        })
        child.on('message', (msg) => {
          assert.strictEqual(msg, 'message')
          done()
        })
        child.send('message')
      })

      it('works in browser process', (done) => {
        const fork = remote.require('child_process').fork
        const child = fork(path.join(fixtures, 'module', 'ping.js'))
        child.on('message', (msg) => {
          assert.strictEqual(msg, 'message')
          done()
        })
        child.send('message')
      })

      it('has String::localeCompare working in script', (done) => {
        const child = ChildProcess.fork(path.join(fixtures, 'module', 'locale-compare.js'))
        child.on('message', (msg) => {
          assert.deepStrictEqual(msg, [0, -1, 1])
          done()
        })
        child.send('message')
      })

      it('has setImmediate working in script', (done) => {
        const child = ChildProcess.fork(path.join(fixtures, 'module', 'set-immediate.js'))
        child.on('message', (msg) => {
          assert.strictEqual(msg, 'ok')
          done()
        })
        child.send('message')
      })

      it('pipes stdio', (done) => {
        const child = ChildProcess.fork(path.join(fixtures, 'module', 'process-stdout.js'), { silent: true })
        let data = ''
        child.stdout.on('data', (chunk) => {
          data += String(chunk)
        })
        child.on('close', (code) => {
          assert.strictEqual(code, 0)
          assert.strictEqual(data, 'pipes stdio')
          done()
        })
      })

      it('works when sending a message to a process forked with the --eval argument', (done) => {
        const source = "process.on('message', (message) => { process.send(message) })"
        const forked = ChildProcess.fork('--eval', [source])
        forked.once('message', (message) => {
          assert.strictEqual(message, 'hello')
          done()
        })
        forked.send('hello')
      })
    })

    describe('child_process.spawn', () => {
      let child

      afterEach(() => {
        if (child != null) child.kill()
      })

      it('supports spawning Electron as a node process via the ELECTRON_RUN_AS_NODE env var', (done) => {
        child = ChildProcess.spawn(process.execPath, [path.join(__dirname, 'fixtures', 'module', 'run-as-node.js')], {
          env: {
            ELECTRON_RUN_AS_NODE: true
          }
        })

        let output = ''
        child.stdout.on('data', (data) => {
          output += data
        })
        child.stdout.on('close', () => {
          assert.deepStrictEqual(JSON.parse(output), {
            processLog: process.platform === 'win32' ? 'function' : 'undefined',
            processType: 'undefined',
            window: 'undefined'
          })
          done()
        })
      })
    })
  })

  describe('contexts', () => {
    describe('setTimeout in fs callback', () => {
      it('does not crash', (done) => {
        fs.readFile(__filename, () => {
          setTimeout(done, 0)
        })
      })
    })

    describe('error thrown in renderer process node context', () => {
      it('gets emitted as a process uncaughtException event', (done) => {
        const error = new Error('boo!')
        const listeners = process.listeners('uncaughtException')
        process.removeAllListeners('uncaughtException')
        process.on('uncaughtException', (thrown) => {
          assert.strictEqual(thrown, error)
          process.removeAllListeners('uncaughtException')
          listeners.forEach((listener) => {
            process.on('uncaughtException', listener)
          })
          done()
        })
        fs.readFile(__filename, () => {
          throw error
        })
      })
    })

    describe('error thrown in main process node context', () => {
      it('gets emitted as a process uncaughtException event', () => {
        const error = ipcRenderer.sendSync('handle-uncaught-exception', 'hello')
        assert.strictEqual(error, 'hello')
      })
    })

    describe('promise rejection in main process node context', () => {
      it('gets emitted as a process unhandledRejection event', () => {
        const error = ipcRenderer.sendSync('handle-unhandled-rejection', 'hello')
        assert.strictEqual(error, 'hello')
      })
    })

    describe('setTimeout called under Chromium event loop in browser process', () => {
      it('can be scheduled in time', (done) => {
        remote.getGlobal('setTimeout')(done, 0)
      })

      it('can be promisified', (done) => {
        remote.getGlobal('setTimeoutPromisified')(0).then(done)
      })
    })

    describe('setInterval called under Chromium event loop in browser process', () => {
      it('can be scheduled in time', (done) => {
        let interval = null
        let clearing = false
        const clear = () => {
          if (interval === null || clearing) {
            return
          }
          // interval might trigger while clearing (remote is slow sometimes)
          clearing = true
          remote.getGlobal('clearInterval')(interval)
          clearing = false
          interval = null
          done()
        }
        interval = remote.getGlobal('setInterval')(clear, 10)
      })
    })
  })

  describe('inspector', () => {
    let child = null

    beforeEach(function () {
      if (!features.isRunAsNodeEnabled()) {
        this.skip()
      }
    })

    afterEach(() => {
      if (child !== null) child.kill()
    })

    it('supports starting the v8 inspector with --inspect/--inspect-brk', (done) => {
      child = ChildProcess.spawn(process.execPath, ['--inspect-brk', path.join(__dirname, 'fixtures', 'module', 'run-as-node.js')], {
        env: {
          ELECTRON_RUN_AS_NODE: true
        }
      })

      let output = ''
      function cleanup () {
        child.stderr.removeListener('data', errorDataListener)
        child.stdout.removeListener('data', outDataHandler)
      }
      function errorDataListener (data) {
        output += data
        if (output.trim().startsWith('Debugger listening on ws://')) {
          cleanup()
          done()
        }
      }
      function outDataHandler (data) {
        cleanup()
        done(new Error(`Unexpected output: ${data.toString()}`))
      }
      child.stderr.on('data', errorDataListener)
      child.stdout.on('data', outDataHandler)
    })

    it('supports js binding', (done) => {
      child = ChildProcess.spawn(process.execPath, ['--inspect', path.join(__dirname, 'fixtures', 'module', 'inspector-binding.js')], {
        env: {
          ELECTRON_RUN_AS_NODE: true
        },
        stdio: ['ipc']
      })

      child.on('message', ({ cmd, debuggerEnabled, secondSessionOpened, success }) => {
        if (cmd === 'assert') {
          assert.strictEqual(debuggerEnabled, true)
          assert.strictEqual(secondSessionOpened, true)
          assert.strictEqual(success, true)
          done()
        }
      })
    })
  })

  describe('message loop', () => {
    describe('process.nextTick', () => {
      it('emits the callback', (done) => {
        process.nextTick(done)
      })

      it('works in nested calls', (done) => {
        process.nextTick(() => {
          process.nextTick(() => {
            process.nextTick(done)
          })
        })
      })
    })

    describe('setImmediate', () => {
      it('emits the callback', (done) => {
        setImmediate(done)
      })

      it('works in nested calls', (done) => {
        setImmediate(() => {
          setImmediate(() => {
            setImmediate(done)
          })
        })
      })
    })
  })

  describe('net.connect', () => {
    before(function () {
      if (!features.isRunAsNodeEnabled() || process.platform !== 'darwin') {
        this.skip()
      }
    })

    it('emit error when connect to a socket path without listeners', (done) => {
      const socketPath = path.join(os.tmpdir(), 'atom-shell-test.sock')
      const script = path.join(fixtures, 'module', 'create_socket.js')
      const child = ChildProcess.fork(script, [socketPath])
      child.on('exit', (code) => {
        assert.strictEqual(code, 0)
        const client = require('net').connect(socketPath)
        client.on('error', (error) => {
          assert.strictEqual(error.code, 'ECONNREFUSED')
          done()
        })
      })
    })
  })

  describe('Buffer', () => {
    it('can be created from WebKit external string', () => {
      const p = document.createElement('p')
      p.innerText = '闲云潭影日悠悠，物换星移几度秋'
      const b = Buffer.from(p.innerText)
      assert.strictEqual(b.toString(), '闲云潭影日悠悠，物换星移几度秋')
      assert.strictEqual(Buffer.byteLength(p.innerText), 45)
    })

    it('correctly parses external one-byte UTF8 string', () => {
      const p = document.createElement('p')
      p.innerText = 'Jøhänñéß'
      const b = Buffer.from(p.innerText)
      assert.strictEqual(b.toString(), 'Jøhänñéß')
      assert.strictEqual(Buffer.byteLength(p.innerText), 13)
    })

    it('does not crash when creating large Buffers', () => {
      let buffer = Buffer.from(new Array(4096).join(' '))
      assert.strictEqual(buffer.length, 4095)
      buffer = Buffer.from(new Array(4097).join(' '))
      assert.strictEqual(buffer.length, 4096)
    })

    it('does not crash for crypto operations', () => {
      const crypto = require('crypto')
      const data = 'lG9E+/g4JmRmedDAnihtBD4Dfaha/GFOjd+xUOQI05UtfVX3DjUXvrS98p7kZQwY3LNhdiFo7MY5rGft8yBuDhKuNNag9vRx/44IuClDhdQ='
      const key = 'q90K9yBqhWZnAMCMTOJfPQ=='
      const cipherText = '{"error_code":114,"error_message":"Tham số không hợp lệ","data":null}'
      for (let i = 0; i < 10000; ++i) {
        const iv = Buffer.from('0'.repeat(32), 'hex')
        const input = Buffer.from(data, 'base64')
        const decipher = crypto.createDecipheriv('aes-128-cbc', Buffer.from(key, 'base64'), iv)
        const result = Buffer.concat([decipher.update(input), decipher.final()]).toString('utf8')
        assert.strictEqual(cipherText, result)
      }
    })
  })

  describe('process.stdout', () => {
    it('does not throw an exception when accessed', () => {
      assert.doesNotThrow(() => {
        // eslint-disable-next-line
        process.stdout
      })
    })

    it('does not throw an exception when calling write()', () => {
      assert.doesNotThrow(() => {
        process.stdout.write('test')
      })
    })

    it('should have isTTY defined on Mac and Linux', function () {
      if (isCI || process.platform === 'win32') {
        this.skip()
        return
      }

      assert.strictEqual(typeof process.stdout.isTTY, 'boolean')
    })

    it('should have isTTY undefined on Windows', function () {
      if (isCI || process.platform !== 'win32') {
        this.skip()
        return
      }

      assert.strictEqual(process.stdout.isTTY, undefined)
    })
  })

  describe('process.stdin', () => {
    it('does not throw an exception when accessed', () => {
      assert.doesNotThrow(() => {
        process.stdin // eslint-disable-line
      })
    })

    it('returns null when read from', () => {
      assert.strictEqual(process.stdin.read(), null)
    })
  })

  describe('process.version', () => {
    it('should not have -pre', () => {
      assert(!process.version.endsWith('-pre'))
    })
  })

  describe('vm.runInNewContext', () => {
    it('should not crash', () => {
      require('vm').runInNewContext('')
    })
  })

  describe('crypto', () => {
    it('should list the ripemd160 hash in getHashes', () => {
      expect(require('crypto').getHashes()).to.include('ripemd160')
    })

    it('should be able to create a ripemd160 hash and use it', () => {
      const hash = require('crypto').createHash('ripemd160')
      hash.update('electron-ripemd160')
      expect(hash.digest('hex')).to.equal('fa7fec13c624009ab126ebb99eda6525583395fe')
    })

    it('should list aes-{128,256}-cfb in getCiphers', () => {
      expect(require('crypto').getCiphers()).to.include.members(['aes-128-cfb', 'aes-256-cfb'])
    })

    it('should be able to create an aes-128-cfb cipher', () => {
      require('crypto').createCipheriv('aes-128-cfb', '0123456789abcdef', '0123456789abcdef')
    })

    it('should be able to create an aes-256-cfb cipher', () => {
      require('crypto').createCipheriv('aes-256-cfb', '0123456789abcdef0123456789abcdef', '0123456789abcdef')
    })

    it('should list des-ede-cbc in getCiphers', () => {
      expect(require('crypto').getCiphers()).to.include('des-ede-cbc')
    })

    it('should be able to create an des-ede-cbc cipher', () => {
      const key = Buffer.from('0123456789abcdeff1e0d3c2b5a49786', 'hex')
      const iv = Buffer.from('fedcba9876543210', 'hex')
      require('crypto').createCipheriv('des-ede-cbc', key, iv)
    })

    it('should not crash when getting an ECDH key', () => {
      const ecdh = require('crypto').createECDH('prime256v1')
      expect(ecdh.generateKeys()).to.be.an.instanceof(Buffer)
      expect(ecdh.getPrivateKey()).to.be.an.instanceof(Buffer)
    })

    it('should not crash when generating DH keys or fetching DH fields', () => {
      const dh = require('crypto').createDiffieHellman('modp15')
      expect(dh.generateKeys()).to.be.an.instanceof(Buffer)
      expect(dh.getPublicKey()).to.be.an.instanceof(Buffer)
      expect(dh.getPrivateKey()).to.be.an.instanceof(Buffer)
      expect(dh.getPrime()).to.be.an.instanceof(Buffer)
      expect(dh.getGenerator()).to.be.an.instanceof(Buffer)
    })

    it('should not crash when creating an ECDH cipher', () => {
      const crypto = require('crypto')
      const dh = crypto.createECDH('prime256v1')
      dh.generateKeys()
      dh.setPrivateKey(dh.getPrivateKey())
    })
  })

  it('includes the electron version in process.versions', () => {
    expect(process.versions)
      .to.have.own.property('electron')
      .that.is.a('string')
      .and.matches(/^\d+\.\d+\.\d+(\S*)?$/)
  })

  it('includes the chrome version in process.versions', () => {
    expect(process.versions)
      .to.have.own.property('chrome')
      .that.is.a('string')
      .and.matches(/^\d+\.\d+\.\d+\.\d+$/)
  })
})
