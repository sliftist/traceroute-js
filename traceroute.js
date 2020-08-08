const dgram = require('dgram');
const raw = require('raw-socket');
const dns = require('dns-then');

const MAX_HOPS = 64;
const MAX_TIMEOUT_IN_MILLISECONDS = 1000;
let port = 33434;

module.exports.trace = trace;
function trace(destination) {
    const icmpSocket = raw.createSocket({ protocol: raw.Protocol.ICMP });
    const udpSocket = dgram.createSocket('udp4');

    let DESTINATION_IP = destination;

    let ttl = 1;
    let tries = 0;

    let startTime;
    let timeout;
    let previousIP;

    icmpSocket.on('message', async function (buffer, ip) {
        let p = buffer.toString('hex').substr(100, 4);
        let portNumber = parseInt(p, 16);
        if (port === portNumber) {
            try {
                let symbolicAddress = await dns.reverse(ip);
                handleReply(ip, symbolicAddress[0]);
            } catch (e) {
                handleReply(ip);
            }
        }
    });

    return new Promise(resolve => {
        DESTINATION_IP = await dns.lookup(DESTINATION_HOST);

        let output = "";
        output += `traceroute to ${DESTINATION_HOST} (${DESTINATION_IP}), ${MAX_HOPS} hops max, 42 byte packets\n`;
        udpSocket.bind(1234, () => sendPacket());

        function sendPacket() {
            port++;

            if (tries >= 3) {
                tries = 0;
                ttl++;
            }
            tries++;

            udpSocket.setTTL(ttl);
            startTime = process.hrtime();
            udpSocket.send(new Buffer(''), 0, 0, port, DESTINATION_IP, function (err) {
                if (err) throw err;
                timeout = setTimeout(handleReply, MAX_TIMEOUT_IN_MILLISECONDS);
            });
        }

        function handleReply(ip, symbolicAddress) {
            if (timeout) {
                clearTimeout(timeout);
            }

            if (ip) {
                const elapsedTime = `${(process.hrtime(startTime)[1] / 1000000).toFixed(3)} ms`;

                if (ip === previousIP) {
                    output += (`    ${elapsedTime}`);
                } else if (tries === 1) {
                    output += (`\n ${ttl}    ${symbolicAddress ? symbolicAddress : ip} (${ip}) ${elapsedTime}`);
                } else {
                    output += (`\n        ${symbolicAddress ? symbolicAddress : ip} (${ip}) ${elapsedTime}`);
                }
            } else {
                if (tries === 1) {
                    output += (`\n ${ttl}    * `);
                } else {
                    output += (`* `);
                }
            }

            if ((ip == DESTINATION_IP && tries === 3) || ttl >= MAX_HOPS) {
                output += "\n";
                resolve(output);
                return;
            }

            previousIP = ip;
            setImmediate(sendPacket);
        }
    });
}
