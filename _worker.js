import { connect } from 'cloudflare:sockets';

const ret_on_err = new Response(null, { status: 500 });

const earlyDataHeaderName = 'Sec-WebSocket-Protocol';

const disallow_ports = [0, 25];
export default {
	/**
	 *
	 * @param {Request} request
	 * @param {{ws_path: string, dh_path: string, rd_path: string, ws_ah_name: string, ws_ah_value: string, rd_ah_name: string, rd_ah_value: string, vless_uuid: string, rd_full_url_hname: string, rd_padding_hname: string}} env
	 * @param ctx
	 * @returns {Promise<Response>}
	 */
	async fetch(request, env, ctx) {
		try {
			const parsed_request_url = new URL(request.url);
			const req_path = parsed_request_url.pathname;

			switch (req_path) {
				case env.rd_path:
					const fu_hname = env.rd_full_url_hname;
					const ah_name = env.rd_ah_name;
					const redirectedUrl = request.headers.get(fu_hname);
					const rd_req_ah_value = request.headers.get(ah_name);
					if ((!redirectedUrl) || (!rd_req_ah_value) || (rd_req_ah_value !== env.rd_ah_value)) {
						return ret_on_err;
					}
					const newRequest = new Request(redirectedUrl, request);
					newRequest.headers.delete(fu_hname);
					newRequest.headers.delete(ah_name);
					newRequest.headers.delete(env.rd_padding_hname);
					return await fetch(newRequest);
				case env.dh_path:
					parsed_request_url.protocol = 'https:';
					parsed_request_url.hostname = 'clean.dnsforge.de';
					parsed_request_url.port = '443';
					parsed_request_url.pathname = '/dns-query';
					return await fetch(parsed_request_url.toString(), request);
				case env.ws_path:
					const upgradeHeader = request.headers.get('Upgrade');
					const ws_req_ah_value = request.headers.get(env.ws_ah_name);
					if ((!upgradeHeader) || (upgradeHeader !== 'websocket') || (!ws_req_ah_value) || (ws_req_ah_value !== env.ws_ah_value)) {
						return ret_on_err;
					}
					return await vlessOverWSHandler(request, env.vless_uuid);
				default:
					return ret_on_err;
			}

		} catch (err) {
			return ret_on_err;
		}
	}
};


/**
 * Handles VLESS over WebSocket requests by creating a WebSocket pair, accepting the WebSocket connection, and processing the VLESS header.
 * @param {Request} request The incoming request object.
 * @param {string} vless_uuid
 * @returns {Promise<Response>} A Promise that resolves to a WebSocket response object.
 */
async function vlessOverWSHandler(request, vless_uuid) {
	const earlyDataString = request.headers.get(earlyDataHeaderName);
	const webSocketPair = new WebSocketPair();
	/** @type {WebSocket} */
	const ws_use_client_resp = webSocketPair[0];
	/** @type {WebSocket} */
	const main_websocket = webSocketPair[1];
	main_websocket.accept();
	let is_healthy = true;
	let run_initialize = false;
	let remoteSocket;
	/** @type {ReadableStreamDefaultReader} */
	let remoteSocketReader;
	/** @type {WritableStreamDefaultWriter} */
	let remoteSocketWriter;

	async function close_all() {
		is_healthy = false;
		try {
			main_websocket.close();
		} catch (err) {
		}
		try {
			await remoteSocket.close();
		} catch (err) {
		}
		throw new Error('e');
	}

	async function full_check() {
		if (!is_healthy) {
			throw new Error('e');
		}
		if (main_websocket.readyState !== 1) {
			if (is_healthy) {
				await close_all();
			}
			throw new Error('e');
		}
	}

	async function remoteToWsTask() {
		let value;
		let done;
		while (!done) {
			await full_check();
			try {
				({ value, done } = await remoteSocketReader.read());
			} catch (err) {
				if (is_healthy) {
					await close_all();
				}
				throw new Error('e');
			}
			await full_check();
			if (done) {
				if (is_healthy) {
					await close_all();
				}
				throw new Error('e');
			}
			try {
				main_websocket.send(value);
			} catch (err) {
				if (is_healthy) {
					await close_all();
				}
				throw new Error('e');
			}

		}

	}

	/**
	 *
	 * @param {ArrayBuffer} vlessBuffer
	 * @returns {Promise<void>}
	 */
	async function initialize(vlessBuffer) {
		run_initialize = true;
		const {
			vlessVersion, addressType, addressRemote, portRemote, rawClientData, has_vless_client_data
		} = processVlessHeader(vlessBuffer, vless_uuid);
		remoteSocket = connect({ hostname: addressRemote, port: portRemote });
		remoteSocketReader = remoteSocket.readable.getReader();
		remoteSocketWriter = remoteSocket.writable.getWriter();
		if (has_vless_client_data) {
			await remoteSocketWriter.write(rawClientData);
		}
		await full_check();
		main_websocket.send((new Uint8Array([vlessVersion, 0])).buffer);
		await full_check();
		remoteToWsTask();
		await full_check();
	}


	async function ws_close_error_event_task(event) {
		if (is_healthy) {
			await close_all();
		}
		throw new Error('e');
	}

	async function ws_message_event_task(event) {
		await full_check();
		if (!run_initialize) {
			try {
				await initialize(event.data);
			} catch (err) {
				if (is_healthy) {
					await close_all();
				}
				throw new Error('e');
			}
			await full_check();
		} else {
			try {
				await remoteSocketWriter.write(event.data);
			} catch (err) {
				if (is_healthy) {
					await close_all();
				}
				throw new Error('e');
			}
			await full_check();
		}
	}

	await full_check();
	main_websocket.addEventListener('message', event => {
		if (!is_healthy) {
			throw new Error('e');
		}
		ws_message_event_task(event);
		if (!is_healthy) {
			throw new Error('e');
		}
	});
	await full_check();
	main_websocket.addEventListener('close', event => {
		if (!is_healthy) {
			throw new Error('e');
		}
		ws_close_error_event_task(event);
		throw new Error('e');
	});
	await full_check();
	main_websocket.addEventListener('error', event => {
		if (!is_healthy) {
			throw new Error('e');
		}
		ws_close_error_event_task(event);
		throw new Error('e');
	});


	await full_check();
	if (earlyDataString) {
		if (run_initialize) {
			if (is_healthy) {
				await close_all();
			}
			throw new Error('e');
		}
		try {
			await initialize(base64ToArrayBuffer(earlyDataString));
		} catch (err) {
			if (is_healthy) {
				await close_all();
			}
			throw new Error('e');
		}

	}
	await full_check();
	return new Response(null, {
		status: 101, webSocket: ws_use_client_resp
	});
}

// https://xtls.github.io/development/protocols/vless.html

/**
 * Processes the VLESS header buffer and returns an object with the relevant information.
 * @param {ArrayBuffer} vlessBuffer The VLESS header buffer to process.
 * @param {string} vless_uuid The user ID to validate against the UUID in the VLESS header.
 * @returns {{
 *  vlessVersion: number,
 *  addressType: number,
 *  addressRemote: string,
 *  portRemote: number,
 *  rawClientData: ArrayBuffer,
 *  has_vless_client_data: boolean
 * }} An object with the relevant information extracted from the VLESS header buffer.
 */
function processVlessHeader(vlessBuffer, vless_uuid) {
	if (!vlessBuffer) {
		throw new Error('e');
	}
	const len_vlessBuffer = vlessBuffer.byteLength;
	if (len_vlessBuffer < 24) {
		throw new Error('e');
	}

	const vlessVersion = (new Uint8Array(vlessBuffer.slice(0, 1)))[0];
	const slicedBuffer = new Uint8Array(vlessBuffer.slice(1, 17));
	const slicedBufferString = stringify(slicedBuffer);

	if (slicedBufferString !== vless_uuid) {
		throw new Error('e');
	}

	const optLength = (new Uint8Array(vlessBuffer.slice(17, 18)))[0];
	//skip opt for now

	const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];

	// 0x01 TCP
	// 0x02 UDP
	// 0x03 MUX
	if (command !== 1) {
		throw new Error('e');
	}
	const portIndex = 18 + optLength + 1;
	const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
	// port is big-Endian in raw data etc 80 == 0x0050
	const portRemote = new DataView(portBuffer).getUint16(0);
	if (disallow_ports.includes(portRemote)) {
		throw new Error('e');
	}

	const addressIndex = portIndex + 2;

	// 1--> ipv4  addressLength =4
	// 2--> domain name addressLength=addressBuffer[1]
	// 3--> ipv6  addressLength =16
	const addressType = (new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1)))[0];
	let addressLength = 0;
	let rawDataIndex = 0;
	const addressValueIndex = addressIndex + 1;
	let addressRemote = '';
	switch (addressType) {
		case 1:
			addressLength = 4;
			rawDataIndex = addressValueIndex + addressLength;
			addressRemote = (new Uint8Array(vlessBuffer.slice(addressValueIndex, rawDataIndex))).join('.');
			break;
		case 2:
			const finalHostnameIndex = addressValueIndex + 1;
			addressLength = (new Uint8Array(vlessBuffer.slice(addressValueIndex, finalHostnameIndex)))[0];
			rawDataIndex = finalHostnameIndex + addressLength;
			addressRemote = new TextDecoder().decode(vlessBuffer.slice(finalHostnameIndex, rawDataIndex));
			break;
		case 3:
			addressLength = 16;
			rawDataIndex = addressValueIndex + addressLength;
			const d_dataView = new DataView(vlessBuffer.slice(addressValueIndex, rawDataIndex));
			// 2001:0db8:85a3:0000:0000:8a2e:0370:7334
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				ipv6.push(d_dataView.getUint16(i * 2).toString(16));
			}
			addressRemote = ipv6.join(':');
			// seems no need add [] for ipv6
			break;
		default:
			throw new Error('e');
	}
	if (!addressRemote) {
		throw new Error('e');
	}
	if (addressRemote.length < 4) {
		throw new Error('e');
	}

	let has_vless_client_data = false;
	if (rawDataIndex > len_vlessBuffer) {
		throw new Error('e');
	} else if (rawDataIndex < len_vlessBuffer) {
		has_vless_client_data = true;
	}
	const rawClientData = vlessBuffer.slice(rawDataIndex);

	return {
		vlessVersion, addressType, addressRemote, portRemote, rawClientData, has_vless_client_data
	};
}


/**
 * Decodes a base64 string into an ArrayBuffer.
 * @param {string} base64Str The base64 string to decode.
 * @returns {ArrayBuffer} An object containing the decoded ArrayBuffer or null if there was an error, and any error that occurred during decoding or null if there was no error.
 */
function base64ToArrayBuffer(base64Str) {
	// go use modified Base64 for URL rfc4648 which js atob not support
	const binaryString = atob(base64Str.replace(/-/g, '+').replace(/_/g, '/'));
	const bytes = new Uint8Array(binaryString.length);
	for (let i = 0; i < binaryString.length; i++) {
		bytes[i] = binaryString.charCodeAt(i);
	}
	return bytes.buffer;

}

/**
 * Checks if a given string is a valid UUID.
 * Note: This is not a real UUID validation.
 * @param {string} uuid The string to validate as a UUID.
 * @returns {boolean} True if the string is a valid UUID, false otherwise.
 */
function isValidUUID(uuid) {
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	return uuidRegex.test(uuid);
}

const byteToHex = [];

for (let i = 0; i < 256; ++i) {
	byteToHex.push((i + 256).toString(16).slice(1));
}

function unsafeStringify(arr) {
	return (byteToHex[arr[0]] + byteToHex[arr[1]] + byteToHex[arr[2]] + byteToHex[arr[3]] + '-' + byteToHex[arr[4]] + byteToHex[arr[5]] + '-' + byteToHex[arr[6]] + byteToHex[arr[7]] + '-' + byteToHex[arr[8]] + byteToHex[arr[9]] + '-' + byteToHex[arr[10]] + byteToHex[arr[11]] + byteToHex[arr[12]] + byteToHex[arr[13]] + byteToHex[arr[14]] + byteToHex[arr[15]]).toLowerCase();
}

function stringify(arr) {
	const uuid = unsafeStringify(arr);
	if (!isValidUUID(uuid)) {
		throw new Error('e');
	}
	return uuid;
}
