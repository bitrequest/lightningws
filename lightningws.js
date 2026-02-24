const WebSocket = require("ws").Server,
	express = require("express"),
	app = express(),
	server = new WebSocket({
		"server": app.listen(8040)
	}),
	clients = new Map();

server.on("connection", socket => {
	let socket_id = null;
	socket.on("message", message => {
		const object = JSON.parse(message);
		socket_id = object.id;
		clients.set(socket_id, socket);
		socket.send(JSON.stringify({
			"pid": object.id,
			"status": "opened"
		}));
	});
	socket.onclose = function() {
		if (socket_id) {
			clients.delete(socket_id);
		}
	};
});

app.post("/", function(req, res) {
	const post_string = req.headers.post,
		post_object = JSON.parse(post_string),
		inv_id = post_object.pid,
		client = clients.get(inv_id);
	if (client && client.readyState === 1) {
		client.send(post_string);
	}
	res.sendStatus(200);
});

// ─── NWC / SPARK cryptography ───────────────────────────────────────────────────────────────────
const nwc = require("./nwc");
nwc.register(app);
nwc.registerSpark(app);
