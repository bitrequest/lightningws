const WebSocket = require("ws").Server,
    express = require("express"),
    app = express(),
    server = new WebSocket({
        "server": app.listen(8040)
    });
let object_id = null;
let subscriptions = [];
let ws = null;

server.on("connection", socket => {
    ws = socket;
    socket.on("message", message => {
        var object = JSON.parse(message);
        object_id = object.id;
        subscriptions.push(object_id);
        socket.send(JSON.stringify({
            "pid": object.id,
            "status": "opened"
        }));
    });
    socket.onclose = function(e) {
        if (object_id) {
            var newarr = unsub(subscriptions, object_id);
            subscriptions = newarr;
        }
    };
});

app.post("/", function(req, res) {
    var post_string = req.headers.post,
        post_object = JSON.parse(post_string),
        inv_id = post_object.pid;
    if (ws) {
        if (subscriptions.includes(inv_id)) {
            ws.send(post_string);
        } else {
            ws.send("no match");
        }
    }
    res.sendStatus(200);
});

function unsub(subs, pid) {
    return subs.filter(f => f !== pid);
}