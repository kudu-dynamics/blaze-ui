
function connectToBlaze() {
    var uri = "ws://" + blazeServerHost + ":" + blazeServerWsPort + "/web/" + sessionId;
    var socket = new WebSocket(uri);
    console.log(socket.readyState);
    return socket;
};



function mainUI () {
    var socket = connectToBlaze();
    socket.onopen = function (event) {
        // this is probably where you could launch the web framework
        // passing in the socket
        var msg = {tag: "WSTextMessage",
                   message: "Hey there, champion"
                  };
        socket.send(JSON.stringify(msg));
    };
    socket.onmessage = function (event) {
        console.log(JSON.parse(event.data));
    };
};
