
window.onload = function() {
	ws = new WebSocket("ws://" + location.host + "/");
	ws.onopen = function() {
		ws.send("hello");
		ws.onmessage = function(m) {
			document.getElementById('txt').innerHTML = "received '" + m.data + "' from server";
		}
	}
}

