/*
This software is in the public domain. Where that dedication is not recognized,
you are granted a perpetual, irrevocable license to copy and modify this file
as you see fit.
*/

#include <stdio.h>

#include "whpl.h"

void on_message(struct whpl_req* req, char* msg, ssize_t len)
{
	if (len < 0) {
		printf("lost websocket connection\n");
		return;
	}
	printf("got message from client: [");
	fwrite(msg, len, 1, stdout);
	printf("]\n");

	whpl_ws_send_str(req, "dillertrans");
}

void on_ws_connect(struct whpl_req* req)
{
	printf("[ws] %s %s %s\n", req->method_string, req->raw_url, req->version);
	whpl_ws_accept(req, on_message);
	//req->data = user data here
}

void on_http_request(struct whpl_req* req)
{
	printf("%s %s %s\n", req->method_string, req->raw_url, req->version);

	if (whpl_subpath_match("__static", &req->subpath)) {
		whpl_serve_static(req, "static", req->subpath);
	} else {
		whpl_serve_static(req, "static", "boot.html");
	}
}

int main(int argc, char** argv)
{
	struct whpl_srv srv;

	whpl_srv_init(&srv);
	whpl_srv_set_inaddr_any(&srv);
	whpl_srv_set_port(&srv, 8888);

	srv.on_http_request = on_http_request;
	srv.on_ws_connect = on_ws_connect;

	whpl_srv_add_mime(&srv, "html", "text/html; charset=utf-8");
	whpl_srv_add_mime(&srv, "js", "application/javascript; charset=utf-8");

	whpl_run(&srv);
	return 0;
}

