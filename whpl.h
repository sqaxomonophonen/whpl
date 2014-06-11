/*
This software is in the public domain. Where that dedication is not recognized,
you are granted a perpetual, irrevocable license to copy and modify this file
as you see fit.
*/

#ifndef _WHPL_H_
#define _WHPL_H_

/*
Websocket/HTTP-Plug, or: whpl
 - stick it where you like!
*/

#include <netinet/in.h>

struct whpl_hdr {
	char* field;
	char* body;
	struct whpl_hdr* next;
};

struct whpl_hdr* whpl_hdr_find(struct whpl_hdr* headers, char* field);

struct whpl_req {
	enum {
		mUNKNOWN = 0,
		mDELETE,
		mGET,
		mHEAD,
		mPOST,
		mPUT,
		mCONNECT,
		mOPTIONS,
		mTRACE,
	} method;
	char* method_string;
	char* raw_url;
	char* version;
	char* path;
	char* subpath;
	struct whpl_hdr* headers;
	void (*on_ws_message)(struct whpl_req* req, char* msg, ssize_t len);
	struct whpl_srv* srv;
	struct whpl_conn* conn; /* "private" */
	void* data; /* user data */
};


/* if component matches the first path component found in subpath then 1 is
 * returned and subpath will point at the following component (if any).
 * otherwise 0 is returned and subpath is not modified. */
int whpl_subpath_match(char* component, char** subpath);


/* various standard responses */
void whpl_status(struct whpl_req* req, int status);
void whpl_404(struct whpl_req* req);
void whpl_500(struct whpl_req* req);

/* serve static file for request. search for file `relative` in `root`
 * (relative to executable). useful together with whpl_subpath_match() */
void whpl_serve_static(struct whpl_req* req, char* root, char* relative);

/* drop connection */
void whpl_kill(struct whpl_req* req);

/* accept websocket connection and register `on_message` as callback for
 * websocket messages. on_message will be called with msg=NULL,len==-1 when the
 * connection is dropped; you should clean up whpl_req.data if necessary when
 * this happens */
void whpl_ws_accept(struct whpl_req* req, void (*on_message)(struct whpl_req* req, char* msg, ssize_t len));

/* send data through websocket */
void whpl_ws_send(struct whpl_req* req, void* data, size_t n);
void whpl_ws_send_str(struct whpl_req* req, char* str);

struct whpl_mime {
	char* extension;
	char* mime;
	struct whpl_mime* next;
};

struct whpl_srv {
	/* bind address for http/websocket */
	struct sockaddr_in http_ws_addr;

	/* callbacks. may be NULL */
	void (*on_http_request)(struct whpl_req* req);
	void (*on_ws_connect)(struct whpl_req* req);

	struct whpl_mime* mimes;

	void* data;
};

/* initialize whpl server */
void whpl_srv_init(struct whpl_srv* srv);

/* configure to listen on any address */
void whpl_srv_set_inaddr_any(struct whpl_srv* srv);

/* set server port */
void whpl_srv_set_port(struct whpl_srv* srv, short port);

/* register mimetype for extension; used by whpl_serve_static() */
void whpl_srv_add_mime(struct whpl_srv* srv, char* extension, char* mimetype);

/* find mime for extension */
struct whpl_mime* whpl_srv_find_mime(struct whpl_srv* srv, char* extension);

/* run server */
void whpl_run(struct whpl_srv* srv);

/* case insensitive string compare */
int whpl_ieq(char* a, char* b);

/* get substring of path which is the extension, empty string if not found */
char* whpl_ext(char* path);

/* path of exectuable */
char* whpl_exepath();

#endif /*_WHPL_H_*/

