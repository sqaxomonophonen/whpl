/*
This software is in the public domain. Where that dedication is not recognized,
you are granted a perpetual, irrevocable license to copy and modify this file
as you see fit.
*/

#include "whpl.h"

#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>

#if __linux
#include <sys/sendfile.h>
#endif

#include "sha1.h"
#include "base64.h"
#include "log.h"


#define READ_BUFFER_SIZE (32768)
#define WRITE_BUFFER_SIZE (READ_BUFFER_SIZE)
#define PERM_BUFFER_SIZE (READ_BUFFER_SIZE)
#define TEMP_BUFFER_SIZE (READ_BUFFER_SIZE)

struct http_parser {
	char* begin;
	enum {
		HP_METHOD = 0,
		HP_URL,
		HP_VERSION,
		HP_HEADERS,
		HP_BODY
	} where;
	int z;

	int err;

};

struct __abuffer {
	size_t sz;
	size_t top;
	size_t save_top;
};

static void abuffer_init(char* b, size_t total)
{
	if (total < sizeof(struct __abuffer)) {
		critf("abuffer_init: need more than %zu bytes to work with!", sizeof(struct __abuffer));
	}
	struct __abuffer* a = (struct __abuffer*) b;
	a->sz = total - sizeof(struct __abuffer);
	a->top = 0;
}

static void* abuffer_alloc(char* b, size_t sz)
{
	struct __abuffer* a = (struct __abuffer*) b;
	if (a->top + sz > a->sz) return NULL;
	char* trix = (char*)(a+1);
	void* r = (void*) (trix + a->top);
	a->top += sz;
	return r;
}

static void abuffer_save(char* b)
{
	struct __abuffer* a = (struct __abuffer*) b;
	a->save_top = a->top;
}

static void abuffer_restore(char* b)
{
	struct __abuffer* a = (struct __abuffer*) b;
	a->top = a->save_top;
}


#if 0
static void abuffer_reset(char* b) {
	struct __abuffer* a = (struct __abuffer*) b;
	a->top = 0;
}
#endif

struct whpl_conn {
	int fd;

	void (*write_fn)(struct whpl_conn*);
	void (*read_fn)(struct whpl_conn*);

	struct http_parser hp;
	struct whpl_req req;

	size_t read_buffer_top;
	char read_buffer[READ_BUFFER_SIZE];
	char write_buffer[WRITE_BUFFER_SIZE];
	char perm_buffer[PERM_BUFFER_SIZE];
	char temp_buffer[TEMP_BUFFER_SIZE];

	int status;
	int stream_fd;
	int z;
	int n;
	struct stat stat;
	struct whpl_mime* mime;

	int ws_text_frame;

	struct whpl_conn* next;
};

static void drop_conn(struct whpl_conn* conn) {
	if (conn->fd == -1) {
		warnf("attempt to drop already dropped connection");
	} else {
		if (conn->req.on_ws_message) {
			conn->req.on_ws_message(&conn->req, NULL, -1);
			conn->req.on_ws_message = NULL;
		}
		close(conn->fd);
		conn->fd = -1; /* mark for "garbage collection" */
	}
}

const char _ucmask = ~32;

struct _method_map_t {
	char* string;
	int method;
} _method_map[] = {
	{"GET", mGET},
	{"HEAD", mHEAD},
	{"POST", mPOST},
	{"PUT", mPUT},
	{"OPTIONS", mOPTIONS},
	{"DELETE", mDELETE},
	{"CONNECT", mCONNECT},
	{NULL, mUNKNOWN}};

static void parse_http_method(struct whpl_conn* conn, char** buf, size_t* n)
{
	struct http_parser* hp = &conn->hp;
	struct whpl_req* req = &conn->req;
	if (hp->begin == 0) hp->begin = *buf;
	while ((*n) > 0) {
		char c = **buf;
		if (c == ' ') {
			size_t len = *buf - hp->begin;
			req->method_string = abuffer_alloc(conn->perm_buffer, len + 1);
			if (req->method_string == NULL) {
				errf("eeek! out of perm_buffer memory when trying to allocate %zu for method", len + 1);
				drop_conn(conn);
				return;
			}
			memcpy(req->method_string, hp->begin, len);
			req->method_string[len] = 0;
			struct _method_map_t* mm = _method_map;
			while (mm->string) {
				if(whpl_ieq(mm->string, req->method_string)) break;
				mm++;
			}
			req->method = mm->method;
			dbgf("got method: %s", req->method_string);
			(*buf)++;
			(*n)--;
			hp->where = HP_URL;
			hp->begin = 0;
			return;
		} else {
			char uc = **buf & _ucmask;
			if(uc < 'A' || uc > 'Z') {
				hp->err = 1;
				return;
			}
			(*buf)++;
			(*n)--;
		}
	}
}

static void parse_http_url(struct whpl_conn* conn, char** buf, size_t* n)
{
	struct http_parser* hp = &conn->hp;
	struct whpl_req* req = &conn->req;
	if (hp->begin == 0) hp->begin = *buf;
	while ((*n) > 0) {
		char c = **buf;
		if (c == ' ') {
			size_t len = *buf - hp->begin;
			req->raw_url = abuffer_alloc(conn->perm_buffer, len + 1);
			if (req->raw_url == NULL) {
				errf("eeek! out of perm_buffer memory when trying to allocate %zu for url", len + 1);
				drop_conn(conn);
				return;
			}
			memcpy(req->raw_url, hp->begin, len);
			req->raw_url[len] = 0;
			dbgf("got url: %s", req->raw_url);
			req->path = req->raw_url; /* XXX must do some parsing first! */
			req->subpath = req->path;
			/* TODO can do more url parsing; figure out all the
			 * parts */
			(*buf)++;
			(*n)--;
			hp->where = HP_VERSION;
			hp->begin = 0;
			return;
		}
		(*buf)++;
		(*n)--;
	}
}

static void parse_http_version(struct whpl_conn* conn, char** buf, size_t* n)
{
	struct http_parser* hp = &conn->hp;
	struct whpl_req* req = &conn->req;
	if (hp->begin == 0) hp->begin = *buf;
	while ((*n) > 0) {
		char c = **buf;
		size_t len = *buf - hp->begin;
		if (len > 12) {
			dbgf("http version longer than 12 characters? what is this, the future?!");
			drop_conn(conn);
			return;
		}
		if (c == '\r') {
			if ((*n) < 2 || (*buf)[1] != '\n') {
				dbgf("malformed input");
				drop_conn(conn);
				return;
			}
			req->version = abuffer_alloc(conn->perm_buffer, len + 1);
			if (req->version == NULL) {
				errf("eeek! out of perm_buffer memory when trying to allocate %zu for version", len + 1);
				drop_conn(conn);
				return;
			}
			memcpy(req->version, hp->begin, len);
			req->version[len] = 0;
			dbgf("got version: %s", req->version);
			(*buf)+=2;
			(*n)-=2;
			hp->where = HP_HEADERS;
			hp->begin = 0;
			hp->z = 0;
			return;
		}
		(*buf)++;
		(*n)--;
	}
}

static void parse_http_headers__field(struct whpl_conn* conn, char** buf, size_t* n)
{
	struct http_parser* hp = &conn->hp;
	struct whpl_req* req = &conn->req;
	if (hp->begin == 0) hp->begin = *buf;
	while ((*n) > 0) {
		char c = **buf;
		size_t len = *buf - hp->begin;
		if (len == 0 && c == '\r') {
			if ((*n) < 2 || (*buf)[1] != '\n') {
				dbgf("malformed input");
				drop_conn(conn);
				return;
			}
			(*buf)+=2;
			(*n)-=2;
			hp->where = HP_BODY;
			hp->begin = 0;
			return;
		} else if (c == ':') {
			struct whpl_hdr* h = abuffer_alloc(conn->perm_buffer, sizeof(struct whpl_hdr));
			if (h == NULL) {
				errf("eeek! out of perm_buffer memory when trying to allocate %zu for whpl_hdr", len + 1);
				drop_conn(conn);
				return;
			}
			h->field = abuffer_alloc(conn->perm_buffer, len + 1);
			if (h->field == NULL) {
				errf("eeek! out of perm_buffer memory when trying to allocate %zu for header field", len + 1);
				drop_conn(conn);
				return;
			}
			h->body = NULL;
			memcpy(h->field, hp->begin, len);
			h->field[len] = 0;
			h->next = req->headers;
			req->headers = h;
			hp->begin = 0;
			hp->z = 1;
			(*buf)++;
			(*n)--;
			return;
		} else if (c < 33 && c > 126) {
			dbgf("malformed input, invalid char %d", c);
			drop_conn(conn);
			return;
		}
		(*buf)++;
		(*n)--;
	}
}

static void parse_http_headers__body(struct whpl_conn* conn, char** buf, size_t* n)
{
	struct http_parser* hp = &conn->hp;
	struct whpl_req* req = &conn->req;
	while ((*n) > 0) {
		char c = **buf;
		if (hp->begin == 0 && c != ' ') hp->begin = *buf;
		size_t len = *buf - hp->begin;
		if (c == '\r') {
			if ((*n) < 2 || (*buf)[1] != '\n') {
				dbgf("malformed input");
				drop_conn(conn);
				return;
			}
			req->headers->body = abuffer_alloc(conn->perm_buffer, len + 1);
			if (req->headers->body == NULL) {
				dbgf("eeek! out of perm_buffer memory when trying to allocate %zu for header body", len + 1);
				drop_conn(conn);
				return;
			}
			memcpy(req->headers->body, hp->begin, len);
			req->headers->body[len] = 0;
			hp->begin = 0;

			dbgf("got header -- '%s': '%s'", req->headers->field, req->headers->body);
			hp->z = 0;
			(*buf)+=2;
			(*n)-=2;
			return;
		} else if (c > 127) {
			dbgf("malformed input, invalid char %d", c);
			drop_conn(conn);
			return;
		}
		(*buf)++;
		(*n)--;
	}
}

static void parse_http_headers(struct whpl_conn* conn, char** buf, size_t* n)
{
	struct http_parser* hp = &conn->hp;
	switch (hp->z) {
		case 0:
			parse_http_headers__field(conn, buf, n);
			break;
		case 1:
			parse_http_headers__body(conn, buf, n);
			break;
		default:
			critf("unexpected z value: %d", hp->z);
	}
}

static void parse_http(struct whpl_conn* conn, char* buf, size_t n)
{
	while (n > 0 && !conn->hp.err && conn->fd != -1) {
		switch (conn->hp.where) {
			case HP_METHOD:
				parse_http_method(conn, &buf, &n);
				break;
			case HP_URL:
				parse_http_url(conn, &buf, &n);
				break;
			case HP_VERSION:
				parse_http_version(conn, &buf, &n);
				break;
			case HP_HEADERS:
				parse_http_headers(conn, &buf, &n);
				if(conn->hp.where == HP_BODY) return;
				break;
			case HP_BODY:
				critf("did not expect HP_BODY");
				break;
			default:
				critf("unexpected state %d", conn->hp.where);
				exit(1);
		}
	}
}

static void write_simple_status(struct whpl_conn* conn);

static void on_body(struct whpl_conn* conn)
{
	conn->read_fn = NULL;

	if (strcmp(conn->req.version, "HTTP/1.1") != 0) {
		conn->status = 505;
		conn->write_fn = write_simple_status;
		return;
	}

	/* scan for interesting headers */
	char* _host = NULL;
	char* _upgrade = NULL;
	char* _connection = NULL;
	#if 0
	char* _authentication = NULL;
	#endif
	char* _ws_key = NULL;
	char* _ws_version = NULL;
	struct whpl_hdr* hs = conn->req.headers;
	while (hs) {
		char* f = hs->field;
		if(whpl_ieq(f, "host")) {
			_host = hs->body;
		} else if (whpl_ieq(f, "upgrade")) {
			_upgrade = hs->body;
		} else if (whpl_ieq(f, "connection")) {
			_connection = hs->body;
		} else if (whpl_ieq(f, "authentication")) {
			#if 0
			_authentication = hs->body;
			#endif
		} else if (whpl_ieq(f, "sec-websocket-key")) {
			_ws_key = hs->body;
		} else if (whpl_ieq(f, "sec-websocket-version")) {
			_ws_version = hs->body;
		}
		hs = hs->next;
	}

	if (!_host) {
		conn->status = 400;
		conn->write_fn = write_simple_status;
	} else if (_upgrade && whpl_ieq(_upgrade, "websocket")) {
		/* websocket upgrade requested; check if other requirements are
		 * met */
		int fail = 0;
		fail |= conn->req.method != mGET;
		fail |= !_connection || !whpl_ieq(_connection, "upgrade");
		fail |= !_ws_version || !whpl_ieq(_ws_version, "13");
		fail |= !_ws_key || strlen(_ws_key) != 24;
		if (fail) {
			conn->status = 400;
			conn->write_fn = write_simple_status;
		} else {
			conn->status = 404;
			conn->write_fn = write_simple_status;
			if (conn->req.srv->on_ws_connect) {
				conn->req.srv->on_ws_connect(&conn->req);
			}
		}
	} else if (conn->req.srv->on_http_request) {
		conn->req.srv->on_http_request(&conn->req);
	} else {
		conn->status = 404;
		conn->write_fn = write_simple_status;
	}

	/* TODO check for basic auth */
}

static void read_http(struct whpl_conn* conn)
{
	char* buf = conn->read_buffer + conn->read_buffer_top;
	size_t nmax = READ_BUFFER_SIZE - conn->read_buffer_top;
	ssize_t n = read(conn->fd, buf, nmax);
	if (n > 0) {
		conn->read_buffer_top += n;
		parse_http(conn, buf, n);
		if (conn->hp.err) {
			dbgf("http parser error, dropping connection");
			drop_conn(conn);
		} else if (conn->hp.where != HP_BODY && conn->read_buffer_top == READ_BUFFER_SIZE) {
			/* XXX */
			dbgf("ARGH -- read http request header until top (%d)", READ_BUFFER_SIZE);
			dbgf("and still found no body; dropping connection,");
			dbgf("but ought to throw a 413 or 414 for good meassure");
			/* FIXME */
			drop_conn(conn);
		} else if (conn->hp.where == HP_BODY) {
			on_body(conn);
		}
	} else if (n == 0) {
		dbgf("(connection lost)"); /* XXX */
		drop_conn(conn);
	} else {
		if (errno == EAGAIN) return;
		perror("read");
		exit(1);
	}
}


static void whpl_conn_reset(struct whpl_conn* conn)
{
	/* no writer */
	conn->write_fn = NULL;

	/* setup reader */
	conn->read_fn = read_http;

	/* clear some structures ... */
	bzero(&conn->hp, sizeof(struct http_parser));
	struct whpl_srv* srv = conn->req.srv;
	bzero(&conn->req, sizeof(struct whpl_req));
	conn->req.srv = srv;
	conn->req.conn = conn;

	/* clear some other stuff */
	conn->read_buffer_top = 0;
	conn->status = 0;
	conn->stream_fd = 0;
	conn->n = 0;
	conn->z = 0;
	conn->mime = NULL;

	/* init perm buffer */
	abuffer_init(conn->perm_buffer, PERM_BUFFER_SIZE);
}


/* XXX some serious bugs if you stress it! don't trust it */
static void path_clean(char* p)
{
	char* d = p;
	char* anchors[2] = {d,d};
	char prev = 0;
	int sta = 1;
	while (*p) {
		if (*p == '/') {
			/* "//" */
			if (prev == '/') d--;
			/* "/./" */
			if (sta == 2) d = anchors[0];
			/* "/../" */
			if (sta == 3) d = anchors[1];
			anchors[1] = anchors[0];
			anchors[0] = d;
			sta = 1;
		} else {
			if (sta && *p == '.') {
				sta++;
			} else {
				sta = 0;
			}
		}
		prev = *p;
		*d = *p;
		d++;
		p++;
	}
	*d = 0;
}

static void write_simple_status(struct whpl_conn* conn)
{
	const size_t N = 1024;
	char buffer[N];
	char* msg = "Cellar Door";
	int s = conn->status;
	switch (conn->status) {
		case 400:
			msg = "Bad Request\n";
			break;
		case 404:
			msg = "Not Found\n";
			break;
		case 500:
			msg = "Internal Server Error\n";
			break;
		case 505:
			msg = "HTTP Version Not Supported\n";
			break;
	}
	int n = snprintf(buffer, N, "HTTP/1.1 %d %s\r\n", s, msg);
	int content_length = n - 11;
	n += snprintf(buffer + n, N - n, "Content-Type: text/plain\r\nContent-Length: %d\r\n\r\n%d %s", content_length, s, msg);
	ssize_t written = write(conn->fd, buffer, n);
	if (written == n) {
		whpl_conn_reset(conn);
	}
}

#if 0
char nybble_ascii(int i)
{
	if (i < 10) return '0' + i;
	if (i < 16) return 'a' + (i - 10);
	return '?';
}

void bin2hex(uint8_t* from, char* to, size_t n) {
	while (n > 0) {
		to[0] = nybble_ascii(*from >> 4);
		to[1] = nybble_ascii(*from & 15);
		from++;
		to+=2;
		n--;
	}
}
#endif

static void write_ws_message(struct whpl_conn* conn)
{
	uint8_t b[10];
	uint8_t fin = 0x80;
	uint8_t text_frame = 0x01;
	b[0] = fin | text_frame;
	size_t hsz = 0;
	if (conn->n < 126) {
		b[1] = (uint8_t) conn->n;
		hsz = 2;
	} else if (conn->n < 65536) {
		b[1] = 126;
		uint16_t* l = (uint16_t*) &b[2];
		*l = htons(conn->n);
		hsz = 4;
	} else {
		/* TODO */
		b[1] = 127;
		critf("ws message too large (%d)", conn->n);
	}
	write(conn->fd, b, hsz);
	write(conn->fd, conn->write_buffer, conn->n);
	/* TODO handle partial writes */
	conn->n = 0;
	conn->write_fn = NULL;
}

static void read_ws_frame(struct whpl_conn* conn)
{
	ssize_t n = read(conn->fd, conn->read_buffer, READ_BUFFER_SIZE);

	if (n < 0) {
		if (errno == EAGAIN) return;
		drop_conn(conn);
		return;
	} else if (n == 0) {
		dbgf("(ws connection lost)");
		drop_conn(conn);
		return;
	}

	dbgf("read_ws: %zd bytes!", n);

	char* b = conn->read_buffer; /* byte 0 */

	int fin = !! (*b & (1<<7));
	int rsv = *b & (0x40|0x20|0x10);
	int op = *b & 0xf;

	if (rsv) {
		/* reserved bits MUST be zero */
		drop_conn(conn);
		return;
	}

	switch (op) {
		case 0: /* continuation frame */
			break;
		case 1: /* text frame */
		case 2: /* binary frame */
			conn->ws_text_frame = (op == 1);
			conn->n = 0;
			break;
		case 8: /* connection close */
			drop_conn(conn); /* XXX play nice! :) */
			break;
		case 9: /* ping */
			/* TODO */
			errf("TODO implement ping");
			drop_conn(conn);
			break;
		case 10: /* pong */
			/* TODO */
			errf("TODO implement pong");
			drop_conn(conn);
			break;
		default: /* reserved or unexpected? */
			dbgf("unexpected ws op: %d", op);
			drop_conn(conn);
			break;
	}

	b++; /* byte 1 */

	int mask = !! (*b & (1<<7));
	if (!mask) {
		/* client frames MUST be masked */
		drop_conn(conn);
		return;
	}

	int pl7 = *b & 0x7f;

	b++; /* byte 2 */

	size_t payload_length = 0;
	if (pl7 < 126) {
		payload_length = pl7;
	} else if (pl7 == 126) {
		uint16_t* host_short = (uint16_t*) b;
		payload_length = ntohs(*host_short);
		b += 2;
	} else if (pl7 == 127) {
		/* TODO htonl for 64 bit */
		errf("64bit ws message length, dropping connection...");
		drop_conn(conn);
		return;
	} else {
		critf("invalid pl7 value %d", pl7);
	}

	/* check that there's room for data */
	if (payload_length > (TEMP_BUFFER_SIZE - conn->n)) {
		warnf("ws message too large; tried to read %zu bytes", payload_length);
		drop_conn(conn);
		return;
	}

	/* unmask payload */
	char mask_key[4] = {b[0], b[1], b[2], b[3]};
	b+=4;
	size_t i;
	for(i = 0; i < payload_length; i++) b[i] ^= mask_key[i&3];

	/* copy to temp buffer */
	memcpy(conn->temp_buffer + conn->n, b, payload_length);
	conn->n += payload_length;

	if (fin) {
		if (conn->req.on_ws_message) {
			conn->req.on_ws_message(&conn->req, conn->temp_buffer, conn->n);
		}
	}
}

static void write_ws_accept(struct whpl_conn* conn)
{
	struct whpl_hdr* h = whpl_hdr_find(conn->req.headers, "sec-websocket-key");
	if (h == NULL || strlen(h->body) != 24) {
		warnf("sec-websocket-key has invalid value");
		drop_conn(conn);
		return;
	}

	SHA1_CTX sha;
	SHA1_Init(&sha);
	SHA1_Update(&sha, (uint8_t*) h->body, 24);
	SHA1_Update(&sha, (uint8_t*) "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 36);
	uint8_t digest[SHA1_DIGEST_SIZE];
	SHA1_Final(&sha, digest);

	char enc[32];
	base64_encode(digest, SHA1_DIGEST_SIZE, enc);

	const size_t N = 1024;
	char buffer[N];

	int n = snprintf(buffer, N, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", enc);
	ssize_t written = write(conn->fd, buffer, n);
	if (written == n) {
		/* TODO handle partial writes? */
		conn->read_fn = read_ws_frame;
		conn->write_fn = NULL;
	}
}

static void stream_file_headers(struct whpl_conn* conn)
{
	const size_t N = 256;
	char buffer[N];
	char* mime = conn->mime ? conn->mime->mime : "binary/octet-stream";
	int n = snprintf(buffer, N, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\nETag: %s\r\n\r\n", mime, conn->n, conn->temp_buffer);
	ssize_t written = write(conn->fd, buffer, n);
	if (written == n) {
		conn->z = 1;
	} else {
		/* XXX no support for partial writes */
	}
}

static void stream_file_file(struct whpl_conn* conn)
{
	if (conn->n == 0) {
		close(conn->stream_fd);
		whpl_conn_reset(conn);
		return;
	}

	off_t len = 0;
	#if __APPLE__
	int e = sendfile(conn->stream_fd, conn->fd, 0, &len, NULL, 0);
	#elif __linux
	int e = sendfile(conn->fd, conn->stream_fd, NULL, conn->n);
	len = e;
	#endif

	if (e < 0) {
		if(errno == EAGAIN) return;
		perror("sendfile");
		drop_conn(conn);
	} else {
		conn->n -= len;
		if (conn->n == 0) {
			close(conn->stream_fd);
			whpl_conn_reset(conn);
		}
	}
}

static void stream_file(struct whpl_conn* conn
){
	switch (conn->z) {
		case 0:
			stream_file_headers(conn);
			break;
		case 1:
			stream_file_file(conn);
			break;
		default:
			critf("programmer error: did not expect z to be %d", conn->z);
	}
}

static void write_304(struct whpl_conn* conn)
{
	const size_t N = 256;
	char buffer[N];
	char* mime = conn->mime ? conn->mime->mime : "binary/octet-stream";
	int n = snprintf(buffer, N, "HTTP/1.1 304 Not Modified\r\nContent-Type: %s\r\nETag: %s\r\n\r\n", mime, conn->temp_buffer);
	ssize_t written = write(conn->fd, buffer, n);
	if (written == n) {
		conn->write_fn = NULL;
		whpl_conn_reset(conn);
	} else {
		/* XXX no support for partial writes */
	}
}



struct whpl_hdr* whpl_hdr_find(struct whpl_hdr* headers, char* field)
{
	while (headers) {
		if (whpl_ieq(headers->field, field)) return headers;
		headers = headers->next;
	}
	return NULL;
}

int whpl_subpath_match(char* component, char** subpath)
{
	char* c = component;
	char* p = *subpath;
	while (*c && *p) {
		if (*p == '/') {
			p++;
			continue;
		} else if (*c != *p) {
			return 0;
		}
		c++;
		p++;
	}
	if (*c == 0 && (*p == 0 || *p == '/')) {
		*subpath = p;
		return 1;
	} else {
		return 0;
	}
}

void whpl_status(struct whpl_req* req, int status)
{
	req->conn->status = status;
	req->conn->write_fn = write_simple_status;
	req->conn->read_fn = NULL;
}

void whpl_404(struct whpl_req* req)
{
	whpl_status(req, 404);
}

void whpl_500(struct whpl_req* req)
{
	whpl_status(req, 500);
}

void whpl_serve_static(struct whpl_req* req, char* root, char* _relative)
{
	char* pb = req->conn->perm_buffer;
	abuffer_save(pb);

	size_t rlen = strlen(_relative);
	char* relative = abuffer_alloc(pb, rlen + 1);
	if (relative == NULL) {
		errf("eeek! out of perm_buffer memory when trying to allocate %zu for relative path", rlen + 1);
		whpl_500(req);
		return;
	}
	memcpy(relative, _relative, rlen + 1);
	path_clean(relative);
	rlen = strlen(relative);

	char* exe = whpl_exepath();
	size_t xlen = strlen(exe);

	size_t rootlen = strlen(root);

	size_t n = xlen + 4 + rootlen + 1 + rlen;
	char* path = abuffer_alloc(pb, n + 1);
	char* pp = path;
	memcpy(pp, exe, xlen);
	pp += xlen;
	*(pp++) = '/'; *(pp++) = '.'; *(pp++) = '.'; *(pp++) = '/';
	memcpy(pp, root, rootlen);
	pp += rootlen;
	*(pp++) = '/';
	memcpy(pp, relative, rlen);
	pp += rlen;
	*pp = 0;

	path_clean(path);

	struct stat* st = &req->conn->stat;
	dbgf("stat path: %s", path);
	if (stat(path, st) == -1) {
		if (errno == ENOENT) {
			whpl_404(req);
		} else {
			perror("stat");
			whpl_500(req);
		}
	} else {
		/* generate etag for file */
		snprintf(req->conn->temp_buffer, TEMP_BUFFER_SIZE, "%lu:%lu", (long) st->st_ino, (long) st->st_mtime);

		struct whpl_hdr* if_none_match = whpl_hdr_find(req->headers, "if-none-match");
		if (if_none_match && strcmp(req->conn->temp_buffer, if_none_match->body) == 0) {
			req->conn->read_fn = NULL;
			req->conn->write_fn = write_304;
			req->conn->mime = whpl_srv_find_mime(req->srv, whpl_ext(path));
		} else {
			if (S_ISREG(st->st_mode)) {
				int fd = open(path, O_RDONLY | O_NONBLOCK);
				if (fd == -1) {
					perror("open");
					whpl_500(req);
				} else {
					req->conn->stream_fd = fd;
					req->conn->read_fn = NULL;
					req->conn->write_fn = stream_file;
					req->conn->n = st->st_size;
					req->conn->mime = whpl_srv_find_mime(req->srv, whpl_ext(path));
				}
			} else {
				whpl_404(req);
			}
		}
	}

	abuffer_restore(pb);
}

void whpl_kill(struct whpl_req* req)
{
	req->conn->fd = -1;
}

void whpl_ws_accept(struct whpl_req* req, void (*on_message)(struct whpl_req* req, char* msg, ssize_t len))
{
	req->conn->write_fn = write_ws_accept;
	req->on_ws_message = on_message;
}

void whpl_ws_send(struct whpl_req* req, void* data, size_t n)
{
	if (n > WRITE_BUFFER_SIZE) {
		critf("whpl_ws_send: message size (%zu) larger than WRITE_BUFFER_SIZE (%d)", n, WRITE_BUFFER_SIZE);
	}
	memcpy(req->conn->write_buffer, data, n);
	req->conn->n = n;
	req->conn->write_fn = write_ws_message;
}

void whpl_ws_send_str(struct whpl_req* req, char* str)
{
	whpl_ws_send(req, str, strlen(str));
}

void whpl_srv_init(struct whpl_srv* srv)
{
	bzero(srv, sizeof(struct whpl_srv));
	srv->http_ws_addr.sin_family = AF_INET;
}

void whpl_srv_set_inaddr_any(struct whpl_srv* srv)
{
	srv->http_ws_addr.sin_addr.s_addr = INADDR_ANY;
}

void whpl_srv_set_port(struct whpl_srv* srv, short port)
{
	srv->http_ws_addr.sin_port = htons(port);
}

void whpl_srv_add_mime(struct whpl_srv* srv, char* extension, char* mimetype)
{
	struct whpl_mime* mime = (struct whpl_mime*) malloc(sizeof(struct whpl_mime));

	size_t xlen = strlen(extension) + 1;
	mime->extension = malloc(xlen);
	memcpy(mime->extension, extension, xlen);

	size_t mlen = strlen(mimetype) + 1;
	mime->mime = malloc(mlen);
	memcpy(mime->mime, mimetype, mlen);

	mime->next = srv->mimes;
	srv->mimes = mime;
}

struct whpl_mime* whpl_srv_find_mime(struct whpl_srv* srv, char* extension)
{
	struct whpl_mime* ms = srv->mimes;
	while (ms) {
		if (whpl_ieq(ms->extension, extension)) return ms;
		ms = ms->next;
	}
	return NULL;
}

void whpl_run(struct whpl_srv* srv)
{
	int max_fd;
	fd_set rfds, wfds;

	int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		perror("socket");
		exit(1);
	}

	int yeah = 1;
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yeah, sizeof yeah);

	if (bind(listen_fd, (struct sockaddr *) &srv->http_ws_addr, sizeof(struct sockaddr_in)) < 0) {
		perror("bind");
		exit(1);
	}

	listen(listen_fd, 5);

	struct whpl_conn* cs;
	struct whpl_conn* connections = NULL;

	while (1) {
		/* figure out which file descriptors to select on */
		FD_ZERO(&wfds);
		FD_ZERO(&rfds);
		FD_SET(listen_fd, &rfds);
		max_fd = listen_fd;
		cs = connections;
		while (cs) {
			if (cs->write_fn) {
				FD_SET(cs->fd, &wfds);
				if (cs->fd > max_fd) max_fd = cs->fd;
				if (cs->stream_fd > 0) {
					FD_SET(cs->stream_fd, &rfds);
					if (cs->stream_fd > max_fd) max_fd = cs->stream_fd;
				}
			}
			if (cs->read_fn) {
				FD_SET(cs->fd, &rfds);
				if (cs->fd > max_fd) max_fd = cs->fd;
			}
			cs = cs->next;
		}

		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		int n = select(max_fd + 1, &rfds, &wfds, NULL, &tv);
		if (n > 0) {
			/* handle new connections */
			if (FD_ISSET(listen_fd, &rfds)) {
				struct sockaddr_in client_addr;
				socklen_t size = sizeof(client_addr);
				int client_fd = accept(listen_fd, (struct sockaddr*) &client_addr, &size);
				if (client_fd < 0) {
					perror("accept");
					exit(1);
				}

				/* set non-blocking */
				if (fcntl(client_fd, F_SETFL, O_NONBLOCK) == -1) {
					perror("fcntl(O_NONBLOCK)");
					exit(1);
				}

				/* allocate new connection */
				struct whpl_conn* conn;
				conn = (struct whpl_conn*) malloc(sizeof(struct whpl_conn));

				/* set defaults */
				whpl_conn_reset(conn);

				/* setup the basics */
				conn->fd = client_fd;
				conn->req.srv = srv;

				/* insert into linked list */
				conn->next = connections;
				connections = conn;
			}

			/* handle client reads and writes, and check for
			 * dropped connections */
			cs = connections;
			struct whpl_conn** ptr = &connections;
			while (cs) {
				struct whpl_conn** next_ptr = &cs->next;
				struct whpl_conn* next = cs->next;
				if (cs->write_fn && FD_ISSET(cs->fd, &wfds)) {
					if (cs->stream_fd <= 0 || FD_ISSET(cs->stream_fd, &rfds)) {
						cs->write_fn(cs);
					}
				}
				if (cs->read_fn && FD_ISSET(cs->fd, &rfds)) {
					cs->read_fn(cs);
				}
				if (cs->fd == -1) {
					/* connection marked for collection */
					dbgf("dropping connection (%p) !", cs);
					*ptr = cs->next;
					free(cs);
				} else {
					ptr = next_ptr;
				}
				cs = next;
			}
		} else if (n == 0) {
			/* TODO timeout -- possibly check connections for timeout? */
		} else {
			/* TODO handle possible error or interrupt? */
		}
	}

	close(listen_fd);
}

int whpl_ieq(char* a, char* b)
{
	for (;;) {
		if (*a == 0 && *b == 0) return 1;
		if (*a == 0 || *b == 0) return 0;
		if ((*a&_ucmask) >= 'A' && (*a&_ucmask) <= 'Z') {
			if ((*a&_ucmask) != (*b&_ucmask)) return 0;
		} else {
			if (*a != *b) return 0;
		}
		a++;
		b++;
	}
}

char* whpl_ext(char* path)
{
	size_t n = strlen(path);
	char* p = path + n - 1;
	while (p != path) {
		if(*p == '.') return p + 1;
		p--;
	}
	return path + n;
}

#if __APPLE__
#include <unistd.h>
#include <libproc.h>
static char exepath[PROC_PIDPATHINFO_MAXSIZE];
static int exepath_populated = 0;
char* whpl_exepath()
{
	if (!exepath_populated) {
		int ret = proc_pidpath(getpid(), exepath, sizeof(exepath));
		if (ret <= 0) {
			perror("proc_pidpath");
			exit(1);
		}
		exepath_populated = 1;
	}
	return exepath;
}
#elif __linux

#define _EXE_PATH_LENGTH (4096)
static char exepath[_EXE_PATH_LENGTH];
static int exepath_populated = 0;
char* whpl_exepath()
{
	if (!exepath_populated) {
		if (readlink("/proc/self/exe", exepath, _EXE_PATH_LENGTH) < 0) {
			perror("readlink");
			exit(1);
		}
		exepath_populated = 1;
	}
	return exepath;
}
#else
#error "TODO exepath implementation for whatever platform this is"
#endif

