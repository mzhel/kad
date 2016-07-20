#ifndef _KAD_H_
#define _KAD_H_

typedef struct _listener_ctx {
  struct event_base* base;
  void* arg;
  uint32_t ip4_no;
  uint16_t port_no;
} LISTENER_CTX;

typedef struct _conn_ctx {
  struct bufferevent* bev;
  struct event_base* base;
  void* arg;
  uint32_t ip4_no;
  uint16_t port_no;
} CONN_CTX;

typedef struct _timer_ctx {
  void* kad_session;
  void* mule_session;
} TIMER_CTX;

#endif // _KAD_H_
