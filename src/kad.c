#include <stdint.h>
#include <stdbool.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>

void
timer_cb(
         evutil_socket_t fd,
         short event,
         void* arg
         )
{

}

bool
setup_event_base(
                        )
{
  bool result = false;
  struct event_base* base;
  struct event* timer_evt;

  do {

    base = event_base_new();

    if (!base){

      break;

    }

    timer_evt = evtimer_new(base, timer_cb, NULL);    

    if (!timer_evt) break;

#if (0 != evtimer_add(timer_evt, ))

    result = true;

  } while (false);

  return result;
}

int main(int argc, char** argv)
{
  return 0;
}
