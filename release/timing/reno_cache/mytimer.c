/*==============================================================================================
__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'
==============================================================================================*/


/*mytimer.c*/

#include <stdint.h>
#include <string.h>
#include <sys/timerfd.h>
#include <pthread.h>
#include <poll.h>
#include <stdio.h>
#include <unistd.h>

#include "mytimer.h"

#define MAX_TIMER_COUNT 1000

struct timer_node
{
    int                 fd;
    time_handler        callback;
    void *              user_data;
    unsigned int        interval;
    t_timer             type;
    struct timer_node * next;
};

static void * _timer_thread(void * data);
static pthread_t g_thread_id;
static struct timer_node *g_head = NULL;

int initialize()
{
    if(pthread_create(&g_thread_id, NULL, _timer_thread, NULL))
    {
        /*Thread creation failed*/
        return 0;
    }

    return 1;
}

size_t start_timer(unsigned int interval, time_handler handler,
                   t_timer type, void * user_data)
{
    struct timer_node * new_node = NULL;
    struct itimerspec new_value;

    new_node = (struct timer_node *)malloc(sizeof(struct timer_node));

    if(new_node == NULL) return 0;

    new_node->callback  = handler;
    new_node->user_data = user_data;
    new_node->interval  = interval;
    new_node->type      = type;

    new_node->fd = timerfd_create(CLOCK_REALTIME, 0);

    if (new_node->fd == -1)
    {
        free(new_node);
        return 0;
    }

    int sec = interval / 1000;
    int r   = interval % 1000;

    new_value.it_value.tv_sec = sec;
    new_value.it_value.tv_nsec = r * 1000000;

    new_value.it_interval.tv_sec= sec;
    new_value.it_interval.tv_nsec = r * 1000000;

    timerfd_settime(new_node->fd, 0, &new_value, NULL);

    /*Inserting the timer node into the list*/
    new_node->next = g_head;
    g_head = new_node;

    printf("timer %p started, sec=%d, nsec=%d\n",
           new_node, sec, r * 1000000);
    return (size_t)new_node;
}

void stop_timer(size_t timer_id)
{
    struct timer_node * tmp = NULL;
    struct timer_node * node = (struct timer_node *)timer_id;

    if (node == NULL) return;

    close(node->fd);

    if(node == g_head)
    {
        g_head = g_head->next;
    } else {

      tmp = g_head;

      while(tmp && tmp->next != node) tmp = tmp->next;

      if(tmp)
      {
          /*tmp->next can not be NULL here*/
          tmp->next = tmp->next->next;
      }
    }
    if(node) free(node);
}

void finalize()
{
    while(g_head) stop_timer((size_t)g_head);

    pthread_cancel(g_thread_id);
    pthread_join(g_thread_id, NULL);
}

struct timer_node * _get_timer_from_fd(int fd)
{
    struct timer_node * tmp = g_head;

    while(tmp)
    {
        if(tmp->fd == fd) return tmp;

        tmp = tmp->next;
    }
    return NULL;
}

void * _timer_thread(void * data)
{
    struct pollfd ufds[MAX_TIMER_COUNT] = {{0}};
    int iMaxCount = 0;
    struct timer_node * tmp = NULL;
    int read_fds = 0, i, s;
    uint64_t exp;

    while(1)
    {
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        pthread_testcancel();
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

        iMaxCount = 0;
        tmp = g_head;

        memset(ufds, 0, sizeof(struct pollfd)*MAX_TIMER_COUNT);
        while(tmp)
        {
            ufds[iMaxCount].fd = tmp->fd;
            ufds[iMaxCount].events = POLLIN;
            iMaxCount++;

            tmp = tmp->next;
        }
        read_fds = poll(ufds, iMaxCount, 100);

        if (read_fds <= 0) continue;

        for (i = 0; i < iMaxCount; i++)
        {
            if (ufds[i].revents & POLLIN)
            {
                s = read(ufds[i].fd, &exp, sizeof(uint64_t));

                if (s != sizeof(uint64_t)) continue;

                tmp = _get_timer_from_fd(ufds[i].fd);

                if(tmp && tmp->callback) tmp->callback((size_t)tmp, tmp->user_data);
            }
        }
    }

    return NULL;
}
