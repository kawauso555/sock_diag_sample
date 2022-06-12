#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

static int
send_query (int fd)
{
  struct sockaddr_nl nladdr = {
    .nl_family = AF_NETLINK
  };
  struct
  {
    struct nlmsghdr nlh;
    struct inet_diag_req_v2 idr;
  } req = {
    .nlh = {
	    .nlmsg_len = sizeof (req),
	    .nlmsg_type = SOCK_DIAG_BY_FAMILY,
	    .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP},
    .idr = {
	    .sdiag_family = AF_INET,
            .sdiag_protocol = IPPROTO_TCP,
	    .idiag_ext = 0,
	    .pad = 0,
	    .idiag_states = UINT32_MAX,
	    .id = {
		   .idiag_dport = htons (12345),
		   },
	    }
    };
  struct iovec iov = {
    .iov_base = &req,
    .iov_len = sizeof (req)
  };
  struct msghdr msg = {
    .msg_name = (void *) &nladdr,
    .msg_namelen = sizeof (nladdr),
    .msg_iov = &iov,
    .msg_iovlen = 1
  };

  for (;;)
    {
      if (sendmsg (fd, &msg, 0) < 0)
	{
	  if (errno == EINTR)
	    continue;

	  perror ("sendmsg");
	  return -1;
	}

      return 0;
    }
}

static int
print_diag (const struct inet_diag_msg *diag, unsigned int len)
{
  char src_addr [32];
  char dst_addr [32];

  if (len < NLMSG_LENGTH (sizeof (*diag)))
    {
      fputs ("short response\n", stderr);
      return -1;
    }
  if (diag->idiag_family != AF_INET)
    {
      fprintf (stderr, "unexpected family %u\n", diag->idiag_family);
      return -1;
    }

  inet_ntop(AF_INET, &(diag->id.idiag_src), src_addr, sizeof (src_addr));
  inet_ntop(AF_INET, &(diag->id.idiag_dst), dst_addr, sizeof (dst_addr));

  printf ("src: %s, sport: %d, dst: %s, dport:%d, state:%d\n",
	  src_addr, ntohs (diag->id.idiag_sport), dst_addr, ntohs (diag->id.idiag_dport), diag->idiag_state);

  return 0;
}

static int
receive_responses (int fd)
{
  long buf[8192 / sizeof (long)];
  struct sockaddr_nl nladdr = {
    .nl_family = AF_NETLINK
  };
  struct iovec iov = {
    .iov_base = buf,
    .iov_len = sizeof (buf)
  };
  int flags = 0;

  for (;;)
    {
      struct msghdr msg = {
	.msg_name = (void *) &nladdr,
	.msg_namelen = sizeof (nladdr),
	.msg_iov = &iov,
	.msg_iovlen = 1
      };

      ssize_t ret = recvmsg (fd, &msg, flags);
      if (ret < 0)
	{
	  if (errno == EINTR)
	    continue;

	  perror ("recvmsg");
	  return -1;
	}
      if (ret == 0)
	return 0;

      const struct nlmsghdr *h = (struct nlmsghdr *) buf;
      if (!NLMSG_OK (h, ret))
	{
	  fputs ("!NLMSG_OK\n", stderr);
	  return -1;
	}

      for (; NLMSG_OK (h, ret); h = NLMSG_NEXT (h, ret))
	{
	  if (h->nlmsg_type == NLMSG_DONE)
	    return 0;
	  if (h->nlmsg_type == NLMSG_ERROR)
	    {
	      const struct nlmsgerr *err = NLMSG_DATA (h);

	      if (h->nlmsg_len < NLMSG_LENGTH (sizeof (*err)))
		{
		  fputs ("NLMSG_ERROR\n", stderr);
		}
	      else
		{
		  errno = -err->error;
		  perror ("NLMSG_ERROR");
		}
	      return -1;
	    }

	  if (h->nlmsg_type != SOCK_DIAG_BY_FAMILY)
	    {
	      fprintf (stderr, "unexpected nlmsg_type %u\n",
		       (unsigned) h->nlmsg_type);
	      return -1;
	    }

	  if (print_diag (NLMSG_DATA (h), h->nlmsg_len))
	    return -1;
	}
    }
}

int
main (void)
{
  int fd = socket (AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);
  if (fd < 0)
    {
      perror ("socket");
      return 1;
    }

  int ret = send_query (fd) || receive_responses (fd);
  close (fd);
  return ret;
}
