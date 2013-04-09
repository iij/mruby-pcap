/*
** pcap.c - Pcap module
**
** See Copyright Notice in mruby.h
*/

#include "mruby.h"
#include "mruby/data.h"
#include "mruby/string.h"
#include "mruby/array.h"
#include "mruby/class.h"
#include <string.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>


#define DEFAULT_SNAPLEN	68
#define DEFAULT_PROMISC	1
#define DEFAULT_TO_MS	1000

struct capture_object {
  pcap_t	*pcap;
  bpf_u_int32	netmask;
  int		dl_type;
  mrb_state	*mrb;
  mrb_value	cap_data;
};

static void free_capture(mrb_state *, void *);

static char pcap_errbuf[PCAP_ERRBUF_SIZE];
static const mrb_data_type mrb_pcap_type = { "PCAP", free_capture };

static mrb_value
pcap_s_lookupdev(mrb_state *mrb, mrb_value self)
{
  char *dev;

  dev = pcap_lookupdev(pcap_errbuf);
  if (dev == NULL) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "%s", pcap_errbuf);
  }

  return mrb_str_new(mrb, dev, strlen(dev));
}

static mrb_value
pcap_s_lookupnet(mrb_state *mrb, mrb_value self)
{
  mrb_value rval;
  char *cdev;
  char buf_str[INET_ADDRSTRLEN+1];
  bpf_u_int32 net, mask;

  mrb_get_args(mrb, "s", &cdev);
  if (pcap_lookupnet(cdev, &net, &mask, pcap_errbuf) == -1)
    mrb_raisef(mrb, E_RUNTIME_ERROR, "%s", pcap_errbuf);

  rval = mrb_ary_new(mrb);
  inet_ntop(AF_INET, &net, buf_str, sizeof(buf_str));
  mrb_ary_push(mrb, rval, mrb_str_new(mrb, buf_str, strlen(buf_str)));
  inet_ntop(AF_INET, &mask, buf_str, sizeof(buf_str));
  mrb_ary_push(mrb, rval, mrb_str_new(mrb, buf_str, strlen(buf_str)));

  return rval;
}

static void
free_capture(mrb_state *mrb, void *ptr)
{
  struct capture_object *cap = ptr;

  if (cap->pcap != NULL) {
    pcap_close(cap->pcap);
    cap->pcap = NULL;
  }
 free(cap);
}

static mrb_value
capture_open_live(mrb_state *mrb, mrb_value self)
{
  mrb_int snaplen, to_ms;
  mrb_value dev, promisc;
  pcap_t *pcap;
  char *cdev;
  int cpromisc;
  int nargs;
  struct capture_object *cap;
  bpf_u_int32 net, netmask;

  nargs = mrb_get_args(mrb, "S|ioi", &dev, &snaplen, &promisc, &to_ms);
  cdev = mrb_str_to_cstr(mrb, dev);
  if (nargs > 2 &&
      mrb_type(promisc) != MRB_TT_TRUE &&
      mrb_type(promisc) != MRB_TT_FALSE)
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid parameter");

  if (nargs < 2)
    snaplen = DEFAULT_SNAPLEN;
  if (snaplen < 0)
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid snaplen");

  if (nargs < 3)
    cpromisc = DEFAULT_PROMISC;
  else {
    if (mrb_type(promisc) == MRB_TT_TRUE)
      cpromisc = 1;
    else
      cpromisc = 0;
  }

  if (nargs < 4)
    to_ms = DEFAULT_TO_MS;

  /* invoke pcap_open_live */
  pcap = pcap_open_live(cdev, snaplen, cpromisc, to_ms, pcap_errbuf);
  if (pcap == NULL)
    mrb_raisef(mrb, E_RUNTIME_ERROR, "%s", pcap_errbuf);
  if (pcap_lookupnet(cdev, &net, &netmask, pcap_errbuf) == -1)
    netmask = 0;

  cap = (struct capture_object *)mrb_malloc(mrb, sizeof(*cap));

  cap->pcap = pcap;
  cap->netmask = netmask;
  cap->dl_type = pcap_datalink(pcap);

  return mrb_obj_value(Data_Wrap_Struct(mrb, mrb_class_ptr(self),
					&mrb_pcap_type, (void*)cap));
}

static void
handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *data)
{
  mrb_value rval;
  char timestamp[32];
  struct capture_object *cap;
  char *data_p = (char *)data;

  cap = (struct capture_object *)user;

  rval = mrb_ary_new(cap->mrb);
  timestamp[0] = '\0';
  snprintf(timestamp, sizeof(timestamp)-1, "%ld.%ld",
	   (long)pkthdr->ts.tv_sec, (long)pkthdr->ts.tv_usec);
  mrb_ary_push(cap->mrb, rval,
	       mrb_str_new(cap->mrb, timestamp, strlen(timestamp)));
  mrb_ary_push(cap->mrb, rval, mrb_fixnum_value(pkthdr->caplen));
  mrb_ary_push(cap->mrb, rval, mrb_fixnum_value(pkthdr->len));
  mrb_ary_push(cap->mrb, rval, mrb_str_new(cap->mrb, data_p, pkthdr->caplen));
  cap->cap_data = rval;

  return;
}

static mrb_value
capture(mrb_state *mrb, mrb_value self)
{
  struct capture_object *cap;
  int nfd;

  cap = (struct capture_object *)mrb_get_datatype(mrb, self, &mrb_pcap_type);
  cap->mrb = mrb;

  if (pcap_file(cap->pcap) != NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "pcap file not supported");
  } else {
    int fd = pcap_fileno(cap->pcap);
    fd_set rset;

    FD_ZERO(&rset);
    do {
      FD_SET(fd, &rset);
      nfd = select(fd+1, &rset, NULL, NULL, NULL);
      if (nfd != 0) {
	pcap_dispatch(cap->pcap, 1, handler, (u_char *)cap);
	break;
      } else {
	continue;
      }
    } while (1);
  }

  return cap->cap_data;
}

static mrb_value
capture_setfilter(mrb_state *mrb, mrb_value self)
{
  struct capture_object *cap;
  struct bpf_program program;
  mrb_value optimize;
  mrb_value filter;
  char *filter_str;
  int nargs;

  nargs = mrb_get_args(mrb, "S|o", &filter_str, &optimize);
  if (nargs != 2)
    optimize = mrb_true_value();
  if (mrb_type(optimize) != MRB_TT_TRUE &&
      mrb_type(optimize) != MRB_TT_FALSE) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid parameter");
  }

  cap = (struct capture_object *)mrb_get_datatype(mrb, self, &mrb_pcap_type);

  filter_str = mrb_str_to_cstr(mrb, filter);
  if (pcap_compile(cap->pcap, &program, filter_str,
		   mrb_type(optimize) == MRB_TT_TRUE ? 1 : 0,
		   cap->netmask) < 0)
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "setfilter: %s", pcap_geterr(cap->pcap));
  if (pcap_setfilter(cap->pcap, &program) < 0)
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "setfilter: %s", pcap_geterr(cap->pcap));

  return mrb_nil_value();
}

static mrb_value
capture_datalink(mrb_state *mrb, mrb_value self)
{
  struct capture_object *cap;

  cap = (struct capture_object *)mrb_get_datatype(mrb, self, &mrb_pcap_type);
  return mrb_fixnum_value(pcap_datalink(cap->pcap));
}

static mrb_value
capture_close(mrb_state *mrb, mrb_value self)
{
  struct capture_object *cap;

  cap = (struct capture_object *)mrb_get_datatype(mrb, self, &mrb_pcap_type);
  pcap_close(cap->pcap);
  cap->pcap = NULL;

  return mrb_nil_value();
}

void
mrb_mruby_pcap_gem_init(mrb_state *mrb)
{
  struct RClass *pcap, *capt;

  pcap = mrb_define_module(mrb, "Pcap");

  mrb_define_module_function(mrb, pcap, "lookupdev", pcap_s_lookupdev,
			     ARGS_NONE());
  mrb_define_module_function(mrb, pcap, "lookupnet", pcap_s_lookupnet,
			     ARGS_REQ(1));

  mrb_define_const(mrb, pcap, "DLT_NULL", mrb_fixnum_value(DLT_NULL));
  mrb_define_const(mrb, pcap, "DLT_EN10MB", mrb_fixnum_value(DLT_EN10MB));
  mrb_define_const(mrb, pcap, "DLT_PPP", mrb_fixnum_value(DLT_PPP));
#ifdef DLT_RAW
  mrb_define_const(mrb, pcap, "DLT_RAW", mrb_fixnum_value(DLT_RAW));
#endif

  capt = mrb_define_class_under(mrb, pcap, "Capture", mrb->object_class);
  mrb_define_singleton_method(mrb, (struct RObject*)capt, "open_live",
  			      capture_open_live, ARGS_ANY());
  mrb_define_method(mrb, capt, "capture", capture, ARGS_NONE());
  mrb_define_method(mrb, capt, "setfilter", capture_setfilter, ARGS_ANY());
  mrb_define_method(mrb, capt, "datalink", capture_datalink, ARGS_NONE());
  mrb_define_method(mrb, capt, "close", capture_close, ARGS_NONE());
}

void
mrb_mruby_pcap_gem_final(mrb_state *mrb)
{
}
