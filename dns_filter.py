'''
dns_filter.py: Copyright (C) 2014 Oliver Hitz <oliver@net-track.ch>

DNS filtering extension for the unbound DNS resolver. At start, it reads the
two files /etc/unbound/blacklist and /etc/unbound/whitelist, which contain a
host name on every line.

For every query sent to unbound, the extension checks if the name is in the
whitelist or in the blacklist. If it is in the whitelist, processing continues
as usual (i.e. unbound will resolve it). If it is in the blacklist, unbound
stops resolution and returns the IP address configured in intercept_address.

The whitelist and blacklist matching is done with every domain part of the
requested name. So, if www.domain.com is requested, the extension checks
whether www.domain.com, domain.com or .com is listed. 

Install and configure:

- copy dns_filter.py to /etc/unbound/dns_filter.py

- if needed, change intercept_address

- change unbound.conf as follows:

  server:
    module-config: "python validator iterator"
  python:
    python-script: "/etc/unbound/dns_filter.py"

- create /etc/unbound/blacklist and /etc/unbound/whitelist as you desire

- restart unbound

'''

blacklist = set()
whitelist = set()

intercept_address = "127.0.0.1"

whitelist_file = "/etc/unbound/whitelist"
blacklist_file = "/etc/unbound/blacklist"

def check_name(name, xlist):
    while True:
        if (name in xlist):
            return True
        elif (name.find('.') == -1):
            return False;
        else:
            name = name[name.find('.')+1:]

def read_list(name, xlist):
    try:
        with open(name, "r") as f:
            for line in f:
                xlist.add(line.rstrip())
    except IOError:
        log_info("dns_filter.py: Unable to open %s" % name)

def init(id, cfg):
    log_info("dns_filter.py: ")
    read_list(whitelist_file, whitelist)
    read_list(blacklist_file, blacklist)
    return True

def deinit(id):
    return True

def inform_super(id, qstate, superqstate, qdata):
    return True

def operate(id, event, qstate, qdata):

    if (event == MODULE_EVENT_NEW) or (event == MODULE_EVENT_PASS):

        # Check if whitelisted.
        name = qstate.qinfo.qname_str.rstrip('.')

#        log_info("dns_filter.py: Checking "+name)

        if (check_name(name, whitelist)):
#            log_info("dns_filter.py: "+name+" whitelisted")
            qstate.ext_state[id] = MODULE_WAIT_MODULE
            return True

        if (check_name(name, blacklist)):
#            log_info("dns_filter.py: "+name+" blacklisted")
            
            msg = DNSMessage(qstate.qinfo.qname_str, RR_TYPE_A, RR_CLASS_IN, PKT_QR | PKT_RA | PKT_AA)
            if (qstate.qinfo.qtype == RR_TYPE_A) or (qstate.qinfo.qtype == RR_TYPE_ANY):
                msg.answer.append("%s 10 IN A %s" % (qstate.qinfo.qname_str, intercept_address))


            if not msg.set_return_msg(qstate):
                qstate.ext_state[id] = MODULE_ERROR 
                return True

            qstate.return_msg.rep.security = 2

            qstate.return_rcode = RCODE_NOERROR
            qstate.ext_state[id] = MODULE_FINISHED 
            return True
        else:
            qstate.ext_state[id] = MODULE_WAIT_MODULE 
            return True

    if event == MODULE_EVENT_MODDONE:
#        log_info("pythonmod: iterator module done")
        qstate.ext_state[id] = MODULE_FINISHED 
        return True
      
    log_err("pythonmod: bad event")
    qstate.ext_state[id] = MODULE_ERROR
    return True
