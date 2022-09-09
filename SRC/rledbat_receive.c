/* Intercepts incoming packets to implement rledbat behavior.
(https://datatracker.ietf.org/doc/html/draft-irtf-iccrg-rledbat-02).

Communicates (via exported variables) with module processing egressing packets, 
e.g., 'write module'

Can only manage a single TCP connection. The connection to which rledbat applies is 
the one with local port RLEDBAT_WATCH_PORT. 
The module must be reloaded when the connection finishes to clean the state for 
the execution with a different TCP connection.

Two flavors implemented, with different target for queuing delay
- draft-irtf-iccrg-rledbat-02, as LEDBAT++, target=60ms
- RLEDBAT2, target = min(60ms, rtt_base)
To select the second, uncomment (or define) RLEDBAT_2

Tested with Ubuntu Linux 3.13.0-24-generic

    LICENSE: GPL

    Based on Sam Protsenko's code for printing data from TCP packets 
    (https://stackoverflow.com/questions/29553990/print-tcp-packet-data)
    Added rledbat support by Anna Mandalari, Alberto Garcia and David Verde (U. Carlos III de Madrid).
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/random.h>
#include <linux/time.h>
#include <linux/limits.h>

#include <linux/string.h>

////
//// optional behaviors
////
// No selection is default rledbat behavior (as by draft-irtf-iccrg-rledbat-02)
// If RLEDBAT2 is defined, then target is min(TARGET, rtt_base)
// #define RLEDBAT2 "RLEDBAT2"

#define NANOS_PER_MS 1000000LL
#define MAX_LONG_LONG 9223372036854775803LL

#define MAX_WINDOW 65535

// should be the same as for the module rewriting outgoing packets, 
// kernel/xt_TWIN.c
#define mss 1448
// this is the minimum value (bytes) the window may have in any reduction
// (either periodic or delay-triggered)
// 2* mss
#define MIN_REDUCTION_BYTES 2896
// will be set to MIN_REDUCTION_BYTES / window_scale:
static uint16_t minimum_window = 0;

#define INIT_WINDOW 1*mss

// Remote port of connections for which rledbat is applied
// Only one connection using this port should be started
// I.e., rledbat is applied to connections with remote port 49000
// To change the port, must also modify install_rledbat.sh
#define RLEDBAT_WATCH_PORT 49000

// rledbat target
#define TARGET 60LL*NANOS_PER_MS
// Data specific for RLEDBAT2
#ifdef RLEDBAT2
// replaces TARGET in some computations
static long long target2 = 0;
#endif // RLEDBAT2

// mus be changed also in xt_TWIN.c, if needed
#define MAX_COUNT_RTT 10000

//gain is defined as 1/min(gain_constant,ceil((2*target)/base))
#define GAIN_CONSTANT 16
// Constant for multiplicative decrease computation
#define CONSTANT_MULTIPLIER 1
#define CONSTANT_DIVIDER 1

// Variables that must keep state between the executions of hook function
// (activated per packet)

// To hook module
static struct nf_hook_ops nfho;


// effective reception window
static unsigned long long rcwnd_ok = INIT_WINDOW;
// Can be used for debug. The write module imports it but doesn't use it
static unsigned long long rcwnd_ok_before = INIT_WINDOW;
static long last_seq = 0;
// rcwnd_ok, rcwnd_ok_before and last_seq are exported to the write module

static long tsval_rtt = 0;

// xt_TWIN (processing outgoing packets) module uses it, need to update the write module first
static unsigned int flag_dup_ack = 0;


//values needed to compute the queueing delay
static long long queue_delay = 0;
static long long rtt = MAX_LONG_LONG;
static long long rtt_min = MAX_LONG_LONG;


// to know if we are reducing the window
static int reduction = 0;

// _time values are ns
// time to maintain the window
static long long keep_window_time = 0;

// periodic reduction 
static unsigned long long periodic_reduction_time=0;
static unsigned long long begin_periodic_reduction_time=0;
static unsigned long long end_periodic_reduction_time=0;

// do not decrease until this time
static unsigned long long next_decrease_time=0;

// to allow computing RTT information
static long tsval_rtt_array[MAX_COUNT_RTT];
static long time_rtt_array[MAX_COUNT_RTT];
// ts_val_array and time_rtt_array are exported to the write module

static long tsval_rtt_old = 0;

//sequence number of the previous packet, to detect retransmissions
static long last_seq_old=0;
static int is_retransmission=0; 

static long tsecr = 0;
static long tsecr_already_checked = 0;

// number bytes acked
static unsigned int acked = 0;
// number of bytes the window must be reduced
static signed long long rcwnd_scale = 0;

static unsigned long to_increase_CA;

//slow start threshold
static unsigned long long ssthresh=MAX_WINDOW;

// first slow start is different, we need to control that case
static int is_first_ss=1;
// to disable temporarily slow start
static int is_ss_allowed=1;
// to know if we have to freeze the window after a periodic reduction
static int freeze_ended=1;
// indicates if a retransmission occurred close to this time (only react with the first)
static int recent_retransmission=0;

//used to know if periodic_reduction_time is from the previous or the next one
static int periodic_reduction_scheduled=0;

// last queuing delay values to compute minimum
#define LAST_QDS 10
// stores up to last 20 qds values, can be easily changed with LAST_QDS
static long long last_qd_values[20] = {MAX_LONG_LONG, MAX_LONG_LONG, MAX_LONG_LONG, MAX_LONG_LONG, MAX_LONG_LONG, MAX_LONG_LONG, MAX_LONG_LONG, MAX_LONG_LONG,
MAX_LONG_LONG, MAX_LONG_LONG, MAX_LONG_LONG, MAX_LONG_LONG, MAX_LONG_LONG, MAX_LONG_LONG, MAX_LONG_LONG, MAX_LONG_LONG,
MAX_LONG_LONG, MAX_LONG_LONG, MAX_LONG_LONG, MAX_LONG_LONG
};
// current pointer to last_qd_values
static long long qd_values_pointer = 0;

// access to the available number of bytes for the (TCP) receiver buffer 
extern int sysctl_tcp_rmem[3];
extern u32 sysctl_rmem_max;

//scaling factor (exponent)
static u16 rcv_wscale=0;
//scaling factor (bytes)
static int window_scale=1;
static int increase_bytes=0;

//number of packet
static int packet_number=0;


////
////    DEBUG facilities
// state contains a 'string' describing the processing being made for the received packet.
// At the end of rledbat_incoming_hook_func, i.e., the function that is called when a 
// packed is received, this string contains the processing being made by rledbat.
// This information is only used for debugging, it does not keep any state for the 
// processing of other packets (state is kept in the variables declared above).
// A pr_debug call can be issued to dump this (and more state) to syslog, if
// -DDEBUG is enabled in the compilation
// The state values are a good way to understand what is happening in the code.
//
static char state[15] = "undef"; // initialize, must be overwritten with first packet
// other values for state (describing the effect after processing the received packet)
//
// "slow" - window was grown according to slow start
// "slow1_end" - slow start for the first time reached 3/4 of the TARGET (60ms) 
//          so this packet made slow start finishing; go to Congestion Avoidance mode.
// "slow1_fix" - slow start for the first time reached ssthresh (normal condition for ss
//          to stop), but not 3/4 of the TARGET. This packet made slow start finishing, 
//          go to Congestion Avoidance mode
//
// "CA" - window grew according to congestion avoidance mode 
// "decrease" - this packet exceeded the delay condition, compute window to reduce in next
//          packets
// "decr2big" - as decrease, but the amount to reduce is too high (more than half window)
// "declessWS" - as decrease, but the amount to reduce is too small, less than the size of 1 
//          window unit. Anyway, decrease one window unit
// "min_window" - as decrease, but the amount to reduce would result in a final window of 
//          less than min window, so cap the value to min_window
// "growb4red" - as decrease, but the result of the window formula is to grow, not decrease.
//          This may happen for small differences between queuing delay and target
//
// "reducing" - previous packets resulting in a window reduction request, window is reduced 
//          with the acked data for this packet
// "waitrtt2dec" - this packet is received when a reduction operation has completed. However, 
//          we want to wait an RTT until the queuing delay is computed either to grow or decrease
//          further
//
// "retrans" - this packet was a retransmission, reduce window to half, activate slow start
//          for later grow
//
// "perio_red" - when processing this packet, we realize its time for a periodic_reduction 
// "perio_red+retr" - a retransmission was detected when also scheduling a periodic reduction.
// "freezing" - the reduction of a periodic slowdown has just finished with this packet. 
//          Ensure that no window update occur in the next 2*RTT period
// "frozen" - waiting for the 2*RTT period after a periodic slowdown to complete.
// "freezing+retrans" - as freezing, but the packet was a retrans, updated slow start threshold
//          for next slow start
// "frozen+retrans" - as frozen, but the packet was a retrans, updated slow start threshold
//          for next slow start


// Receives last queuing delay (qd) measured.
// Stores the last qd measured for future use
// Returns minimum of the last LAST_QDS values (including last_qd) and last_qd
static long long qd_min_lastN(long long last_qd)
{
    int i;
    long long qd_min;

    if (LAST_QDS == 1)
    {
        return last_qd;
    }

    last_qd_values[qd_values_pointer % LAST_QDS] = last_qd;
    qd_values_pointer++;

    qd_min = last_qd_values[0];
    for (i = 1; i < LAST_QDS; i++)
    {
        if (last_qd_values[i] < qd_min)
        {
            qd_min = last_qd_values[i];
        }
    }
    return qd_min;
}

// Get timestamp echo reply (TSecr) from the received packet
static void get_TSecr(struct tcphdr *tcph){
	uint8_t size;
    uint8_t *end;
    uint8_t *p;
	
	//get the TSecr from the received packet
    // must go to the address in which the ts val is, reading previous options
    p = (uint8_t *)tcph + 20; // or sizeof (struct tcphdr)
        // end -> where data start
    end = (uint8_t *)tcph + tcph->doff * 4;
    while (p < end)
    {
        uint8_t kind = *p++;
        if (kind == 0)
        {
            break;
        }
        if (kind == 1)
        {
            // No-op option with no length.
            continue;
        }
        size = *p++;
	
        // ts val is option number 8
        if (kind == 8)
        {
            tsecr = (long) ntohl(*(uint32_t *)(p+4));
        }
        p += (size - 2);
    }
}

static int getSyn(struct tcphdr *tcph){
	return tcph->syn;
}

// Is there WS window scale option?
static int isWSoption(struct tcphdr *tcph){

	uint8_t size;
    uint8_t *end;
    uint8_t *p;
	
	//get the TSval  and tsecr from the received packet
    // must go to the address in which the ts val is, reading previous options
    p = (uint8_t *)tcph + 20; // or sizeof (struct tcphdr)
        // end -> where data start
    end = (uint8_t *)tcph + tcph->doff * 4;
    while (p < end){
        uint8_t kind = *p++;
        if (kind == 0)
        {
            break;
        }
        if (kind == 1)
        {
            // No-op option with no length.
            continue;
        }
        size = *p++;
	
        if(kind == 3) return 1;
        p += (size - 2);
    }
	
	return 0;
}


// updates global variables rtt and rtt_min
// only checks for each tsecr once, for the first packet received
// returns rtt_min if there was no previous value
static void  min_rtt(long tsecr,unsigned long long reception_time){
	int i;

    for (i = 0; i < MAX_COUNT_RTT; i++){
        if (tsval_rtt_array[i] == tsecr){
            // // Compute rtt for every packet, even if it has the same tsecr!
            // // rtts grow for packets being received with the same tsecr
            // rtt = reception_time - time_rtt_array[i];
            // if (rtt < rtt_min){
            //         rtt_min = rtt;
            //     }
            // return;

            if (tsecr != tsecr_already_checked){
                
                rtt = reception_time - time_rtt_array[i];
                tsecr_already_checked = tsecr;
                
                if (rtt < rtt_min){
                    rtt_min = rtt;
                }
                return;
            }
            else { // do not keep searching
                // do not change neither rtt nor rtt_min
                pr_debug("receive_REPEATED");
                return; 
            }

        }
    }

    // value was not in array (e.g., because all values were cleared due to a retransmission)
    // rtt_min does not change
    // set rtt to rtt_min to indicate this case    
	rtt = rtt_min;

    pr_debug("NOT_FOUND: rtt: %lld, tsecr: %ld, tsecr_already_checked %ld, iterations %d\n", rtt, tsecr, tsecr_already_checked, i);
    return;
}


static void clear_rtt_table(void) {
    int i;

    for (i=0; i<MAX_COUNT_RTT; i++) {
        tsval_rtt_array[i] = 0;
        time_rtt_array[i] = 0;
    }

    tsval_rtt_old = 0;
    pr_debug("RTT table CLEARED ");
}

//auxiliary function to calculate ceil 
static unsigned long long ceil_rledbat(unsigned long long num, unsigned long long den){
    if(num>den){
        unsigned long long rest= num%den;
        unsigned long long lacking= den - rest;
        
        return (unsigned long long) (num +lacking)/den;
    }
    else { 
      return 1;
    }
}

// gain DIVIDER (the divider of GAIN=1/gain)
static unsigned long long gain(long long rtt_min){
	unsigned int gain_aux=0;
	
    // according to LEDBAT++ draft
    gain_aux=ceil_rledbat(2*TARGET,rtt_min);

	if (GAIN_CONSTANT>gain_aux)
		return gain_aux;
	else return GAIN_CONSTANT;
}


static long long bytes_to_decrease_rledbat(unsigned long long window,unsigned long long scale, long long queue_delay,long long rtt_min){
	// standard decrease is
	//W += max( (GAIN - Constant * W * (delay/target - 1)), -W/2) )
    // (note RLEDBAT2 modifies this)
    // As we cannot use floating point operations in the kernel, 
	// we transform this equation so we dont use doubles assuming gain will always be 1/x x>0
	// (Constant_divider*Target - gain_divider*constant_num*window*(delay-target))/(gain_divider*constant_divider*target)
    unsigned long long window_size=window*scale;
	long long diff=0;
	unsigned long long gain_val=0;
	long long aux=0;
	long long num=0;
	long long den=0;
	long long decrease=0;
	long long window_half=0;
    #ifdef RLEDBAT2
        diff = queue_delay - target2;
    #else
        diff=queue_delay-TARGET;
    #endif

	gain_val=gain(rtt_min);
	aux=gain_val*CONSTANT_MULTIPLIER*window_size;

    #ifdef RLEDBAT2
        num=CONSTANT_DIVIDER* target2 -aux*diff;
	    den=gain_val*CONSTANT_DIVIDER* target2;
    #else
	    num=CONSTANT_DIVIDER*TARGET-aux*diff;
	    den=gain_val*CONSTANT_DIVIDER*TARGET;
    #endif

	decrease=num/den;
	window_half=-1*(window_size/2);

    pr_debug("decrease_rledbat aux:%lld num:%lld, den:%lld window_size:%llu gain:%llu window_half:%lld \n", aux, num, den, window_size, gain_val, window_half);
	if (decrease>=window_half){ 
      return decrease;
    }
	else{
        return window_half;
    }
}

// This is the most important function, the
//function that will be executed with each packet received
static unsigned int rledbat_incoming_hook_func(const struct nf_hook_ops *ops,
                                   struct sk_buff *skb,
                                   const struct net_device *in,
                                   const struct net_device *out,
                                   int (*okfn)(struct sk_buff *)){

    unsigned long denominator_CA;

	struct iphdr *iph;        /* IPv4 header */
    struct tcphdr *tcph;      /* TCP header */
    u16 sport, dport;         /* Source and destination ports */
    u32 saddr, daddr;         /* Source and destination addresses */
    //unsigned char *user_data; /* TCP data begin pointer */
    //unsigned char *tail;      /* TCP data end pointer */
    //unsigned char *it;        /* TCP data iterator */

    u32 space;
    
	//time when the packet was received
    unsigned long long reception_time;

    //used to calculate reception time
    struct timeval t;
    struct tm broken;

    /* Network packet is empty, seems like some problem occurred. Skip it */
    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb); /* get IP header */

    /* Skip if  it is not a TCP packet */
    if (iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    tcph = tcp_hdr(skb); /* get TCP header */

    /* Convert network endianness to host endianness */
    saddr = ntohl(iph->saddr);
    daddr = ntohl(iph->daddr);
    sport = ntohs(tcph->source);
    dport = ntohs(tcph->dest);
    last_seq = (u32)ntohl(tcph->seq);

    /* Watch only for the selected port, local port (destination for incoming packet) */
    if (dport != RLEDBAT_WATCH_PORT)
        return NF_ACCEPT;

	// get the time when we received the packet
    do_gettimeofday(&t);
    time_to_tm(t.tv_sec, 0, &broken);

	 reception_time =
        ((unsigned long long)(t.tv_sec) * 1e6 +
         (unsigned long long)(t.tv_usec)) * 1000;
	
	//increase packet number
	packet_number++;
	//find tsecr 
	get_TSecr(tcph);
	
    //check if this packet is a retransmission
	if((last_seq<=last_seq_old)&& (tsval_rtt>=tsval_rtt_old))
		is_retransmission=1;
	else is_retransmission=0;
	last_seq_old=last_seq;
    
    if (tsval_rtt != tsval_rtt_old){
        tsval_rtt_old = tsval_rtt; }

	//update global variables rtt and rtt_min
	min_rtt(tsecr,reception_time);

	//read #bytes received
    acked = ntohs(iph->tot_len) - (tcph->doff * 4) - (iph->ihl * 4);

    queue_delay = rtt - rtt_min; 
    #ifdef RLEDBAT2
        // compute RLEDBAT2-specific target2 variable
        if (rtt_min < TARGET) {
            target2 = rtt_min;
        }
        else {
            target2 = TARGET;    
        }
    #endif

    // Take the min of the last LAST_QDS values
    queue_delay = qd_min_lastN(queue_delay);


    // Next we consider all the cases relevant for rledbat behavior: first packet, 
    // there is a retransmission, qd is too high, periodic slowdown to measure rttmin, etc.


	// Check in the first packet (that should be a SYN) that there is an WS option included.
    // The value used is discarded, compute a new value according to the available memory. 
    // The value is exported to the module rewriting outgoing packets, so that it changes it for
    // all packets sent.
	if(1==packet_number){
		if(getSyn(tcph) && isWSoption(tcph)){
			int rest=0;
            int tcp_rmem=0;

			tcp_rmem=sysctl_tcp_rmem[2];
			space = max_t(u32, tcp_rmem, sysctl_rmem_max);
			while (space > 65535 && (rcv_wscale) < 14) {
			   space >>= 1;
			   (rcv_wscale)++;
			}
			window_scale=1<<rcv_wscale;
			//set window depending on scaling
			rcwnd_ok=INIT_WINDOW/window_scale;
			//rounding
			rest=INIT_WINDOW%window_scale;
			if(rest!=0){
				rcwnd_ok++;
			}
			// set minimum window depending on scaling
			rest=MIN_REDUCTION_BYTES%window_scale;
			minimum_window=MIN_REDUCTION_BYTES/window_scale;
			//rounding (ceil)
			if(rest!=0){
				minimum_window++;
			}
		}
        else {
            pr_debug("WARNING: first packet received is not a SYN, and it should!");
            return NF_ACCEPT;
        }
	}

	//see IF WE ARE REDUCING THE WINDOW
	if(reduction){ 
		/* we are within an RTT for which window is being reduced, do not change window,
        but try to reduce the amount of data previously decided (rcwnd_scale) */
        if (rcwnd_scale > 0){ /* adjust window with received packets */
  			//how much we have to reduce the window according to ws
  			int decrease_ws=0;
  			int rest=0;
  			if(acked >= rcwnd_scale){
                // we complete the reduction now
  				decrease_ws=rcwnd_scale/window_scale;
  				rcwnd_ok-=decrease_ws;
  				reduction=0;
                recent_retransmission=0;
  				//rounding
  				rest=rcwnd_scale%window_scale;
  				if((rest>0)&&(rcwnd_ok-1>=minimum_window)){
                    rcwnd_ok--;
                }
  				rcwnd_scale=0;	
  			}
  			else{
  				decrease_ws=acked/window_scale;
                rest=acked%window_scale;
                if((rest>0)&&(rcwnd_ok-1>=minimum_window)){
                    decrease_ws++;            
                }

                if(rcwnd_ok-decrease_ws>=minimum_window){
                    rcwnd_ok-=decrease_ws;
  				    rcwnd_scale-=decrease_ws*window_scale;
                }
                else {
                    rcwnd_ok=minimum_window;
                }
  				
                if((rcwnd_scale<=0)||(rcwnd_ok==minimum_window)){
                    reduction=0;
                    rcwnd_scale=0;
                    recent_retransmission=0;
                }  				
  			}
  		    strncpy(state, "reducing", 9);
		}
		else if(rcwnd_scale==0){
            // Some times the window to reduce is so small that is is 0. A reduction was
            // requested, but the amount was 0.
			reduction=0;
			strncpy(state, "reducing",9);
		}
		if(is_retransmission && !recent_retransmission){
            recent_retransmission=1;
			//if there is a loss and we are in a periodic reduction update ssthresh to rcwnd_ok/2
			if(!periodic_reduction_scheduled&&!freeze_ended){
				unsigned long long ssthresh_aux=rcwnd_ok/2;
				if(ssthresh_aux>=minimum_window)
					ssthresh=ssthresh_aux;
				else ssthresh=minimum_window;
				strncpy(state, "perio_red+retr",15);
			}
			//we drop to minimum and grow in ss
			else {
				unsigned long long ssthresh_aux=rcwnd_ok/2;
				rcwnd_scale = (rcwnd_ok - minimum_window)*window_scale;

				if(ssthresh_aux>=minimum_window)
					ssthresh=ssthresh_aux;
                else ssthresh=minimum_window;

                reduction=1;
                is_ss_allowed=1;
                strncpy(state, "retrans", 8);

                // rtt values for packets already received do not have any meaning
                clear_rtt_table();
                rtt = rtt_min;
			}
		}
	}

	//SEE IF HE HAVE TO MAINTAIN THE WINDOW
	else if(reception_time<keep_window_time){
			//Do nothing
			strncpy(state, "frozen", 7);
			if(is_retransmission){
				unsigned long long ssthresh_aux=rcwnd_ok/2;
				if(ssthresh_aux>=minimum_window)
					ssthresh=ssthresh_aux;
				else ssthresh=minimum_window;
				strncpy(state, "frozen+retrans",15);
			}
	}
	//CHANGE THE WINDOW
	else{
		//See if we have just done a periodic slowdown to freeze the window 
		if(!freeze_ended){
			keep_window_time=reception_time +2*rtt;
			strncpy(state, "freezing", 9);
			freeze_ended=1;
			if(is_retransmission){
				unsigned long long ssthresh_aux=rcwnd_ok/2;
				if(ssthresh_aux>=minimum_window)
					ssthresh=ssthresh_aux;
				else ssthresh=minimum_window;
				strncpy(state, "freeze+retrans",15);
			}
		}
		//See if we have to do a periodic slowdown
		else if((!is_first_ss)&&(reception_time> periodic_reduction_time)&&periodic_reduction_scheduled){
			rcwnd_scale = (rcwnd_ok - minimum_window)*window_scale;
            // TCP's receive window may force rcwn_ok to be 1 MSS. Do not reduce. 
            if (rcwnd_scale < 0) {
                rcwnd_scale = 0;
            }
			reduction=1;
			begin_periodic_reduction_time=reception_time;
			//set ssthresh to th current rcwnd
			ssthresh=rcwnd_ok;
			strncpy(state, "perio_red", 10);
			freeze_ended=0;
			is_ss_allowed=1;
			periodic_reduction_scheduled=0;
			if(is_retransmission){
				unsigned long long ssthresh_aux=rcwnd_ok/2;
				if(ssthresh_aux>=minimum_window)
					ssthresh=ssthresh_aux;
				else ssthresh=minimum_window;
				strncpy(state, "perio_red+retr",15);
			}
		}
		//Se if there has been a packet loss
		else if(is_retransmission){
			unsigned long long ssthresh_aux=rcwnd_ok/2;

            recent_retransmission=1;

			if(ssthresh_aux>=minimum_window)
			 	ssthresh=ssthresh_aux;
            else ssthresh=minimum_window;


            // Option 1: reduce to minimum window value
		    // rcwnd_scale = (rcwnd_ok - minimum_window)*window_scale;

            // option 2: reduce current window to half
            rcwnd_scale = (rcwnd_ok - ssthresh) * window_scale;

			reduction=1;
            is_ss_allowed=1;
			strncpy(state, "retrans", 8);

      
            //we have to schedule first periodic reduction if the loss ocurred while first slow start
            if(is_first_ss){
                is_first_ss=0;			
				//set first reduction
				periodic_reduction_time=reception_time+2*rtt;
				periodic_reduction_scheduled=1;
          
            }

            // rtt values for packets already received do not have any meaning
            clear_rtt_table();

		}
		//See if we have to decrease the window 
    #ifdef RLEDBAT2
        else if((queue_delay>target2)&&((!is_first_ss)||(periodic_reduction_scheduled))){
    #else
        // regular rledbat
        else if((queue_delay>TARGET)&&((!is_first_ss)||(periodic_reduction_scheduled))){
    #endif 
			if(reception_time>=next_decrease_time){
      			long long decrease_aux=0;
                is_ss_allowed=0;


                //standard decrease
                // rledbat and RLEDBAT2
                //W += max( (GAIN - Constant * W * (delay/target - 1)), -W/2) )
                decrease_aux=bytes_to_decrease_rledbat(rcwnd_ok,window_scale,queue_delay,rtt_min);

      			pr_debug("decrease returned: %lld, ventana:%lld window_scale:%d queue_delay:%lld rtt_min:%lld\n",decrease_aux, rcwnd_ok, window_scale, queue_delay, rtt_min);
      			//we can still increase,check if we decrease to set the reduction
      			if(decrease_aux<0){
      				if(rcwnd_ok>minimum_window){
      					rcwnd_scale+=-1*decrease_aux;
                        if(rcwnd_scale>=window_scale){                             
        					strncpy(state, "decrease", 9);
        					//assure window is at least 2mss if it is not, set the window to 2mss
        					if((rcwnd_ok-rcwnd_scale/window_scale)<minimum_window){
        						rcwnd_scale=(rcwnd_ok-minimum_window)*window_scale;
        						strncpy(state,"decr2big",9);
        					}
        					reduction=1;
        					next_decrease_time=reception_time+rtt;
                  
        				}
                        //not enough to reduce but we will ceil in the reduction, reducing 1 ws
                        else{
                            reduction=1;
                            next_decrease_time=reception_time+rtt;
                            strncpy(state, "declessWS", 10);
                        }
                    }
      				else{
      					reduction=0;
      					strncpy(state,"min_window",11);
      				}
                    // rtt values for packets already received do not have any meaning (as it will take an RTT to recover). 
                    // I may comment the following... and then some packets with larger RTT than the current one will be taken into account. But this is a problem at the beginning of the communication, so I clear it.
                    // 20220701 comment again
                    clear_rtt_table();
      			}
                //we still grow: note that the formula for bytes to decrease may result in positive values
                // if the queuing delay excedent is small 
      			else {
                    int increase_aux=0;
      				increase_bytes+=decrease_aux;
      				if(increase_bytes>=window_scale){
      					increase_aux=increase_bytes / window_scale;
      					rcwnd_ok+=increase_aux;
      					increase_bytes -= increase_aux*window_scale;	
                
      				}
      				strncpy(state, "growb4red", 10);
      			} 
    			//there's a case when we haven't scheduled a periodic_reduction & we are over TARGET so we have to check if there's one scheduled
    			if(reception_time>periodic_reduction_time){
    						
    				unsigned long long reduction_time;
    				
    
    				periodic_reduction_scheduled=1;
    
    				end_periodic_reduction_time=reception_time;
    				reduction_time=end_periodic_reduction_time-begin_periodic_reduction_time;
    				periodic_reduction_time=reception_time+9*reduction_time; 
    			} 
   			
    		}
    		else strncpy(state,"waitrtt2dec",12);
		}
		//See how we grow
		else{
            // Init, use slow start to grow
            #ifdef RLEDBAT2
            if(is_first_ss &&(queue_delay>(3*target2)/4)){
            #else
			if(is_first_ss &&(queue_delay>(3*TARGET)/4)){
            #endif
				int increase_aux=0;
				//we have completed the first slow start
				//set the ssthesh as the current window so the next time we grow in congestion avoidance
				ssthresh=rcwnd_ok;
				
				is_first_ss=0;
				is_ss_allowed=0;
				//set first reduction
				periodic_reduction_time=reception_time+2*rtt;
				periodic_reduction_scheduled=1;
				//congestion avoidance
                increase_bytes+= acked + ((acked/(rcwnd_ok*window_scale)))/gain(rtt_min);
        
				if(increase_bytes>=window_scale){
					increase_aux=increase_bytes / window_scale;
					rcwnd_ok+=increase_aux;
					increase_bytes -= increase_aux*window_scale;
          	
				}
				strncpy(state, "slow1_end", 10);	
			}
			else if(rcwnd_ok<ssthresh&&is_ss_allowed){
				
				int increase_aux=0;
				//rledbat slow start
				increase_bytes+=acked/gain(rtt_min);
				if(increase_bytes>=window_scale){
					increase_aux=increase_bytes / window_scale;
					rcwnd_ok+=increase_aux;
					increase_bytes -= increase_aux*window_scale;	
				}
				strncpy(state, "slow", 5);
			}
            //there is a case when the congestion window reaches its maximum and the delay is less than 3/4 target and that breaks the algorithm
            else if(rcwnd_ok>=ssthresh && is_first_ss){
                int increase_aux=0;
				//we have completed the first slow start because we cant grow more
				rcwnd_ok=ssthresh;
				is_first_ss=0;
				is_ss_allowed=0;
				//set first reduction
				periodic_reduction_time=reception_time+2*rtt;
				periodic_reduction_scheduled=1;
				//congestion avoidance
                increase_bytes+= acked + ((acked/(rcwnd_ok*window_scale)))/gain(rtt_min);
				if(increase_bytes>=window_scale){
					increase_aux=increase_bytes / window_scale;
					rcwnd_ok+=increase_aux;
					increase_bytes -= increase_aux*window_scale;
				}	
				strncpy(state, "slow1_fix", 10);
            }
            else{ 
				int increase_aux=0;
                // int to_increase=0;
                is_ss_allowed=0;
				//we need to calculate the next periodic reduction if there is not one scheduled
				if(reception_time>periodic_reduction_time){		
					unsigned long long reduction_time;
					periodic_reduction_scheduled=1;
					end_periodic_reduction_time=reception_time;
					reduction_time=end_periodic_reduction_time-begin_periodic_reduction_time;
					periodic_reduction_time=reception_time+9*reduction_time; 
				} 
				
				//congestion avoidance
                // to_increase=((acked*acked/(rcwnd_ok*window_scale)))/gain(rtt_min);
		        // acked * acked may not work as intended: with TSO/GSO and GRO, packets may be larger 
                // than 1 mss, and window may grow more than 1 mss per RTT
                to_increase_CA += acked * mss / gain(rtt_min);
                // (acked/(rcwnd_ok*window_scale))/gain(rtt_min);

                denominator_CA = (rcwnd_ok*window_scale);

                if (to_increase_CA  > denominator_CA)
                {
                    long int increase_CA_aux;
                    increase_CA_aux = to_increase_CA/ denominator_CA;
                    increase_bytes += increase_CA_aux;
                    to_increase_CA -=  increase_CA_aux*denominator_CA;
                }
        
                if(increase_bytes>=window_scale){
                        increase_aux=increase_bytes / window_scale;
                        rcwnd_ok+=increase_aux;
                        if(rcwnd_ok>MAX_WINDOW) rcwnd_ok=MAX_WINDOW;
                        increase_bytes -= increase_aux*window_scale;	
                }

                strncpy(state, "CA", 3);
            }

		}
	}

    // Do not change the first part, "read;reception_time;%lld;rtt;%lld;rtt_min;%lld;" as this format
    // is assumed for some data processing the output for further analysis 
	pr_debug("read;reception_time;%lld;rtt;%lld;rtt_min;%lld;window:%lld;thresh:%lld:state;%s;retrans:%d;to_reduce:%lld;reducing:%d;delay:%lld;TARGET:%lld;window_scale:%d;acked:%d;window_scale:%d;increase_bytes:%d;Gain:%lld;periodic_reduction_time:%lld\n",reception_time,rtt,rtt_min,rcwnd_ok,ssthresh,state,is_retransmission,rcwnd_scale,reduction,queue_delay,TARGET,rcv_wscale,acked,window_scale,increase_bytes,gain(rtt_min),periodic_reduction_time);

	return NF_ACCEPT;
}
	

static int __init rledbat_incoming_init(void){
    int res;
    nfho.hook = (nf_hookfn *)rledbat_incoming_hook_func; /* hook function */
    nfho.hooknum = NF_INET_PRE_ROUTING;      /* received packets */
    nfho.pf = PF_INET;                       /* IPv4 */
    nfho.priority = NF_IP_PRI_FIRST;         /* max hook priority */
    
    res = nf_register_hook(&nfho);
    if (res < 0) {
        pr_err("rledbat_receive: error in nf_register_hook()\n");
        return res;
    }

    pr_debug("rledbat_receive: loaded\n");

    #ifdef RLEDBAT2
    pr_debug("RLEDBAT2 active, target=min( minRTT, TARGET)\n");
    #endif // RLEDBAT2

    return 0;
}

static void __exit rledbat_incoming_exit(void){
    nf_unregister_hook(&nfho);
    pr_debug("rledbat_receive: unloaded\n");
}


EXPORT_SYMBOL(rcwnd_ok);
EXPORT_SYMBOL(rcwnd_ok_before);
EXPORT_SYMBOL(last_seq);

EXPORT_SYMBOL(tsval_rtt_array);
EXPORT_SYMBOL(time_rtt_array);

EXPORT_SYMBOL(flag_dup_ack);
EXPORT_SYMBOL(rcv_wscale);

module_init(rledbat_incoming_init);
module_exit(rledbat_incoming_exit);

MODULE_AUTHOR("Sam Protsenko, modified by Anna Mandalari, Alberto Garcia and David Verde, UC3M");
MODULE_DESCRIPTION("Originally, Module for printing TCP packet data, now rLEDBAT prototype");
MODULE_LICENSE("GPL");
