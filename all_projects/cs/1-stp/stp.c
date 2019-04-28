#include "stp.h"

#include "base.h"
#include "ether.h"
#include "utils.h"
#include "types.h"
#include "packet.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <sys/types.h>
#include <unistd.h>

#include <pthread.h>
#include <signal.h>

stp_t *stp;

const u8 eth_stp_addr[] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x01 };

static bool stp_is_root_switch(stp_t *stp)
{
	return stp->designated_root == stp->switch_id;
}

static bool stp_port_is_designated(stp_port_t *p)
{
	return p->designated_switch == p->stp->switch_id &&
		p->designated_port == p->port_id;
}

static const char *stp_port_state(stp_port_t *p)
{
	if (p->stp->root_port && \
			p->port_id == p->stp->root_port->port_id)
		return "ROOT";
	else if (p->designated_switch == p->stp->switch_id &&
		p->designated_port == p->port_id)
		return "DESIGNATED";
	else
		return "ALTERNATE";
}

// Author: Siyuan Sheng
static void stp_port_send_config(stp_port_t *p)
{
	// TODO: send config packet from this port
	// fprintf(stdout, "TODO: send config packet.\n");
	
	// allocate space for the entire packet
	int packet_size = ETHER_HDR_SIZE + LLC_HDR_SIZE + sizeof(struct stp_config);
	char *packet = (char *) malloc(packet_size);
	if (packet == NULL) {
		log(ERROR, "malloc space for packet failed!");
	}
	memset(packet, 0, packet_size);

	// fill in ether_header
	struct ether_header ether_h;
	memcpy(ether_h.ether_dhost, eth_stp_addr, ETH_ALEN);
	memcpy(ether_h.ether_shost, p->iface->mac, ETH_ALEN);
	ether_h.ether_type = ETH_P_ARP;
	memcpy(packet, &ether_h, ETHER_HDR_SIZE);

	// fill in llc_header with blanks
	// have been done in memset, just skip
	
	// fill in stp config
	struct stp_config tmp_config;
	
	// fill in stp_header of tmp_config
	tmp_config.header.proto_id = STP_PROTOCOL_ID;
	tmp_config.header.version = STP_PROTOCOL_VERSION;
	tmp_config.header.msg_type = STP_TYPE_CONFIG;

	// fill in other fields of tmp_config
	tmp_config.flags = 0;
	tmp_config.root_id = p->designated_root;
	tmp_config.root_path_cost = p->designated_cost;
	tmp_config.switch_id = p->designated_switch;
	tmp_config.port_id = p->designated_port;
	tmp_config.msg_age = 0; // useless in this lab
	tmp_config.max_age = STP_MAX_AGE;
	tmp_config.hello_time = STP_HELLO_TIME;
	tmp_config.fwd_delay = STP_FWD_DELAY;

	memcpy(packet+ETHER_HDR_SIZE+LLC_HDR_SIZE, &tmp_config, sizeof(struct stp_config));

	// send packet
	iface_send_packet(p->iface, packet, packet_size);
}

static void stp_send_config(stp_t *stp)
{
	for (int i = 0; i < stp->nports; i++) {
		stp_port_t *p = &stp->ports[i];
		if (stp_port_is_designated(p)) {
			stp_port_send_config(p);
		}
	}
}

static void stp_handle_hello_timeout(void *arg)
{
	// log(DEBUG, "hello timer expired, now = %llx.", time_tick_now());

	stp_t *stp = arg;
	stp_send_config(stp);
	stp_start_timer(&stp->hello_timer, time_tick_now());
}

static void stp_port_init(stp_port_t *p)
{
	stp_t *stp = p->stp;

	p->designated_root = stp->designated_root;
	p->designated_switch = stp->switch_id;
	p->designated_port = p->port_id;
	p->designated_cost = stp->root_path_cost;
}

void *stp_timer_routine(void *arg)
{
	while (true) {
		long long int now = time_tick_now();

		pthread_mutex_lock(&stp->lock);

		stp_timer_run_once(now);

		pthread_mutex_unlock(&stp->lock);

		usleep(100);
	}

	return NULL;
}

// Author: Siyuan Sheng
// if config is better than p
static bool stp_is_better_config(stp_port_t *p, struct stp_config *config)
{
	if (config->root_id < p->designated_root) return true;
	else if (config->root_id > p->designated_root) return false;

	if (config->root_path_cost < p->designated_cost) return true;
	else if (config->root_path_cost > p->designated_cost) return false;

	if (config->switch_id < p->designated_switch) return true;
	else if (config->switch_id > p->designated_switch) return false;

	if (config->port_id < p->designated_port) return true;
	else if (config->port_id > p->designated_port) return false;

	return false;
}

// AuthorL Siyuan Sheng
// if p2 is better than p1
static bool stp_is_better_port(stp_port_t *p1, stp_port_t *p2)
{
	if (p2->designated_root < p1->designated_root) return true;
	else if (p2->designated_root > p1->designated_root) return false;

	if (p2->designated_cost < p1->designated_cost) return true;
	else if (p2->designated_cost > p1->designated_cost) return false;

	if (p2->designated_switch < p1->designated_switch) return true;
	else if (p2->designated_switch > p1->designated_switch) return false;

	if (p2->designated_port < p1->designated_port) return true;
	else if (p2->designated_port > p1->designated_port) return false;

	return false;
}

// Author: Siyuan Sheng
static void stp_port_update_config(stp_port_t *p, struct stp_config *config)
{
	p->designated_root = config->root_id;
	p->designated_cost = config->root_path_cost;

	// changed from dp into ap
	p->designated_switch = config->switch_id;
	p->designated_port = config->port_id;
}

// Author: Siyuan Sheng
static void stp_update_status(stp_t *stp)
{
	stp_port_t *best_p = NULL;
	for (int i = 0; i < stp->nports; i++)
	{
		stp_port_t *p = &stp->ports[i];
		if (stp_port_is_designated(p)) continue;
		if (best_p == NULL || stp_is_better_port(best_p, p)) best_p = p;
	}

	if (best_p == NULL) {
		stp->root_port = NULL;
		stp->designated_root = stp->switch_id;
		stp->root_path_cost = 0;
	}
	else {
		stp->root_port = best_p;
		stp->designated_root = best_p->designated_root;
		stp->root_path_cost = best_p->designated_cost + best_p->path_cost;
	}
}

// Author: Siyuan Sheng
static void stp_update_configs(stp_t *stp)
{
	// update ap configs
	for (int i = 0; i < stp->nports; i++)
	{
		stp_port_t *p = &stp->ports[i];
		if (stp_port_is_designated(p)) continue;
		if (p->port_id == stp->root_port->port_id) continue;

		stp_port_t tmp_dp;
		tmp_dp.designated_root = stp->designated_root;
		tmp_dp.designated_cost = stp->root_path_cost;
		tmp_dp.designated_switch = stp->switch_id;
		tmp_dp.designated_port = p->port_id;

		// change from ap into dp
		if (stp_is_better_port(p, &tmp_dp)) {
			p->designated_switch = stp->switch_id;
			p->designated_port = p->port_id;
		}
	}

	// update dp configs
	for (int i = 0; i < stp->nports; i++)	
	{
		stp_port_t *p = &stp->ports[i];
		if (stp_port_is_designated(p)) {
			p->designated_root = stp->designated_root;
			p->designated_cost = stp->root_path_cost;
		}
	}
}

// Author: Siyuan Sheng
static void stp_update_hello_timer(stp_t *stp)
{
	if (stp_is_root_switch(stp)) return;
	stp_stop_timer(&stp->hello_timer);
}

static void stp_handle_config_packet(stp_t *stp, stp_port_t *p,
		struct stp_config *config)
{
	// TODO: handle config packet here
	// fprintf(stdout, "TODO: handle config packet here.\n");
	
	if (stp_is_better_config(p, config)) {
		stp_port_update_config(p, config);
		stp_update_status(stp);
		stp_update_configs(stp);
		stp_update_hello_timer(stp);
		stp_send_config(stp);
	}
	else {
		stp_port_send_config(p);
	}
}

static void *stp_dump_state(void *arg)
{
#define get_switch_id(switch_id) (int)(switch_id & 0xFFFF)
#define get_port_id(port_id) (int)(port_id & 0xFF)

	pthread_mutex_lock(&stp->lock);

	bool is_root = stp_is_root_switch(stp);
	if (is_root) {
		log(INFO, "this switch is root."); 
	}
	else {
		log(INFO, "non-root switch, designated root: %04x, root path cost: %d.", \
				get_switch_id(stp->designated_root), stp->root_path_cost);
	}

	for (int i = 0; i < stp->nports; i++) {
		stp_port_t *p = &stp->ports[i];
		log(INFO, "port id: %02d, role: %s.", get_port_id(p->port_id), \
				stp_port_state(p));
		log(INFO, "\tdesignated ->root: %04x, ->switch: %04x, " \
				"->port: %02d, ->cost: %d.", \
				get_switch_id(p->designated_root), \
				get_switch_id(p->designated_switch), \
				get_port_id(p->designated_port), \
				p->designated_cost);
	}

	pthread_mutex_unlock(&stp->lock);

	exit(0);
}

static void stp_handle_signal(int signal)
{
	if (signal == SIGTERM) {
		log(DEBUG, "received SIGTERM, terminate this program.");
		
		pthread_t pid;
		pthread_create(&pid, NULL, stp_dump_state, NULL);
	}
}

void stp_init(struct list_head *iface_list)
{
	stp = malloc(sizeof(*stp));

	// set switch ID
	u64 mac_addr = 0;
	iface_info_t *iface = list_entry(iface_list->next, iface_info_t, list);
	for (int i = 0; i < sizeof(iface->mac); i++) {
		mac_addr <<= 8;
		mac_addr += iface->mac[i];
	}
	stp->switch_id = mac_addr | ((u64) STP_BRIDGE_PRIORITY << 48);

	stp->designated_root = stp->switch_id;
	stp->root_path_cost = 0;
	stp->root_port = NULL;

	stp_init_timer(&stp->hello_timer, STP_HELLO_TIME, \
			stp_handle_hello_timeout, (void *)stp);

	stp_start_timer(&stp->hello_timer, time_tick_now());

	stp->nports = 0;
	list_for_each_entry(iface, iface_list, list) {
		stp_port_t *p = &stp->ports[stp->nports];

		p->stp = stp;
		p->port_id = (STP_PORT_PRIORITY << 8) | (stp->nports + 1);
		p->port_name = strdup(iface->name);
		p->iface = iface;
		p->path_cost = 1;

		stp_port_init(p);

		// store stp port in iface for efficient access
		iface->port = p;

		stp->nports += 1;
	}

	pthread_mutex_init(&stp->lock, NULL);
	pthread_create(&stp->timer_thread, NULL, stp_timer_routine, NULL);

	signal(SIGTERM, stp_handle_signal);
}

void stp_destroy()
{
	pthread_kill(stp->timer_thread, SIGKILL);

	for (int i = 0; i < stp->nports; i++) {
		stp_port_t *port = &stp->ports[i];
		port->iface->port = NULL;
		free(port->port_name);
	}

	free(stp);
}

void stp_port_handle_packet(stp_port_t *p, char *packet, int pkt_len)
{
	stp_t *stp = p->stp;

	pthread_mutex_lock(&stp->lock);
	
	// protocol insanity check is omitted
	struct stp_header *header = (struct stp_header *)(packet + ETHER_HDR_SIZE + LLC_HDR_SIZE);

	if (header->msg_type == STP_TYPE_CONFIG) {
		stp_handle_config_packet(stp, p, (struct stp_config *)header);
	}
	else if (header->msg_type == STP_TYPE_TCN) {
		log(ERROR, "TCN packet is not supported in this lab.");
	}
	else {
		log(ERROR, "received invalid STP packet.");
	}

	pthread_mutex_unlock(&stp->lock);
}
