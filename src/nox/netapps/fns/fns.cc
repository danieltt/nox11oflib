/* Copyright 2011 Daniel Turull (KTH) <danieltt@kth.se>
 *
 * This file is part of NOX.
 *
 * NOX is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * NOX is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with NOX.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "assert.hh"
#include "netinet++/ethernet.hh"
#include <cstdlib>
#include "fns.hh"
#include "libnetvirt/fns-msg.h"
#include "libnetvirt/fns.h"
#include "../discovery/discovery.hh"
#include "packets.h"

#ifdef NOX_OF10
#include "openflow-action.hh"
#include "packet-in.hh"
#define TIMEOUT_DEF 0
#endif

namespace vigil {
static Vlog_module lg("fns");

Disposition fns::handle_link_event(const Event& e) {
	const Link_event& le = assert_cast<const Link_event&> (e);
	int cost = 1;
	lg.dbg("Adding link to finder");
	//	Node* a = finder.addNode(le.dpsrc.as_host());
	//	Node* b = finder.addNode(le.dpdst.as_host());
	if (le.action == le.ADD) {
		finder.addEdge(le.dpsrc.as_host(), le.dpdst.as_host(), new LinkAtr(
				cost, le.sport, le.dport),
				new LinkAtr(cost, le.dport, le.sport));
	}

	return CONTINUE;
}

Disposition fns::handle_datapath_join(const Event& e) {
	const Datapath_join_event& le = assert_cast<const Datapath_join_event&> (e);

#ifdef NOX_OF10
	finder.addNode(le.datapath_id.as_host());
#else
	finder.addNode(le.dpid.as_host());
#endif

	/*Remove all entries*/

	return CONTINUE;
}

Disposition fns::handle_datapath_leave(const Event& e) {
	const Datapath_leave_event& le = assert_cast<const Datapath_leave_event&> (
			e);
	finder.removeNode(le.datapath_id.as_host());
	return CONTINUE;
}

Disposition fns::handle_packet_in(const Event& e) {
	uint64_t dpid;
	int port;
#ifdef NOX_OF10
	const Packet_in_event& pi = assert_cast<const Packet_in_event&> (e);
	const Buffer& b = *pi.get_buffer();
	Flow flow(pi.in_port, b);
	dpid = pi.datapath_id.as_host();
	port = pi.in_port;
#else
	const Ofp_msg_event& ome = assert_cast<const Ofp_msg_event&> (e);
	struct ofl_msg_packet_in *in = (struct ofl_msg_packet_in *) **ome.msg;
	Nonowning_buffer b(in->data, in->data_length);
	Flow flow(in->in_port, b);
	dpid = ome.dpid.as_host();
	port = in->in_port;

#endif

	/* drop all LLDP packets */
	if (flow.match.dl_type == LLDP_TYPE) {
		return CONTINUE;
	}

	lg.dbg("MPLS: label:%u tc:%d", flow.match.mpls_label, flow.match.mpls_tc);
	EPoint* ep = rules.getEpoint(EPoint::generate_key(dpid, port,
			flow.match.mpls_label));

	if (ep == NULL) {
		lg.dbg("No rules for this endpoint: %ld:%d", dpid, port);
		/*DROP packet for a given time*/
	} else {
		ethernetaddr dl_src = ethernetaddr(flow.match.dl_src);
		locator.insertClient(dl_src, ep);
		/*TODO fix buffer id -1*/
		process_packet_in(ep, &flow, b, -1);
	}

	//	locator.printLocations();
	return CONTINUE;
}

void fns::process_packet_in(EPoint* ep_src, Flow *flow, const Buffer& buff,
		int buf_id) {
	EPoint* ep_dst;

	vector<Node*> path;
	int in_port = 0, out_port = 0;
	int psize;
	buf_id = -1;
	pair<int, int> ports;
	fnsDesc* fns = ep_src->fns;

	/* Is destination broadcast address and ARP?*/
	/* TODO with OF1.1 should be possible to send the packets
	 *  to the endpoint using the network
	 *  Install the rules like multicast
	 *
	 *  Currently we use the controller channel to forward the ARP packets.
	 */
	ethernetaddr dl_dst = ethernetaddr(flow->match.dl_dst);
	ethernetaddr dl_src = ethernetaddr(flow->match.dl_src);

	lg.dbg("Processing and installing rule for %ld:%d in fns: %s\n",
			ep_src->ep_id, ep_src->in_port, fns->name);

	if (dl_dst.is_broadcast() && flow->match.dl_type == ETH_TYPE_ARP) {
		/*Send to all endpoints of the fns*/
		lg.warn("Sending ARP broadcast msg");
		for (int j = 0; j < fns->nEp; j++) {
			if (fns->ep[j].id != ep_src->ep_id)
				forward_via_controller(fns->ep[j].id, buff, fns->ep[j].port);
		}
		return;
	}

	/*Compute path from source*/
	/*Caching is required if the network is big*/
	if (finder.compute(ep_src->ep_id) < 0) {
		printf("error computing path\n");
		return;
	}
	/*Get location of destination*/
	ep_dst = locator.getLocation(dl_dst);
	if (ep_dst == NULL) {
		lg.warn("NO destination for this packet in the LOCATOR");
		return;
	}
	/*Get shortest path*/
	//	finder.PrintShortestRouteTo(ep_dst->ep_id);
	path = finder.getPath(ep_dst->ep_id);
	psize = path.size();

	/*Install specific rules with src and destination L2*/
	for (int k = psize - 1; k >= 0; k--) {
		if (psize == 1) {
			/*Endpoint in the same node*/
			ports = pair<int, int> (ep_dst->in_port, ep_src->in_port);
		} else if (k > 0) {
			ports = path.at(k)->getPortTo(path.at(k - 1));
		}
		out_port = ports.first;
		if (k == 0) {
			out_port = ep_dst->in_port;
		}
		if (k == path.size() - 1) {
			in_port = ep_src->in_port;
		}

		/*Conflict resolution*/
		//flow = getMatchFlow(path.at(k)->id, flow);
		/* Install rule */
		ofp_match match;

		match =install_rule(path.at(k)->id, in_port,
				out_port, dl_src, dl_dst, buf_id);
		lg.dbg("match in: %d",ntohl(match.in_port));

		/* Keeping track of the installed rules */
		ep_src->addRule(FNSRule(path.at(k)->id, match));
		/* Install rule reverse*/
		match =install_rule(path.at(k)->id, out_port, in_port, dl_dst, dl_src,
				buf_id);

		/* Keeping track of the installed rules */
		ep_src->addRule(FNSRule(path.at(k)->id, match));
		in_port = ports.second;

	}

}
#ifdef NOX_OF10
int fns::install_rule(uint64_t id, int p_in, int p_out, Flow* flow, int buf) {
	datapathid src;
	ofp_action_list actlist;
	lg.warn("Installing new path: %ld: %d -> %d | src: %s dst: %s\n", id, p_in,
			p_out, flow->dl_src.string().c_str(), flow->dl_dst.string().c_str());

	/*OpenFlow command initialization*/
	ofp_flow_mod* ofm;
	size_t size = sizeof *ofm + sizeof(ofp_action_output);
	boost::shared_array<char> raw_of(new char[size]);
	ofm = (ofp_flow_mod*) raw_of.get();

	src = datapathid::from_host(id);

	ofm->buffer_id = buf;
	ofm->header.version = OFP_VERSION;
	ofm->header.type = OFPT_FLOW_MOD;

	ofm->header.length = htons(size);
	/*WILD cards*/
	uint32_t filter = OFPFW_ALL;
	/*Filter by port*/
	filter &= (~OFPFW_IN_PORT);
	if (!flow->dl_src.is_zero()) {
		filter &= (~OFPFW_DL_SRC);
		memcpy(ofm->match.dl_src, flow->dl_src.octet,
				sizeof(flow->dl_src.octet));
	}
	if (!flow->dl_dst.is_zero()) {
		filter &= (~OFPFW_DL_DST);
		memcpy(ofm->match.dl_dst, flow->dl_dst.octet,
				sizeof(flow->dl_dst.octet));
	}

	ofm->match.wildcards = htonl(filter);
	ofm->match.in_port = htons(p_in);
	//	memcpy(ofm->match.dl_dst, r->getDlDst().octet, sizeof(r->getDlDst().octet));

	/*Some more parameters*/
	ofm->cookie = htonl(cookie);
	ofm->command = htons(OFPFC_ADD);
	//	ofm->hard_timeout = htons(0);
	ofm->hard_timeout = htons(TIMEOUT_DEF);
	ofm->priority = htons(OFP_DEFAULT_PRIORITY);
	ofm->flags = ofd_flow_mod_flags();

	/*Action*/
	ofp_action_output& action = *((ofp_action_output*) ofm->actions);
	memset(&action, 0, sizeof(ofp_action_output));

	action.type = htons(OFPAT_OUTPUT);
	action.len = htons(sizeof(ofp_action_output));
	action.max_len = htons(0);
	action.port = htons(p_out);

	/*Send command*/
	send_openflow_command(src, &ofm->header, true);
	cookie++;
	return 0;
}

int fns::remove_rule(FNSRule rule) {
	datapathid src;
	ofp_action_list actlist;

	lg.warn("Removing rule from switch: %lu", rule.sw_id);
	/*OpenFlow command initialization*/
	ofp_flow_mod* ofm;
	size_t size = sizeof *ofm;
	boost::shared_array<char> raw_of(new char[size]);
	ofm = (ofp_flow_mod*) raw_of.get();

	src = datapathid::from_host(rule.sw_id);

	ofm->header.version = OFP_VERSION;
	ofm->header.type = OFPT_FLOW_MOD;

	ofm->header.length = htons(size);
	/*WILD cards*/
	uint32_t filter = OFPFW_ALL;
	/*Filter by port*/
	filter &= (~OFPFW_IN_PORT);
	filter &= (~OFPFW_DL_SRC);
	memcpy(ofm->match.dl_src, rule.dl_src.octet, sizeof(rule.dl_src.octet));

	filter &= (~OFPFW_DL_DST);
	memcpy(ofm->match.dl_dst, rule.dl_dst.octet, sizeof(rule.dl_dst.octet));

	ofm->match.wildcards = htonl(filter);
	ofm->match.in_port = htons(rule.in_port);
	ofm->command = htons(OFPFC_DELETE);
	ofm->out_port = OFPP_NONE;
	ofm->hard_timeout = 0;
	ofm->priority = htons(OFP_DEFAULT_PRIORITY);
	ofm->flags = ofd_flow_mod_flags();
	/*Send command*/
	send_openflow_command(src, &ofm->header, true);
	cookie++;
	return 0;
}
#endif

#ifdef NOX_OF11

ofp_match fns::install_rule(uint64_t id, int p_in, int p_out,
		vigil::ethernetaddr dl_src, vigil::ethernetaddr dl_dst, int buf) {
	datapathid src;

	lg.warn("Installing new path: %ld: %d -> %d | src: %s\n", id, p_in, p_out,
			dl_src.string().c_str());

	datapathid dpid;
	/*OpenFlow command initialization*/
	dpid = datapathid::from_host(id);

	/* delete all flows on this switch */
	struct ofp_match match;
	match.type = OFPMT_STANDARD;
	match.wildcards = OFPFW_ALL;
	//    memset(match.dl_src_mask, 0xff, 6);
	//   memset(match.dl_dst_mask, 0xff, 6);
	match.nw_src_mask = 0xffffffff;
	match.nw_dst_mask = 0xffffffff;
	match.metadata_mask = 0xffffffffffffffffULL;
	match.in_port = htonl(p_in);

	/* L2 src */
	memset(match.dl_src_mask, 0, sizeof(match.dl_src_mask));
	memcpy(match.dl_src, dl_src.octet, sizeof(dl_src.octet));

	/* L2 dst */
	memset(match.dl_dst_mask, 0, sizeof(match.dl_dst_mask));
	memcpy(match.dl_dst, dl_dst.octet, sizeof(dl_dst.octet));

	struct ofl_action_output output = { {/*.type = */OFPAT_OUTPUT }, /*.port = */
			p_out, /*.max_len = */0 };

	struct ofl_action_header *actions[] = {
			(struct ofl_action_header *) &output };

	struct ofl_instruction_actions apply = {
			{/*.type = */OFPIT_WRITE_ACTIONS }, /*.actions_num = */1, /*.actions = */
			actions };

	struct ofl_instruction_header *insts[] = {
			(struct ofl_instruction_header *) &apply };

	struct ofl_msg_flow_mod mod;
	mod.header.type = OFPT_FLOW_MOD;
	mod.cookie = htonl(cookie);
	mod.cookie_mask = 0x00ULL;
	mod.table_id = 0;
	mod.command = OFPFC_ADD;
	mod.out_port = htonl(p_out);
	mod.out_group = 0;
	mod.flags = 0x0000;
	mod.match = (struct ofl_match_header *) &match;
	mod.instructions_num = 1;
	mod.instructions = insts;
	mod.priority = htons(OFP_DEFAULT_PRIORITY);
	mod.buffer_id = buf;
	mod.hard_timeout = 0;
	mod.idle_timeout = 0;

	/* XXX OK to do non-blocking send?  We do so with all other
	 * commands on switch join */
	if (send_openflow_msg(dpid, (struct ofl_msg_header *) &mod, 0/*xid*/, false)
			== EAGAIN) {
		lg.err("Error, unable to clear flow table on startup");
	}

	return match;

}

int fns::remove_rule(FNSRule rule) {
	datapathid dpid;

	lg.dbg("Removing rule in %lu, in: %d",rule.sw_id, ntohl(rule.match.in_port));
	/*OpenFlow command initialization*/
	dpid = datapathid::from_host(rule.sw_id);

	struct ofl_msg_flow_mod mod;
	mod.header.type = OFPT_FLOW_MOD;
	mod.cookie = 0x00ULL;
	mod.cookie_mask = 0x00ULL;
	mod.table_id = 0xff; // all tables
	mod.command = OFPFC_DELETE;
	mod.out_port = OFPP_ANY;
	mod.out_group = OFPG_ANY;
	mod.flags = 0x0000;
	mod.match = (struct ofl_match_header *) &rule.match;
	mod.instructions_num = 0;
	mod.instructions = NULL;

	/* XXX OK to do non-blocking send?  We do so with all other
	 * commands on switch join */
	if (send_openflow_msg(dpid, (struct ofl_msg_header *) &mod, 0/*xid*/, false)
			== EAGAIN) {
		lg.err("Error, unable to clear flow table on startup");
	}
	return 0;
}

int fns::install_rule_mpls(uint64_t id, int p_in, int p_out, int mpls_tag) {
	datapathid src;
	lg.warn("Adding mpls rule");

	/*OpenFlow command initialization*/

	return 0;
}

#endif

void fns::forward_via_controller(uint64_t id, const Buffer& buff, int port) {
	lg.warn("ATTENTION. Sending packet directly to the destination: %lu :%d",
			id, port);

#ifdef NOX_OF10
	send_openflow_packet(datapathid::from_host(id), buff, port, 0, false);
#else
	send_openflow_pkt(datapathid::from_host(id), buff, OFPP_CONTROLLER, port,
			false);
#endif
}

Flow* fns::getMatchFlow(uint64_t id, Flow* flow) {
	return flow;
}

int fns::save_fns(fnsDesc* fns1) {

	fnsDesc* fns = rules.addFNS(fns1);

	printf("Name: %s\n", (char*) &fns->name);
	printf("Num of endpoints %d\n", fns->nEp);
	for (int i = 0; i < fns->nEp; i++) {
		/*Save endpoints and compute path*/
		lg.warn("Adding rule to ep: %ld : %d\n", fns->ep[i].id, fns->ep[i].port);
		rules.addEPoint(&fns->ep[i], fns);
	}
	return 0;
}
int fns::remove_fns(fnsDesc* fns) {
	int i;
	lg.warn("Removing fns with name: %s and uuid: %lu \n", (char*) &fns->name,
			fns->uuid);

	/* Search fns info */
	fns = rules.getFNS(fns);
	if (fns == NULL) {
		lg.warn("The FNS doesn't exists");
		return -1;
	}
	/* Go to any end nodes and remove installed path */
	lg.warn("Num of affected endpoints: %d", fns->nEp);
	for (i = 0; i < fns->nEp; i++) {
		uint64_t key = EPoint::generate_key(fns->ep[i].id, fns->ep[i].port,
				fns->ep[i].mpls);
		EPoint* ep = rules.getEpoint(key);
		lg.warn("Installed rules: %d", (int) ep->num_installed());
		while (ep->num_installed()>0) {
			FNSRule rule = ep->getRuleBack();
			remove_rule(rule);
			ep->installed_pop();
			//TODO fixing
		}
		rules.removeEPoint(key);
	}

	/* Remove fns from the list and free memory*/
	lg.warn("removing fns");
	rules.removeFNS(fns);

	return 0;
}

void fns::server() {

	socklen_t addrlen;
	struct sockaddr_in serv_addr, clientaddr;
	int yes = 1;
	int sockfd = 0;
	int listener;
	fd_set master; /* master file descriptor list */
	fd_set read_fds; /* temp file descriptor list for select() */
	int fdmax;
	int newfd;
	int nbytes;
	struct timeval tv;
	void* buf;

	listener = socket(AF_INET, SOCK_STREAM, 0);
	if (listener < 0) {
		perror("ERROR opening socket");
		exit(1);
	}

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(server_port);

	if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
		perror("ERROR on setsockopt()");
		exit(1);
	}

	if (bind(listener, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		close(listener);
		perror("ERROR on binding");
		exit(1);
	}

	if (listen(listener, MAX_CONNECTIONS) == -1) {
		perror("ERROR on listen");
		exit(1);
	}

	fdmax = listener; /* maximum file descriptor number */

	/*Allocate reception buffer*/
	buf = (void*) malloc(MSG_SIZE);
	if (buf == NULL) {
		perror("ERROR in malloc");
		exit(1);
	}

	/* clear the master and temp sets */
	FD_ZERO(&master);
	FD_ZERO(&read_fds);

	/* add the listener to the master set */
	FD_SET(listener, &master);

	/*Loop forever*/
	while (1) {
		/* copy it */
		read_fds = master;

		/*Set timeout*/
		tv.tv_sec = SELECT_TIMEOUT;
		tv.tv_usec = 0;
		if (select(fdmax + 1, &read_fds, NULL, NULL, &tv) == -1) {
			perror("Server-select()");
			exit(1);
		}

		/*Check listening*/
		if (FD_ISSET(listener, &read_fds)) {
			addrlen = sizeof(clientaddr);
			if ((newfd = accept(listener, (struct sockaddr *) &clientaddr,
					(socklen_t *) &addrlen)) == -1) {
				perror("Server-accept() error lol!");
				continue;
			}
			FD_SET(newfd, &master); /* add to master set */
			/*TODO manage multiple ports*/
			sockfd = newfd;

			if (newfd > fdmax)
				fdmax = newfd;//* keep track of the maximum */

			printf("New connection in %d\n", sockfd);

		}
		int s = sockfd;
		if (FD_ISSET(s, &read_fds)) {
			/*do the job*/
			if ((nbytes = recv(s, buf, MSG_SIZE, 0)) <= 0) {
				/* got error or connection closed by client */
				if (nbytes == 0) {
					/* connection closed */
					printf("socket hung up\n");
				} else {
					perror("recv()");
				}
				/* close it... */
				close(s);
				/* remove from master set */
				FD_CLR(s, &master);
				//} else if (nbytes < sizeof(struct msg_hdr)) {
				//	lg.dbg("Too small packet");
			} else {
				/* we got some data from a client*/
				lg.dbg("New msg of size %d", nbytes);
				struct msg_hdr *msg = (struct msg_hdr*) buf;
				struct msg_fns *msg1;
				switch (msg->type) {
				case FNS_MSG_ADD:
					msg1 = (struct msg_fns*) buf;
					save_fns(&msg1->fns);
					break;
				case FNS_MSG_DEL:
					msg1 = (struct msg_fns*) buf;
					remove_fns(&msg1->fns);

					break;
				default:
					printf("Invalid message of size %d: %s\n", nbytes,
							(char*) buf);
					break;
				}
			}
		}
	}
	lg.dbg("Finishing server");
	free(buf);
	/*Close all sockets*/
	close(listener);

}
void fns::configure(const Configuration* c) {
	server_port = TCP_PORT;
	lg.dbg(" Listening in port: %d", server_port);
}

void fns::install() {
	lg.dbg(" Install called ");
	this->server_thread.start(boost::bind(&fns::server, this));
	/*
	 register_handler<Link_event> (
	 boost::bind(&fns::handle_link_event, this, _1));

	 register_handler<Packet_in_event> (boost::bind(&fns::handle_packet_in,
	 this, _1));
	 register_handler<Datapath_join_event> (boost::bind(
	 &fns::handle_datapath_join, this, _1));
	 register_handler<Datapath_leave_event> (boost::bind(
	 &fns::handle_datapath_leave, this, _1));
	 */

	register_handler("Link_event", boost::bind(&fns::handle_link_event, this,
			_1));
	register_handler("Datapath_join_event", boost::bind(
			&fns::handle_datapath_join, this, _1));
	register_handler("Datapath_leave_event", boost::bind(
			&fns::handle_datapath_leave, this, _1));
	register_handler("Packet_in_event", boost::bind(&fns::handle_packet_in,
			this, _1));

}

void fns::getInstance(const Context* c, fns*& component) {
	component = dynamic_cast<fns*> (c->get_by_interface(
			container::Interface_description(typeid(fns).name())));
}

REGISTER_COMPONENT(Simple_component_factory<fns>,
		fns)
;
} // vigil namespace

