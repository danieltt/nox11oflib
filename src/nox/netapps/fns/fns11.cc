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
//#include "openflow-action.hh"

#if OFP_VERSION == 0x01
#define NOX_OF10
#endif
#if OFP_VERSION == 0x02
#define NOX_OF11
#endif

namespace vigil {
static Vlog_module lg("fns");

Disposition fns::handle_link_event(const Event& e) {
	const Link_event& le = assert_cast<const Link_event&> (e);
	int cost = 1;
	lg.warn("Adding link to finder %ld:%d -> %ld:%d", le.dpsrc.as_host(),
			le.sport, le.dpdst.as_host(), le.dport);
	//	Node* a = finder.addNode(le.dpsrc.as_host());
	//	Node* b = finder.addNode(le.dpdst.as_host());
	if (le.action == le.ADD) {
		finder.addEdge(le.dpsrc.as_host(), le.dpdst.as_host(), new LinkAtr(
				cost, le.sport, le.dport),
				new LinkAtr(cost, le.dport, le.sport));
	}
	/*	else
	 finder.removeEdge(new Edge(a,b,cost));*/
	/*
	 msg_link msg;
	 msg.type = FNS_MSG_LINK;
	 msg.size = sizeof(msg_link);
	 msg.action = le.action;
	 msg.dpsrc = (le.dpsrc.as_host();
	 msg.sport = le.sport;
	 msg.dpdst = le.dpdst.as_host();
	 msg.dport = le.dport;

	 lg.dbg("Link event");
	 if (server_sock_fd > 0) {
	 lg.dbg("Sending msg to FNS server");
	 send(server_sock_fd, &msg, sizeof(msg), 0);
	 }*/
	return CONTINUE;
}

Disposition fns::handle_datapath_join(const Event& e) {
	const Datapath_join_event& le = assert_cast<const Datapath_join_event&> (e);
	lg.warn("Datapath in: %ld", le.dpid.as_host());

#ifdef NOX_OF10
	finder.addNode(le.datapath_id.as_host());
#else
	finder.addNode(le.dpid.as_host());
#endif
	return CONTINUE;
}

Disposition fns::handle_datapath_leave(const Event& e) {
	const Datapath_leave_event& le = assert_cast<const Datapath_leave_event&> (
			e);
	finder.removeNode(le.datapath_id.as_host());
	return CONTINUE;
}

Disposition fns::handle_packet_in(const Event& e) {
	const Ofp_msg_event& ome = assert_cast<const Ofp_msg_event&> (e);

	struct ofl_msg_packet_in *in = (struct ofl_msg_packet_in *) **ome.msg;
	Nonowning_buffer b(in->data, in->data_length);
	Flow flow(in->in_port, b);
	/* drop all LLDP packets */
	if (flow.dl_type == ethernet::LLDP) {
		return CONTINUE;
	}

	lg.dbg("Packet in from: %s: ", flow.dl_src.string().c_str());

	RuleOF* rule = rules->getRule(ome.dpid.as_host(), in->in_port);
	if (rule == NULL) {
		lg.warn("No rules for this endpoint: %ld:%d", ome.dpid.as_host(),
				in->in_port);
		/*DROP packet for a given time*/
	} else
		process_rule(rule, &flow, in->buffer_id);

	return CONTINUE;
}

void fns::process_rule(RuleOF* rule, Flow *flow, uint32_t buf) {
	fnsDesc* fns = rule->fns;
	vector<Node*> path;
	int in_port = 0, out_port = 0;
	int psize;

	pair<int, int> ports;

	lg.warn("Processing and installing rule for %ld:%d in fns: %s\n",
			rule->ep_id, rule->in_port, fns->name);

	/*Compute path to source*/
	/*Caching is required if the network is big*/
	if (finder.compute(rule->ep_id) < 0) {
		lg.dbg("error computing path\n");
		return;
	}

	/*Check mode*/
	/*Now is only broadcast*/
	buf = (-1);
	/*Install routes for every destination*/
	for (int j = 0; j < fns->nEp; j++) {
		if (rule->ep_id != fns->ep[j].id || rule->in_port != fns->ep[j].port) {
			/*Install routes between 2 first endpoints
			 * from i to j */
			finder.PrintShortestRouteTo(fns->ep[j].id);

			path = finder.getPath(fns->ep[j].id);
			psize = path.size();
			for (int k = psize - 1; k >= 0; k--) {
				if (psize == 1) {
					/*Endpoint in the same node*/
					ports = pair<int, int> (fns->ep[j].port, rule->in_port);
				} else if (k > 0) {
					ports = path.at(k)->getPortTo(path.at(k - 1));
				}
				out_port = ports.first;
				if (k == 0) {
					out_port = fns->ep[j].port;
				}
				if (k == path.size() - 1) {
					in_port = rule->in_port;
				}

				/*Conflict resolution*/
				flow = getMatchFlow(path.at(k)->id, flow);
				/*Install rule*/
				install_rule(path.at(k)->id, in_port, out_port, flow, buf);
				in_port = ports.second;

			}
		}
	}
}

void fns::process_rule_reverse(RuleOF* rule, Flow *flow, uint32_t buf) {
	fnsDesc* fns = rule->fns;
	vector<Node*> path;
	int in_port = 0, out_port = 0;
	int psize;

	pair<int, int> ports;

	lg.warn("Processing and installing rule for %ld:%d in fns: %s\n",
			rule->ep_id, rule->in_port, fns->name);

	/*Compute path to source*/
	/*Caching is required if the network is big*/
	if (finder.compute(rule->ep_id) < 0) {
		lg.dbg("error computing path\n");
		return;
	}

	/*Check mode*/
	/*Now is only broadcast*/
	buf = (-1);
	/*Install routes for every destination*/
	for (int j = 0; j < fns->nEp; j++) {
		if (rule->ep_id != fns->ep[j].id || rule->in_port != fns->ep[j].port) {
			/*Send packet recevied directly to destination*/

			/*Install routes between 2 first endpoints
			 * from i to j in reverse*/
			finder.PrintShortestRouteTo(fns->ep[j].id);

			path = finder.getPath(fns->ep[j].id);
			psize = path.size();
			for (int k = 0; k < psize; k++) {
				if (psize == 1) {
					/*Endpoint in the same node*/
					ports = pair<int, int> (fns->ep[j].port, rule->in_port);
				} else if (k < psize - 1) {
					ports = path.at(k)->getPortTo(path.at(k + 1));
				}
				out_port = ports.first;
				if (k == 0) {
					in_port = fns->ep[j].port;
				}
				if (k == path.size() - 1) {
					out_port = rule->in_port;
				}
				/*Conflict resolution*/
				flow = getMatchFlow(path.at(k)->id, flow);
				/*Install rule*/
				install_rule(path.at(k)->id, in_port, out_port, flow, buf);
				in_port = ports.second;
			}
		}
	}
}

Flow* fns::getMatchFlow(uint64_t id, Flow* flow) {
	//	flow->dl_dst = ethernetaddr();
	return flow;
}
int fns::save_fns(fnsDesc* fns1) {
	fnsDesc *fns = (fnsDesc *) malloc(sizeof(fnsDesc));
	/*When removing look for all the references*/
	memcpy(fns, fns1, sizeof(fnsDesc));

	lg.dbg("Name: %s\n", (char*) &fns->name);
	for (int i = 0; i < fns->nEp; i++) {
		/*Save endpoints and compute path*/
		lg.dbg("Adding rule to ep: %ld : %d\n", fns->ep[i].id, fns->ep[i].port);
		rules->addRule(&fns->ep[i], fns);
	}
	return 0;
}

int fns::process_fns(void* msg) {

	fnsDesc *fns = (fnsDesc*) msg;

	/*save fns*/
	save_fns(fns);
	//install_fns(fns);
	return 0;
}
int fns::install_rule(uint64_t id, int p_in, int p_out, int buf) {
	Flow* f = new Flow();
	int r = install_rule(id, p_in, p_out, f, buf);
	delete f;
	return r;
}

int fns::install_rule(uint64_t id, int p_in, int p_out, Flow* flow, int buf) {
	datapathid src;
	lg.warn("Installing new path: %ld: %d -> %d | src: %s\n", id, p_in, p_out,
			flow->dl_src.string().c_str());

	/*OpenFlow command initialization*/
	ofp_flow_mod* ofm;
	size_t size = sizeof *ofm + sizeof(ofp_instruction_actions)
			+ sizeof(ofp_action_output);
	boost::shared_array<char> raw_of(new char[size]);
	ofm = (ofp_flow_mod*) raw_of.get();
	memset(ofm, 0, size);
	src = datapathid::from_host(id);

	ofm->buffer_id = buf;
	ofm->header.version = OFP_VERSION;
	ofm->header.type = OFPT_FLOW_MOD;

	ofm->header.length = htons(size);
	/*WILD cards*/
	uint32_t filter = OFPFW_ALL;
	/*Filter by port*/
	filter &= (~OFPFW_IN_PORT);

	/*Set masks to 1*/
	uint64_t mask = 0xFFFFFFFFFFFFFFFF;
	memcpy(&ofm->match.dl_dst_mask, &mask, sizeof(ofm->match.dl_dst_mask));
	memcpy(&ofm->match.dl_src_mask, &mask, sizeof(ofm->match.dl_dst_mask));
	memcpy(&ofm->match.nw_dst_mask, &mask, sizeof(ofm->match.nw_dst_mask));
	memcpy(&ofm->match.nw_src_mask, &mask, sizeof(ofm->match.nw_dst_mask));

	if (!flow->dl_src.is_zero()) {
		/*mask*/
		memset(ofm->match.dl_src_mask, 0, sizeof(ofm->match.dl_src_mask));
		/*content*/
		memcpy(ofm->match.dl_src, flow->dl_src.octet,
				sizeof(flow->dl_src.octet));
	}
	if (!flow->dl_dst.is_zero()) {
		/*mask*/
			memset(ofm->match.dl_dst_mask, 0, sizeof(ofm->match.dl_dst_mask));
			/*content*/
			memcpy(ofm->match.dl_dst, flow->dl_dst.octet,
					sizeof(flow->dl_dst.octet));
	}

	ofm->match.wildcards = htonl(filter);
	ofm->match.in_port = htons(p_in);
	//	memcpy(ofm->match.dl_dst, r->getDlDst().octet, sizeof(r->getDlDst().octet));

	/*Some more parameters*/
	ofm->cookie = htonl(cookie);
	ofm->command = htons(OFPFC_ADD);
	ofm->hard_timeout = htons(0);
	//ofm->hard_timeout = htons(10);
	ofm->priority = htons(OFP_DEFAULT_PRIORITY);
	//	ofm->flags = htons(OFPFF_CHECK_OVERLAP);

	/*Action*/
	ofp_instruction_actions* ins =
			((ofp_instruction_actions*) ofm->instructions);
	memset(ins, 0, sizeof(ofp_instruction_actions));
	ins->type = htons(OFPIT_WRITE_ACTIONS);
	ins->len = htons(sizeof(ofp_instruction_actions)
			+ sizeof(ofp_action_output));

	ofp_action_output* action = ((ofp_action_output*) ins->actions);
	memset(action, 0, sizeof(ofp_action_output));

	action->type = htons(OFPAT_OUTPUT);
	action->len = htons(sizeof(ofp_action_output));
	action->max_len = htons(256);
	action->port = htonl(p_out);

	/*Send command*/
	send_openflow_command(src, &ofm->header, true);
	cookie++;
	return 0;
}

int fns::process_message(void* msg, int size) {

	lg.dbg("Processing msg: %s", (char*) msg);
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

			lg.dbg("New connection in %d\n", sockfd);

		}
		int s = sockfd;
		if (FD_ISSET(s, &read_fds)) {
			/*do the job*/
			if ((nbytes = recv(s, buf, MSG_SIZE, 0)) <= 0) {
				/* got error or connection closed by client */
				if (nbytes == 0) {
					/* connection closed */
					lg.dbg("socket hung up\n");
				} else {
					lg.err("recv()");
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
					process_fns((void*) &msg1->fns);
					break;
				default:
					lg.dbg("Invalid message of size %d: %s\n", nbytes,
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

	register_handler("Link_event", boost::bind(&fns::handle_link_event, this,
			_1));
	register_handler("Datapath_join_event", boost::bind(
			&fns::handle_datapath_join, this, _1));
	register_handler("Datapath_leave_event", boost::bind(
			&fns::handle_datapath_leave, this, _1));
	register_handler("Packet_in_event", boost::bind(&fns::handle_packet_in,
			this, _1));

	//Get topology instance
	//	resolve(topo);
	rules = new RulesDB(&finder);

}

void fns::getInstance(const Context* c, fns*& component) {
	component = dynamic_cast<fns*> (c->get_by_interface(
			container::Interface_description(typeid(fns).name())));
}

REGISTER_COMPONENT(Simple_component_factory<fns>,
		fns)
;
} // vigil namespace

