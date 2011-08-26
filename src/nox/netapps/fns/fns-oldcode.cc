
int fns::install_fns(fnsDesc* fns) {
	vector<Node*> path;
	int in_port = 0, out_port = 0;
	int psize;

	pair<int, int> ports;

	/*Compute path*/
	for (int i = 0; i < fns->nEp; i++) {
		if (finder.compute(fns->ep[i].id) < 0) {
			printf("error computing path\n");
			return -1;
		}

		/*Install routes for every destination*/
		for (int j = 0; j < fns->nEp; j++) {
			if (i != j) {
				/*Install routes between 2 first endpoints
				 }
				 * from i to j */
				finder.PrintShortestRouteTo(fns->ep[j].id);

				path = finder.getPath(fns->ep[j].id);
				psize = path.size();
				for (int k = 0; k < psize; k++) {
					if (psize == 1) {
						/*Endpoint in the same node*/
						ports = pair<int, int> (fns->ep[j].port,
								fns->ep[i].port);
					} else if (k < psize - 1) {
						ports = path.at(k)->getPortTo(path.at(k + 1));
					}
					out_port = ports.first;
					if (k == 0) {
						in_port = fns->ep[j].port;
					}
					if (k == path.size() - 1) {
						out_port = fns->ep[i].port;
					}

					install_rule(path.at(k)->id, in_port, out_port, -1);
					in_port = ports.second;
				}
			}
		}
	}

	return 0;
}

int fns::install_rule_reverse(uint64_t id, int p_in, int p_out, Flow* flow,
		int buf) {
	datapathid src;
	ofp_action_list actlist;

	lg.warn("Installing new path: %ld: %d -> %d | src: %s\n", id, p_in, p_out,
			flow->dl_src.string().c_str());

	/*OpenFlow command initialization*/
	ofp_flow_mod* ofm;
	size_t size = sizeof *ofm + sizeof(ofp_action_output)+ sizeof(ofp_action_output);
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
	//	filter &= (~OFPFW_DL_DST);

	ofm->match.wildcards = htonl(filter);
	ofm->match.in_port = htons(p_in);
	//	memcpy(ofm->match.dl_dst, r->getDlDst().octet, sizeof(r->getDlDst().octet));

	/*Some more parameters*/
	ofm->cookie = htonl(cookie);
	ofm->command = htons(OFPFC_ADD);
	ofm->hard_timeout = htons(HARD_TIMEOUT);
	//ofm->hard_timeout = htons(10);
	ofm->priority = htons(OFP_DEFAULT_PRIORITY);
	ofm->flags = htons(OFPFF_CHECK_OVERLAP);

	/*Action*/
	{
	ofp_action *act = new ofp_action();
	act->set_action_output(p_out, 0);
	actlist.action_list.push_back(*act);
	}

	actlist.pack((uint8_t*)&ofm->actions);
	/* ofp_action_output& action = *((ofp_action_output*) ofm->actions);
	 memset(&action, 0, sizeof(ofp_action_output));
	 action.type = htons(OFPAT_OUTPUT);
	 action.len = htons(sizeof(ofp_action_output));
	 action.max_len = htons(0);
	 action.port = htons(p_out);
	 */

	/*Send command*/
	send_openflow_command(src, &ofm->header, true);
	cookie++;
	return 0;
}
