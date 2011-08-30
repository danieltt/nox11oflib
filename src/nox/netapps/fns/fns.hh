/* Copyright 2008 (C) Nicira, Inc.
 * Copyright 2009 (C) Stanford University.
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
#ifndef fns_HH
#define fns_HH

#include "noxdetect.hh"
#include "component.hh"
#include "config.h"
#include "threads/native.hh"
#include <boost/bind.hpp>
#include "discovery/link-event.hh"
#include "datapath-join.hh"
#include "datapath-leave.hh"
#include "flow.hh"
#include <inttypes.h>
#include "netinet++/datapathid.hh"
#include "openflow-default.hh"

#include "rules.hh"
#include "libnetvirt/fns.h"
#include "PathFinder.hh"


#ifdef LOG4CXX_ENABLED
#include <boost/format.hpp>
#include "log4cxx/logger.h"
#else
#include "vlog.hh"
#endif

#define HARD_TIMEOUT 30
namespace vigil {
using namespace std;
using namespace vigil::container;

/** \brief fns
 * \ingroup noxcomponents
 *
 * @author
 * @date
 */
class fns: public Component {
public:
	/** \brief Constructor of fns.
	 *
	 * @param c context
	 * @param node XML configuration (JSON object)
	 */
	fns(const Context* c, const json_object* node) :
		Component(c) {
	}

	Native_thread server_thread;

	/*Event handlers */
	Disposition handle_link_event(const Event&);
	Disposition handle_datapath_join(const Event& e);
	Disposition handle_datapath_leave(const Event& e);
	Disposition handle_packet_in(const Event& e);

	void server();

	void process_packet_in(EPoint* rule, Flow *flow, const Buffer& buff, int buf_id);
	void forward_via_controller(Flow *flow, const Buffer& buff, uint64_t id , int port);

	int install_rule(uint64_t id, int p_in, int p_out, Flow* flow, int buf);
#ifdef NOX_OF11
	int install_rule_mpls(uint64_t id, int p_in, int p_out, int mpls_tag);
#endif
	int remove_rule(FNSRule rule);

	int save_fns(fnsDesc* fns);
	int remove_fns(fnsDesc* fns);

	Flow* getMatchFlow(uint64_t id, Flow* flow);

	/** \brief Configure fns.
	 *
	 * Parse the configuration, register event handlers, and
	 * resolve any dependencies.
	 *
	 * @param c configuration
	 */
	void configure(const Configuration* c);

	/** \brief Start fns.
	 *
	 * Start the component. For example, if any threads require
	 * starting, do it now.
	 */
	void install();

	/** \brief Get instance of fns.
	 * @param c context
	 * @param component reference to component
	 */
	static void getInstance(const container::Context* c, fns*& component);

private:
	int server_sock_fd;
	int sock_fd;
	int server_port;
	PathFinder finder;
	RulesDB* rules;
	Locator* locator;
	int cookie;

};
}
#endif
