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

#ifndef RULES_HH_
#define RULES_HH_

#include "libnetvirt/fns-msg.h"
#include "libnetvirt/fns.h"
#include "PathFinder.hh"
#include "openflow/openflow.h"
#include "netinet++/ethernetaddr.hh"
#include <list>

using namespace std;
class FNSRule {
public:
	FNSRule(uint64_t sw_id, int in_port, vigil::ethernetaddr dl_src,
			vigil::ethernetaddr dl_dst) :
		sw_id(sw_id), in_port(in_port), dl_src(dl_src), dl_dst(dl_dst) {
	}
	;
	uint64_t sw_id;
	int in_port;
	vigil::ethernetaddr dl_src;
	vigil::ethernetaddr dl_dst;

};

class EPoint {
public:
	EPoint(uint64_t ep_id, int in_port, fnsDesc* fns) :
		ep_id(ep_id), in_port(in_port), fns(fns) {
	}
	void addRule(FNSRule r);
	bool initialized;
	uint64_t ep_id;
	int in_port;
	//vigil::ethernetaddr src_mac;
	fnsDesc* fns;
	vector<FNSRule> installed_rules;
	//vector<Node*> path;
};

class SWEPoint {
public:
	SWEPoint(uint64_t ep_id) :
		ep_id(ep_id) {
	}
	void insertEpoint(int port, EPoint* rule);
	void removeEpoint_fromPort(int port);
	EPoint* getEpoint(int port);
private:
	uint64_t ep_id;
	multimap<int, EPoint*> rules; /*Port , rules*/
};

class RulesDB {
public:
	RulesDB(PathFinder*finder) :
		finder(finder) {
	}
	void addEPoint(endpoint* ep, fnsDesc* fns);
	EPoint* getEpoint(uint64_t id, int port);
	SWEPoint* getSWEndpoint(uint64_t id);
	fnsDesc* addFNS(fnsDesc* fns);
	void removeFNS(fnsDesc* fns);
	fnsDesc* getFNS(fnsDesc* fns);

private:
	PathFinder* finder;
	/* Rules in memory
	 * To be more scalable should be stored in a distributed way*/
	map<uint64_t, SWEPoint*> endpoints;
	map<uint64_t, fnsDesc*> fnsList;
};

class Locator {
public:
	Locator(RulesDB* rules) :
		rules(rules) {
	}

	bool insertClient(vigil::ethernetaddr addr, uint64_t id, int port);
	bool insertClient(vigil::ethernetaddr addr, EPoint* ep);
	EPoint* getLocation(vigil::ethernetaddr);
	void printLocations();
private:
	map<vigil::ethernetaddr, EPoint*> clients;
	bool validateAddr(vigil::ethernetaddr addr);
	RulesDB* rules;

};

#endif /* RULES_HH_ */
