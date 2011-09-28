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

#include "libnetvirt/fns.h"
#include "PathFinder.hh"
#include "netinet++/ethernetaddr.hh"

#include <stdio.h>
#include <cstdlib>

#include "noxdetect.hh"

using namespace std;
class FNSRule {
public:
	FNSRule(uint64_t sw_id, ofp_match match);
	uint64_t sw_id;
	ofp_match match;
};



class EPoint {
public:
	EPoint(uint64_t ep_id, int in_port, uint32_t mpls, uint64_t fns_uuid);
	void addRule(FNSRule r);
	int num_installed();
	FNSRule getRuleBack();
	void installed_pop();
	static uint64_t generate_key(uint64_t sw_id, uint32_t port, uint32_t mpls);


	uint64_t key;
	uint64_t ep_id;
	int in_port;
	uint32_t mpls;
	uint64_t fns_uuid;

private:
	vector<FNSRule> installed_rules;
};

class FNS{
public:
	FNS(uint64_t uuid);
	uint64_t getUuid();
	int numEPoints();
	void addEPoint(EPoint* ep);
	int removeEPoint(EPoint* ep);
	EPoint* getEPoint(int pos);

private:
	uint64_t uuid;
	vector<EPoint*> epoints;
};


class RulesDB {
public:

	uint64_t addEPoint(endpoint* ep, FNS* fns);
	EPoint* getEpoint(uint64_t key);
	void removeEPoint(uint64_t key);

	FNS* addFNS(fnsDesc* fns);
	void removeFNS(uint64_t uuid);
	FNS* getFNS(uint64_t uuid);


private:
	PathFinder* finder;
	/* Rules in memory
	 * To be more scalable should be stored in a distributed way*/
	map<uint64_t, EPoint> endpoints;
	map<uint64_t, FNS> fnsList;
};

class Locator {
public:
	bool insertClient(vigil::ethernetaddr addr, EPoint* ep);
	EPoint* getLocation(vigil::ethernetaddr);
	void printLocations();
private:
	map<vigil::ethernetaddr, EPoint*> clients;
	bool validateAddr(vigil::ethernetaddr addr);

};

#endif /* RULES_HH_ */
