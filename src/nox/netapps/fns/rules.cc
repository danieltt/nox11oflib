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
#include "rules.hh"
#include <algorithm> // remove and remove_if

FNSRule::FNSRule(uint64_t sw_id, ofp_match match1) :
	sw_id(sw_id) {
	memcpy(&match, &match1, sizeof(match));
}

/*Epoint class*/

EPoint::EPoint(uint64_t ep_id, int in_port, uint32_t mpls, uint64_t fns_uuid) :
	ep_id(ep_id), in_port(in_port), mpls(mpls), fns_uuid(fns_uuid) {
	key = generate_key(ep_id, in_port, mpls);
}

void EPoint::addRule(FNSRule r) {
	installed_rules.push_back(r);
}
int EPoint::num_installed() {
	return installed_rules.size();
}
FNSRule EPoint::getRuleBack() {
	return installed_rules.back();
}
void EPoint::installed_pop() {
	installed_rules.pop_back();
}

uint64_t EPoint::generate_key(uint64_t sw_id, uint32_t port, uint32_t mpls) {
	/*TODO improve mixing functions */
	uint64_t tmp = ((uint64_t) port << 32) + mpls;
	tmp ^= tmp >> 33;
	tmp *= 0xff51afd7ed558ccd;
	tmp ^= tmp >> 33;
	tmp *= 0xc4ceb9fe1a85ec53;
	tmp ^= tmp >> 33;

	sw_id ^= sw_id >> 33;
	sw_id *= 0xff51afd7ed558ccd;
	sw_id ^= sw_id >> 33;
	sw_id *= 0xc4ceb9fe1a85ec53;
	sw_id ^= sw_id >> 33;

	return (tmp + sw_id) % UINT64_MAX;
}

FNS::FNS(uint64_t uuid) :
	uuid(uuid) {

}

uint64_t FNS::getUuid() {
	return uuid;
}

void FNS::addEPoint(EPoint* ep) {
	printf("Adding ep: %d %d\n",ep->ep_id, ep->in_port);
	epoints.push_back(ep);
}

int FNS::removeEPoint(EPoint* ep) {
	ep->fns_uuid = 0;
	epoints.erase(std::remove(epoints.begin(), epoints.end(), ep), epoints.end());

	return 0;
}

int FNS::numEPoints() {
	return epoints.size();
}
EPoint* FNS::getEPoint(int pos) {
	return epoints.at(pos);
}

/*RulesDB class*/
uint64_t RulesDB::addEPoint(endpoint* ep, FNS* fns) {
	EPoint epoint = EPoint(ep->id, ep->port, ep->mpls, fns->getUuid());
	//	printf("Adding %ld\n",ep->id);
	EPoint *node = getEpoint(epoint.key);
	if (node == NULL) {
		endpoints.insert(pair<uint64_t, EPoint> (epoint.key, epoint));
		fns->addEPoint(getEpoint(epoint.key));
		return epoint.key;
	} else {
		return 0;
	}
}
void RulesDB::removeEPoint(uint64_t key) {
	printf("Before removing: %d\n", endpoints.size());
	endpoints.erase(key);
	printf("After removing: %d\n", endpoints.size());

}

EPoint* RulesDB::getEpoint(uint64_t id) {
	//	printf("# endpoints: %d\n",endpoints.size());
	if (endpoints.size() == 0) {
		return NULL;
	}
	map<uint64_t, EPoint>::iterator epr = endpoints.find(id);
	if (endpoints.end() == epr)
		return NULL;
	return &epr->second;
}

FNS* RulesDB::addFNS(fnsDesc* fns1) {

	FNS fns(fns1->uuid);
	//	for (int i = 0; i < fns1->nEp; i++) {
	//		fns.addEPoint(fns1->ep[i]);
	//	}
	fnsList.insert(pair<uint64_t, FNS> (fns1->uuid, fns));
	return getFNS(fns1->uuid);
}

FNS* RulesDB::getFNS(uint64_t uuid) {
	map<uint64_t, FNS>::iterator fns1 = fnsList.find(uuid);
	if (fnsList.end() == fns1)
		return NULL;
	return &fns1->second;
}

void RulesDB::removeFNS(uint64_t uuid) {
	fnsList.erase(uuid);

}

/**
 * Locator class
 */

bool Locator::validateAddr(vigil::ethernetaddr addr) {
	if (addr.is_multicast() || addr.is_broadcast() || addr.is_zero())
		return false;
	/*Check if ethernetaddr exists*/
	if (clients.size() == 0)
		return true;
	map<vigil::ethernetaddr, EPoint*>::iterator epr = clients.find(addr);
	if (clients.end() == epr) {
		return true;
	}

	return false;
}

bool Locator::insertClient(vigil::ethernetaddr addr, EPoint* ep) {
	if (!validateAddr(addr))
		return false;
	/*If not, insert*/
	clients.insert(pair<vigil::ethernetaddr, EPoint*> (addr, ep));
	return true;
}
EPoint* Locator::getLocation(vigil::ethernetaddr addr) {
	if (clients.size() == 0) {
		return NULL;
	}
	map<vigil::ethernetaddr, EPoint*>::iterator epr = clients.find(addr);
	if (clients.end() == epr)
		return NULL;
	return epr->second;
}

void Locator::printLocations() {
	map<vigil::ethernetaddr, EPoint*>::iterator it;
	printf("LOACATOR DB:\n");
	printf("num of entries: %d\n", (int) clients.size());
	for (it = clients.begin(); it != clients.end(); it++) {
		printf("%s -> %d p:%d\n", it->first.string().c_str(),
				(int) it->second->ep_id, (int) it->second->in_port);
	}

}
