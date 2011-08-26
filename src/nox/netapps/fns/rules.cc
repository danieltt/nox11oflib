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

/*Epoint class*/
void EPoint::addRule(FNSRule r){
	installed_rules.push_back(r);
}


/*SWEPoint class*/
void SWEPoint::insertEpoint(int port, EPoint* rule) {
	rules.insert(pair<int, EPoint*> (port, rule));
}
EPoint* SWEPoint::getEpoint(int port) {
	multimap<int, EPoint*>::iterator rule = rules.find(port);
	if (rules.end() == rule)
		return NULL;
	return rule->second;
}
void SWEPoint::removeEpoint_fromPort(int port){
	rules.erase(port);

}

/*RulesDB class*/
void RulesDB::addEPoint(endpoint* ep, fnsDesc* fns) {
	EPoint* epoint = new EPoint(ep->id, ep->port, fns);
	SWEPoint* node;
	//	printf("Adding %ld\n",ep->id);
	node = getSWEndpoint(ep->id);
	if (node == NULL) {
		node = new SWEPoint(ep->id);
		endpoints.insert(pair<uint64_t, SWEPoint*> (ep->id, node));
	}
	node->insertEpoint(ep->port, epoint);

}

fnsDesc* RulesDB::addFNS(fnsDesc* fns1){
	fnsDesc *fns = (fnsDesc *) malloc(sizeof(fnsDesc));
	/*When removing look for all the references*/
	memcpy(fns, fns1, sizeof(fnsDesc));
	fnsList.insert(pair<uint64_t, fnsDesc*> (fns->uuid, fns));
	return fns;
}


fnsDesc* RulesDB::getFNS(fnsDesc* fns){
	map<uint64_t, fnsDesc*>::iterator fns1 = fnsList.find(fns->uuid);
	if (fnsList.end() == fns1)
		return NULL;
	return fns1->second;
}



void RulesDB::removeFNS(fnsDesc* fns){

	fnsList.erase(fns->uuid);
	/*Free memory*/
	free(fns);
}


SWEPoint* RulesDB::getSWEndpoint(uint64_t id) {
	//	printf("# endpoints: %d\n",endpoints.size());
	if (endpoints.size() == 0) {
		return NULL;
	}
	map<uint64_t, SWEPoint*>::iterator epr = endpoints.find(id);
	if (endpoints.end() == epr)
		return NULL;
	return epr->second;
}

/* return the first rule that match */
EPoint* RulesDB::getEpoint(uint64_t id, int port) {
	SWEPoint* epr;
	if ((epr = getSWEndpoint(id)) == NULL)
		return NULL;
	return epr->getEpoint(port);
}


/*Locator class*/
bool Locator::validateAddr(vigil::ethernetaddr addr){
	if(addr.is_multicast() || addr.is_broadcast() || addr.is_zero())
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

bool Locator::insertClient(vigil::ethernetaddr addr, uint64_t id, int port) {
	EPoint* ep;
	if(!validateAddr(addr))
		return false;
	/*If not, insert*/
	/* Get endpoint*/
	ep = rules->getEpoint(id, port);
	clients.insert(pair<vigil::ethernetaddr, EPoint*> (addr, ep));
	return true;
}
bool Locator::insertClient(vigil::ethernetaddr addr, EPoint* ep) {
	if(!validateAddr(addr))
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

void Locator::printLocations(){
	map<vigil::ethernetaddr, EPoint*>::iterator it;
	printf("LOACATOR DB:\n");
	printf("num of entries: %d\n", (int)clients.size());
	for(it = clients.begin(); it != clients.end(); it++)
	{
		printf("%s -> %d p:%d\n",it->first.string().c_str(), (int)it->second->ep_id, (int) it->second->in_port);
	}

}
