from typing import get_origin
import neo4j
from neo4j import Auth, GraphDatabase
from neo4j.exceptions import ServiceUnavailable
import log
import sys
import pdb

databaseUri="bolt://localhost:7687"
databaseUser="neo4j"
databasePassword="kali"

driver = None
session = None

def connect():
    global session
    global driver

    log.logger.debug(f"[ ] Connecting to neo4j database (url={databaseUri}, user={databaseUser}, password={databasePassword})")

    try:
        driver = GraphDatabase.driver(databaseUri, auth = Auth(scheme = 'basic', principal = databaseUser, credentials = databasePassword))
        session = driver.session()
        session.run("MATCH (u:User {name:'CONNECTIONTEST12321'}) RETURN u")
    except ServiceUnavailable:
        log.logger.exception('[-] Connection to BloodHound Neo4j database failed')
        sys.exit()

    except Exception:
        log.logger.exception('[-] Error')
        sys.exit()
    

def element_query(query, attributes=[]):

    log.logger.debug(f"[ ] Executing Bloodhound query: {query}")
    results = session.run(query)
    results = results.values()
    
    res = {}

    for i in results:
        for i2 in i:
            res_item = {}
            for attr in attributes:
                if attr in i2.keys():
                    res_item[attr] = i2[attr]
                else:
                    print("ERROR, entry does not contain requested key: "+str(i2))

            if "name" in i2.keys():
                res[i2["name"]]=res_item
            elif "azname" in i2.keys():
                res[i2["azname"]]=res_item
            elif "objectid" in i2.keys():
                res[i2["objectid"]]=res_item
            else:
                print("ERROR: "+str(i2))
                continue

    if len(attributes) == 0:
        return sorted(res.keys())
    return res

def get_computers():
    res = element_query('MATCH (c:Computer) RETURN c')
    return res

def get_users():
    res = element_query('MATCH (u:User) RETURN u')
    return res

groups_cache = {}

def get_groups(target_name):
    if target_name in groups_cache:
        return groups_cache[target_name]
    query = "MATCH (d {name:'"+target_name+"'})-[r:MemberOf*1..]->(o:Group) RETURN o"
    log.logger.debug(f"[ ] Executing Bloodhound query: {query}")
    #query = "MATCH p=(n:GPO)-[r:GpLink|Contains*1..]->(o {name: '"+target_name+"'}) RETURN p"
    results = session.run(query)
    results = results.values()

    ret = []
    for r in results:
        group_name = r[0]._properties["name"].split("@")[0]
        domain = r[0]._properties["domain"].split(".")[0]

        # dn = r[0]._properties["distinguishedname"]
        # group_name = dn.split(",")[0].split("=")[1]
        # domain = dn.split("DC=")[1].split(",")[0].upper()
        
        ret.append(domain+"\\"+group_name)

    groups_cache[target_name] = ret
    return ret

def get_OU_path(target_name):
    query = "MATCH p=(d:Domain)-[r:Contains*1..]->(o {name: '"+target_name+"'}) RETURN p"
    log.logger.debug(f"[ ] Executing Bloodhound query: {query}")
    #query = "MATCH p=(n:GPO)-[r:GpLink|Contains*1..]->(o {name: '"+target_name+"'}) RETURN p"
    results = session.run(query)
    results = results.values()
    if len(results) == 0 or len(results[0])==0:
        return None
    path = results[0][0].nodes
    #resval[0][0].nodes[5]._properties["blocksinheritance"]
    return path

ou_gpo_cache = {}

def get_OU_GPOs(OU_name):
    if OU_name in ou_gpo_cache:
        return ou_gpo_cache[OU_name]
    gpo_ids = []
    query = "MATCH p=(n:GPO)-[r:GpLink]->(o {name: '"+OU_name+"'}) RETURN n"
    log.logger.debug(f"[ ] Executing Bloodhound query: {query}")
    results = session.run(query)
    results = results.values()

    for node in results:
        gpo_ids.append("{"+node[0]._properties["gpcpath"].split("{")[1])
    
    ou_gpo_cache[OU_name] = gpo_ids
    return gpo_ids

def set_object_prop(objects, rights):
    for object in objects:
        query = []
        for r in rights:
            query.append(f"a.{r}='{rights[r]}'")
        query = "MATCH (a) WHERE a.name='"+object+"' or a.objectid='"+object+"' SET "+", ".join(query)+" RETURN COUNT(*) AS count"
        log.logger.debug(f"[ ] Executing Bloodhound query: {query}")
        results = session.run(query)

        count = results.single()['count']

        if count > 0:
            log.logger.info('[+] Modified: ' + object)
            log.logger.debug('[*] Number of modified entries: ' + str(count))
        else:
            log.logger.error('[-] Could not modify: ' + object)

def insert_edge(start_node, end_node, edge_name, comment=""):
    query = "MATCH (a), (b) WHERE a.objectid = '"+start_node+"' AND (b.objectid = '"+end_node+"' OR b.name = '"+end_node+"') AND NOT (a)-[:"+edge_name+"]->(b) CREATE (a)-[r:"+edge_name+" {comment: '"+comment+"'}]->(b) RETURN a"
    log.logger.debug(f"[ ] Executing Bloodhound query: {query}")
    results = session.run(query)
    res_vals = results.values()

    if len(res_vals) > 0:
        log.logger.info(f'[+] Added Bloodhound edge: ({start_node})-[:{edge_name}]->({end_node})')
    else:
        query = "MATCH (a)-[:"+edge_name+"]->(b) WHERE a.objectid = '"+start_node+"' AND (b.objectid = '"+end_node+"' OR b.name = '"+end_node+"') RETURN a"
        results = session.run(query)
        res_vals = results.values()
        if len(res_vals) > 0:
            log.logger.debug(f'[-] Bloodhound Edge already exists: ({start_node})-[:{edge_name}]->({end_node})')
            return
        else:
            query = "MATCH (a) WHERE a.objectid = '"+start_node+"' RETURN a"
            results = session.run(query)
            res_vals = results.values()
            if len(res_vals) == 0:
                log.logger.error(f'[-] Could not add Bloodhound edge: "{start_node}" does not exist')
                return
            query = "MATCH (a) WHERE (b.objectid = '"+end_node+"' OR b.name = '"+end_node+"') RETURN b"
            results = session.run(query)
            res_vals = results.values()
            if len(res_vals) == 0:
                log.logger.error(f'[-] Could not add Bloodhound edge: "{end_node}" does not exist')
                return
            log.logger.error(f'[-] Start and end node exist, but could not add Bloodhound edge: ({start_node})-[:{edge_name}]->({end_node})')