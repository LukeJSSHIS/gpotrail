#!/usr/bin/python3

import log
import xml.etree.ElementTree as ET
import pdb
import collections
import bloodhound_api
import pdb
import collections
import gpo_parser
from argparse import RawTextHelpFormatter,ArgumentParser, ArgumentDefaultsHelpFormatter

def get_rolled_out_gpo_list(target_name):
    path = bloodhound_api.get_OU_path(target_name)
    if path == None:
        log.logger.error(f"[-] Error determining GPOs for target {target_name}: Target name does not exist in bloodhound.")
        return []
    gpo_list = []

    for ou in path:
        dn = ou._properties["distinguishedname"]

        new_list = []
        if "blocksinheritance" in ou._properties and ou._properties["blocksinheritance"]:
            for g, enforced in gpo_list:
                if enforced:
                    new_list.append((g, enforced))
            gpo_list = new_list

        candidates=[GPOs[x] for x in bloodhound_api.get_OU_GPOs(ou._properties["name"])]

        # Check Security Filtering
        for c in candidates:
            if c.applies_to(target_name):
                gpo_list.append((c, c.is_enforced_link(dn)))

    return gpo_list

# {"RegistrySettings": [GPO_extension1, GPO_extension2,... ], "...": [], ...}
def join_extension(rsop, new_p_elements, new_enforced, new_is_loopback_gpo=False):

    new_extensions = {}
    for old_pe in rsop:
        new_extensions[old_pe["pe"].fingerprint] = old_pe

    for new_pe in new_p_elements:
        if new_pe.fingerprint in new_extensions:
            suppress_log = False
            if new_pe.text == new_extensions[new_pe.fingerprint]["pe"].text:
                suppress_log = True

            if not suppress_log: log.logger.info(f"Policy conflict: \n  [OLD] '{new_extensions[new_pe.fingerprint]['pe'].parent_policy.name}'\n        {new_extensions[new_pe.fingerprint]['pe']}\n  [NEW] '{new_pe.parent_policy.name}'' \n        {new_pe}\n")
            
            # NEW is loopback GPO, OLD is not
            if new_is_loopback_gpo and not new_extensions[new_pe.fingerprint]["loopback_gpo"]:
                if not suppress_log: log.logger.info(f"NEW wins as demanded by loopback mode")
                new_extensions[new_pe.fingerprint] = {"pe":new_pe, "enforced":new_enforced, "loopback_gpo":new_is_loopback_gpo}
            # NEW is not loopback GPO, or both NEW and GPO are conflicting loopback GPOs
            else:
                # OLD is enforced
                if new_extensions[new_pe.fingerprint]["enforced"]:
                    # NEW is enforced as well 
                    if new_enforced:
                        # Higher tier enforced GPO win
                        if not suppress_log: log.logger.info(f"OLD wins as it is enforced and NEW is enforced but has no precedence")
                        continue
                    # NEW is not enforced
                    else:
                        if not suppress_log: log.logger.info(f"OLD wins as it is enforced and NEW is not")
                        continue
                # OLD is not enforced
                else:
                    # TODO: this does support cases in which conflicting GPOs are on the same "level" (e.g., same OU)
                    # Lower tier non-enforced GPO win
                    if not suppress_log: log.logger.info(f"NEW wins as it has precedence and OLD is not enforced")
                    new_extensions[new_pe.fingerprint] = {"pe":new_pe, "enforced":new_enforced, "loopback_gpo":new_is_loopback_gpo}
        else:
            new_extensions[new_pe.fingerprint] = {"pe":new_pe, "enforced":new_enforced, "loopback_gpo":new_is_loopback_gpo}
 
    
    rsop = new_extensions.values()

    return rsop

def get_gpo_loopback_processing_mode(rsop_computer):
    res = ""

    for meta_pe in rsop_computer:
        loopback_setting = meta_pe["pe"].get_loopback_setting()
        if loopback_setting != "":
            return loopback_setting

    return res

def get_rsop(target_name, user_name=""):
    #rsop_computer = {"q1:WindowsFirewallSettings": "abs", ...}
    rsop_computer = []
    rsop_user = []
    applied_policies = set()

    # Merge COMPUTER GPOs
    #####################
    candidates_computer_gpos = get_rolled_out_gpo_list(target_name)

    for c_gpo, enforced in candidates_computer_gpos:  
        # mash policies together where applicable (computer/user enabled, filtering, ?)
        if c_gpo.is_computer_enabled():
            p_elements = c_gpo.get_computer_policy_elements()
            rsop_computer = join_extension(rsop_computer, p_elements, enforced)
            applied_policies.add(c_gpo.name)

    # Merge USER GPOs
    #################
    
    # if Group Policy loopback processing mode = Replace -> use computer GPOs
    candidates_user_gpos = []
    loopback_mode = get_gpo_loopback_processing_mode(rsop_computer)
    log.logger.debug(f"Loopback mode identified as: {loopback_mode}")
    if loopback_mode != "Replace":
        if user_name != "":
            candidates_user_gpos = get_rolled_out_gpo_list(user_name)

        for u_gpo, enforced in candidates_user_gpos:
            if u_gpo.is_user_enabled():
                p_elements = u_gpo.get_user_policy_elements()
                rsop_user = join_extension(rsop_user, p_elements, enforced)
                applied_policies.add(u_gpo.name)

    if loopback_mode == "Merge" or loopback_mode == "Replace":
        for u_gpo, enforced in candidates_computer_gpos:
            if u_gpo.is_user_enabled():
                p_elements = u_gpo.get_user_policy_elements()
                rsop_user = join_extension(rsop_user, p_elements, enforced, True)
                applied_policies.add(u_gpo.name)

    return {"user":rsop_user, "computer":rsop_computer, "applied_policies":sorted(applied_policies)}

def print_rsop(rsop, filtered=False):

    print("")
    print("- APPLIED POLICIES -")
    print("--------------------")

    print("\n".join(rsop["applied_policies"]))

    print("")
    print("- COMPUTER -")
    print("------------")

    for meta_pe in sorted(rsop["computer"], key=lambda x: str(x["pe"])):
        pe = meta_pe["pe"]
        if filtered and not pe.is_security_relevant:
            continue
        print(pe)

    print("") 
    print("-   USER   -")
    print("------------")
    
    for meta_pe in sorted(rsop["user"], key=lambda x: str(x["pe"])):
        pe = meta_pe["pe"]
        if filtered and not pe.is_security_relevant:
            continue
        print(pe)

# | EnableLUA | LocalAccountTokenFilterPolicy | FilterAdministratorToken | Effect |
# |:----------|:------------------------------|:-------------------------|:------|
# | 0         | N/A                           | N/A                      | Local admins & RID 500 allowed |
# | 1         | 0 (default)                   | 0 (default)              | Only RID 500 account allowed |
# | 1         | 0                             | 1                        | No accounts allowed |
# | 1         | 1                             | 0                        | Local admins & RID 500 allowed |

def get_psexec_rights(rsop):
    # TODO: integrate URA: SeDenyNetworkLogonRight and SeDenyRemoteInteractiveLogonRight
    ret = {"psexec_local_admin": "not allowed", "psexec_builtin_admin": "allowed"}
    for meta_pe in sorted(rsop["computer"], key=lambda x: str(x["pe"])):
        pe = meta_pe["pe"]

        if "EnableLUA: 0" in str(pe):
            ret["psexec_local_admin"] = "allowed"
            ret["psexec_builtin_admin"] = "allowed"
            return ret
        if "FilterAdministratorToken: 1" in str(pe):
            ret["psexec_local_admin"] = "not allowed"
            ret["psexec_builtin_admin"] = "not allowed"
            return ret
        if "LocalAccountTokenFilterPolicy: 1" in str(pe):
            ret["psexec_local_admin"] = "allowed"
            ret["psexec_builtin_admin"] = "allowed"

    return ret

def map_local_group_to_bh_edge(group_name):
    # RID Admins
    if group_name == "S-1-5-32-544" or group_name == "Administrators (built-in)":
        return "AdminTo"
    # RDP Users
    if group_name == "S-1-5-32-555":
        return "CanRDP"
    # DCOM Users
    if group_name == "S-1-5-32-562":
        return "ExecuteDCOM"
    # Remote Management Users
    if group_name == "S-1-5-32-580":
        return "CanPSRemote"
    # Backup Operators
    if group_name == "S-1-5-32-551":
        return None
    
    return None


def find_gpo_group_settings(rsop):
    #(group, member)
    group_relationships = []
    for meta_pe in rsop["computer"]:
        pe = meta_pe["pe"]
        group_change = pe.get_group_change()
        if not group_change == None and len(group_change) > 0:
            group_relationships.extend(group_change)

    return group_relationships

def enrich(arguments):
    computers = bloodhound_api.get_computers()
    
    for c in computers:
        c = c.upper()
        log.logger.info(f"[x] Enriching {c}")
        # Set PSEXEC rights
        rsop = get_rsop(c.upper())
        ps_exec_rights = get_psexec_rights(rsop)

        # Insert GPO group memberships
        for (group, member) in find_gpo_group_settings(rsop):
            edge_type = map_local_group_to_bh_edge(group)
            if edge_type == None:
                continue
            log.logger.debug(f"[ ] Adding '{member}' to '{group}' on {c}. Edge type: '{edge_type}'")
            bloodhound_api.insert_edge(member, c, edge_type, "added via bloodtrail")

    exit()

def show(arguments):
    print(f"    {'':<50}   {'COMPUTER':<8}   {'USER':<8}")
    print(f"    {'':<50}   {'enabled ':<8}   {'enabled':<8}")
    print(f"---------------------------------------------------------------------------")
    for gpo in GPOs.values():
        print(f"[ ] {gpo.name:<50}   {str(gpo.is_computer_enabled()):<8}   {str(gpo.is_user_enabled()):<8}")
        if arguments.details:
            tmp = []
            for x in gpo.to_str().split("\n"):
                x = x.strip()
                if len(x) > 0:
                    tmp.append(f"{'':<10}{x}")
            print("\n"+"\n".join(tmp)+"\n")

def rsop(arguments):
    rsop = get_rsop(arguments.computer.upper(), arguments.user.upper())
    print_rsop(rsop, filtered=arguments.filter_non_security)

if __name__ == "__main__":
    parser = ArgumentParser(description = 'gpotrail, a tool to make GPOs digestable.', formatter_class = RawTextHelpFormatter)
    parser.add_argument('-i', dest = 'input_xml', help = 'Path to the "gporeport.xml" file that was generated using "Get-GpoReport -All -ReportType xml"', required=True)
    parser.add_argument('-v', dest = 'verbose', help = 'Enable verbose logging', action = 'store_true')
    parser.add_argument('--bh_db_url', dest = 'bloodhound_db_url', help = 'URL of the neo4j database that contains bloodhound data.', default="bolt://localhost:7687")
    parser.add_argument('--bh_db_user', dest = 'bloodhound_db_user', help = 'Filter out non-security related policies.', default="neo4j")
    parser.add_argument('--bh_db_password', dest = 'bloodhound_db_password', help = 'Filter out non-security related policies.', default="kali")

    subparsers = parser.add_subparsers(title='Subcommands', help="", required=True)

    enrichment_parser = subparsers.add_parser('enrich', help="Analyze GPOs, enrich Bloodhound model and exit. Examples: mark nodes that allow SMBexec.")
    enrichment_parser.set_defaults(func=enrich)

    rsop_parser = subparsers.add_parser('rsop', help="Generate Resultant Set Of Policies (RSOP) for the provided computer.")
    rsop_parser.add_argument('-c', dest = 'computer', help = 'DNS name of the computer on which to generate RSOP on.', required=True)
    rsop_parser.add_argument('-u', dest = 'user', help = 'Username of the user for which to generate the RSOP (example: john@domain.com)', default="")
    rsop_parser.add_argument('-f', dest = 'filter_non_security', help = 'Filter out non-security related policies.', action = 'store_true')
    rsop_parser.set_defaults(func=rsop)

    show_parser = subparsers.add_parser('show', help="Output all GPOs including whether they are enabled or not")
    show_parser.add_argument('-d', dest = 'details', help = 'Print GPO details.', action = 'store_true' )
    show_parser.set_defaults(func=show)

    arguments = parser.parse_args()

    bloodhound_api.databaseUri=arguments.bloodhound_db_url
    bloodhound_api.databaseUser=arguments.bloodhound_db_user
    bloodhound_api.databasePassword=arguments.bloodhound_db_password

    log.init_logging(arguments.verbose)
    bloodhound_api.connect()

    global GPOs
    GPOs = gpo_parser.import_GPOs(arguments.input_xml)

    arguments.func(arguments)
