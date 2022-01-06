import xml.etree.ElementTree as ET
import pdb
import helper
import collections
import random
import bloodhound_api
import log
import html

class GPO_extension:
    xml = None
    text = None
    fingerprint = None
    category = None
    is_security_relevant = True
    tag = None

    group_change = None

    parent_policy = None

    def __init__(self, gpo_xml, category, parent_policy):
        self.xml = gpo_xml
        self.category = category
        self.parent_policy = parent_policy
        self.group_change = []
        self.parse()


    def __str__(self):
        return self.text

    def is_enforced(self):
        return self.parent_policy.is_enforced

    def get_group_change(self):
        return self.group_change

    def parse(self):
        e = self.xml
        tag = e.tag.split("}")[1]
        self.tag=tag

        log_indent = 26

        if tag == "RegistrySetting":
            path = e.find("{http://www.microsoft.com/GroupPolicy/Settings/Registry}KeyPath")
            if path != None:
                path = path.text
                command = e.find("{http://www.microsoft.com/GroupPolicy/Settings/Registry}Command")
                if command != None:
                    self.fingerprint = f"RegistrySetting (command): {path}"
                    self.text = f"RegistrySetting (command): {path}: {command.text}"
                    return

                key = e.find("{http://www.microsoft.com/GroupPolicy/Settings/Registry}Value/{http://www.microsoft.com/GroupPolicy/Settings/Registry}Name")
                if key != None:
                    key = key.text
                    value = e.find("{http://www.microsoft.com/GroupPolicy/Settings/Registry}Value/{http://www.microsoft.com/GroupPolicy/Settings/Registry}Name").text
                    self.fingerprint = f"RegistrySetting (key): {path+'/'+key}"
                    self.text = f"{'RegistrySetting (key)':<{log_indent}}: {path+'/'+key}: {value}"
                    return

                adm = e.find("{http://www.microsoft.com/GroupPolicy/Settings/Registry}AdmSetting")
                if adm != None:
                    adm = adm.text
                    self.fingerprint = f"RegistrySetting (adm): {path}"
                    self.text = f"{'RegistrySetting (adm)':<{log_indent}}: {path}: {adm}"
                    return
        elif tag == "RegistrySettings":
            ret = []
            ret_fingerprint = []

            for r in e.findall("{http://www.microsoft.com/GroupPolicy/Settings/Windows/Registry}Registry"):
                for p in r.findall("{http://www.microsoft.com/GroupPolicy/Settings/Windows/Registry}Properties"):
                    key = p.attrib["hive"]+"\\"+p.attrib["key"]
                    value = p.attrib["value"]+" ("+p.attrib["type"]+")"
                    
                    ret.append(f"{key}: {value}")
                    # TODO: this is probably not accurate, as single keys will be overwritable by other policies?
                    ret_fingerprint.append(f"{key}")
            self.fingerprint = "RegistrySettings: "+", ".join(ret_fingerprint)
            self.text = f"{'RegistrySettings':<{log_indent}}: "+", ".join(ret)
            return
        elif tag == "SecurityOptions":
            policy_name = e.find("{http://www.microsoft.com/GroupPolicy/Settings/Security}SystemAccessPolicyName")
            if policy_name != None:
                policy_name = policy_name.text
                values = e.findall("{http://www.microsoft.com/GroupPolicy/Settings/Security}SettingNumber")+e.findall("{http://www.microsoft.com/GroupPolicy/Settings/Security}SettingString")+e.findall("{http://www.microsoft.com/GroupPolicy/Settings/Security}SettingBoolean")
                value = ",".join([x.text for x in values])
                self.fingerprint = f"SecurityOptions (Policy): {policy_name}"
                self.text = f"{'SecurityOptions (Policy)':<{log_indent}}: {policy_name}: {value}"
                return

            key = e.find("{http://www.microsoft.com/GroupPolicy/Settings/Security}KeyName")
            if key != None:
                key = key.text
                values = e.findall("{http://www.microsoft.com/GroupPolicy/Settings/Security}SettingNumber")+e.findall("{http://www.microsoft.com/GroupPolicy/Settings/Security}SettingString")+e.findall("{http://www.microsoft.com/GroupPolicy/Settings/Security}SettingBoolean")
                value = ",".join([x.text for x in values])
                self.fingerprint = f"SecurityOptions (Key): {key}"
                self.text = f"{'SecurityOptions (Key)':<{log_indent}}: {key}: {value}"
                return
        elif tag == "Account":
            name = e.find("{http://www.microsoft.com/GroupPolicy/Settings/Security}Name")
            if name != None:
                name = name.text
                value = e.find("{http://www.microsoft.com/GroupPolicy/Settings/Security}SettingNumber")
                if value != None:
                    value = value.text
                    self.fingerprint = f"SecurityOptions (Account): {name}"
                    self.text = f"{'SecurityOptions (Account)':<{log_indent}}: {name}: {value}"
                    return
                value = e.find("{http://www.microsoft.com/GroupPolicy/Settings/Security}SettingBoolean")
                if value != None:
                    value = value.text
                    self.fingerprint = f"SecurityOptions (Account): {name}"
                    self.text = f"{'SecurityOptions (Account)':<{log_indent}}: {name}: {value}"
                    return
        elif tag == "Policy":
            name = e.find("{http://www.microsoft.com/GroupPolicy/Settings/Registry}Name").text
            state = e.find("{http://www.microsoft.com/GroupPolicy/Settings/Registry}State").text

            category = e.find("{http://www.microsoft.com/GroupPolicy/Settings/Registry}Category").text

            attributes = []
                
            for attribute in e.findall("{http://www.microsoft.com/GroupPolicy/Settings/Registry}DropDownList"):
                s_state = attribute.find("{http://www.microsoft.com/GroupPolicy/Settings/Registry}State").text
                if s_state != "Enabled":
                    s_state = f" [{s_state}]"
                else:
                    s_state = ""
                s_name = attribute.find("{http://www.microsoft.com/GroupPolicy/Settings/Registry}Name").text
                if s_name == None or s_name.strip() == "":
                    s_name = ""
                else:
                    s_name = s_name.strip()+f"{s_state}: "
                values = []
                for v in attribute.findall("{http://www.microsoft.com/GroupPolicy/Settings/Registry}Value"):
                    values.append(v.find("{http://www.microsoft.com/GroupPolicy/Settings/Registry}Name").text)
                
                attributes.append(f"({s_name}{', '.join(values)})")


            self.fingerprint = f"Policy: {name} ({category})"
            self.text = f"{'Policy':<{log_indent}}: {name} ({category}) [{state}] {', '.join(attributes)}"
            return

        elif tag == "RestrictedGroups":
            group_names = []
            group_sids = []
            members = []
            member_sids = []
            member_ofs = []
            member_of_sids = []

            groups = e.findall("{http://www.microsoft.com/GroupPolicy/Settings/Security}GroupName")
            for g in groups:
                group_name = g.find("{http://www.microsoft.com/GroupPolicy/Types}Name")
                group_sid= g.find("{http://www.microsoft.com/GroupPolicy/Types}SID")
                
                if group_name != None:
                    group_name = group_name.text
                if group_sid != None:
                    group_sid = group_sid.text
                if group_name == None:
                    group_name = group_sid
                if group_sid == None:
                    group_sid = group_name

                group_names.append(group_name)
                group_sids.append(group_sid)

            for mo in e.findall("{http://www.microsoft.com/GroupPolicy/Settings/Security}Memberof"):    
                member_of = mo.find("{http://www.microsoft.com/GroupPolicy/Types}Name")
                member_of_sid = mo.find("{http://www.microsoft.com/GroupPolicy/Types}SID")

                if member_of != None:
                    member_of = member_of.text
                if member_of_sid != None:
                    member_of_sid = member_of_sid.text
                if member_of == None:
                    member_of = member_of_sid
                if member_of_sid == None:
                    member_of_sid = member_of

                member_ofs.append(member_of)
                member_of_sids.append(member_of_sid)
            
            for m in e.findall("{http://www.microsoft.com/GroupPolicy/Settings/Security}Member"):   
                member = m.find("{http://www.microsoft.com/GroupPolicy/Types}Name")
                member_sid = m.find("{http://www.microsoft.com/GroupPolicy/Types}SID")

                if member != None:
                    member = member.text
                if member_sid != None:
                    member_sid = member_sid.text
                if member == None:
                    member = member_sid
                if member_sid == None:
                    member_sid = member

                members.append(member)
                member_sids.append(member_sid)

            #(group, member)
            for group_sid in group_sids:
                for mo in member_of_sids:
                    self.group_change.append((mo, group_sid))
                for m in member_sids:
                    self.group_change.append((group_sid, m))

            self.text = f"{'RestrictedGroups':<{log_indent}}: GROUP: {', '.join(x for x in group_names)} || MEMBER: {', '.join(x for x in members)} || MEMBER_OF: {', '.join(x for x in member_ofs)}"
            self.fingerprint = self.text
            return
        
        elif tag == "LocalUsersAndGroups":
            ret = []
            for group in e.findall("{http://www.microsoft.com/GroupPolicy/Settings/Lugs}Group"):
                member_names = []
                member_sids = []
                member_ofs = []
                member_ofs_sid = []

                properties = group.find("{http://www.microsoft.com/GroupPolicy/Settings/Lugs}Properties")
                if "groupName" in properties.attrib:
                    group_name = properties.attrib["groupName"]
                else: 
                    group_name = properties.attrib["groupSid"]
                group_sid = properties.attrib["groupSid"] 
                if group_sid == "":
                    group_sid = group_name

                for member in properties.findall("{http://www.microsoft.com/GroupPolicy/Settings/Lugs}Members/{http://www.microsoft.com/GroupPolicy/Settings/Lugs}Member"):
                    if "name" in member.attrib:
                        member_names.append(f"{member.attrib['name']} ({member.attrib['action']})")
                    else:
                        member_names.append(f"{member.attrib['sid']} ({member.attrib['action']})")
                    if member.attrib['sid'] == "":
                        member_sids.append(member.attrib['name'])
                    else:
                        member_sids.append(member.attrib['sid'])

                for m in member_sids:
                    self.group_change.append((group_sid, m))
                for mo in member_ofs_sid:
                    self.group_change.append((mo, group_sid))

                ret.append(f"{'LocalUsersAndGroups':<{log_indent}}: GROUP: {group_name} || MEMBER: {', '.join(member_names)} || MEMBER_OF: {', '.join(member_ofs)}")
                
            self.text = "\n".join(ret)
            self.fingerprint = self.text
            return 

        elif tag == "SystemServices":
            name = e.find("{http://www.microsoft.com/GroupPolicy/Settings/Security}Name").text
            mode = e.find("{http://www.microsoft.com/GroupPolicy/Settings/Security}StartupMode").text
            self.fingerprint = f"SystemServices: {name}"
            self.text = f"{'SystemServices':<{log_indent}}: {name}: {mode}"
            return

        elif tag == "Script":
            command = e.find("{http://www.microsoft.com/GroupPolicy/Settings/Scripts}Command").text
            type = e.find("{http://www.microsoft.com/GroupPolicy/Settings/Scripts}Type").text
            self.text = f"{'Script':<{log_indent}}: {type}: {command}"
            self.fingerprint = self.text
            return

        elif tag == "UserRightsAssignment":
            right = e.find("{http://www.microsoft.com/GroupPolicy/Settings/Security}Name").text

            member = []
            for m in e.findall("{http://www.microsoft.com/GroupPolicy/Settings/Security}Member"):
                name = m.find("{http://www.microsoft.com/GroupPolicy/Types}Name")
                if name == None:
                    name = m.find("{http://www.microsoft.com/GroupPolicy/Types}SID")
                member.append(name.text)

            self.fingerprint = f"UserRightsAssignment: {right}"
            self.text = f"{'UserRightsAssignment':<{log_indent}}: {right:<32}: {', '.join(member)}"
            return

        
        elif tag == "AuditSetting":
            setting = e.find("{http://www.microsoft.com/GroupPolicy/Settings/Auditing}SubcategoryName").text
            value = e.find("{http://www.microsoft.com/GroupPolicy/Settings/Auditing}SettingValue").text
            value_int = int(value)
            decoded_value = []

            if value_int == 0:
                decoded_value.append("None")
            if value_int & (1 << 0):
                decoded_value.append("Success")
            if value_int & (1 << 1):
                decoded_value.append("Failure")

            self.fingerprint = f"AuditSetting: {setting}"
            self.text = f"{'AuditSetting':<{log_indent}}: {setting:<42}: {', '.join(decoded_value)} ({value})"
            return

        else:
            self.fingerprint = str(random.randint(1, 99999999))
            self.text = e.tag.replace("http://www.microsoft.com/GroupPolicy/Settings/","")
            return
        
        
        return "ERROR: "+ET.tostring(e, method="xml").decode()
    
    def get_loopback_setting(self):
        e = self.xml
        tag = e.tag.split("}")[1]
        if tag == "Policy":
            name = e.find("{http://www.microsoft.com/GroupPolicy/Settings/Registry}Name").text
            if name != "Configure user Group Policy loopback processing mode":
                return ""
            state = e.find("{http://www.microsoft.com/GroupPolicy/Settings/Registry}State").text
            if state != "Enabled":
                return ""
                
            for attribute in e.findall("{http://www.microsoft.com/GroupPolicy/Settings/Registry}DropDownList"):
                s_state = attribute.find("{http://www.microsoft.com/GroupPolicy/Settings/Registry}State").text
                if s_state != "Enabled":
                    continue

                values = []
                for v in attribute.findall("{http://www.microsoft.com/GroupPolicy/Settings/Registry}Value"):
                    mode = v.find("{http://www.microsoft.com/GroupPolicy/Settings/Registry}Name").text
                    if mode == "Replace" or mode == "Merge":
                        return mode
        return ""
                
class GPO:
    links = {}

    user_policy_elements = None
    computer_policy_elements = None
    is_enforced = False

    def __init__(self, gpo_xml):
        self.id = gpo_xml.find("{http://www.microsoft.com/GroupPolicy/Settings}Identifier/{http://www.microsoft.com/GroupPolicy/Types}Identifier").text.upper()

        self.name = gpo_xml.find("{http://www.microsoft.com/GroupPolicy/Settings}Name").text

        self.security_descriptor = gpo_xml.find("{http://www.microsoft.com/GroupPolicy/Settings}SecurityDescriptor")
        self.computer_settings = gpo_xml.find("{http://www.microsoft.com/GroupPolicy/Settings}Computer")
        self.user_settings = gpo_xml.find("{http://www.microsoft.com/GroupPolicy/Settings}User")
        
        links = gpo_xml.findall("{http://www.microsoft.com/GroupPolicy/Settings}LinksTo")
        for link in links:
            if link.find("{http://www.microsoft.com/GroupPolicy/Settings}Enabled").text.lower() != "true":
                continue
            som = html.unescape(link.find("{http://www.microsoft.com/GroupPolicy/Settings}SOMPath").text)
            self.links[som] = link.find("{http://www.microsoft.com/GroupPolicy/Settings}NoOverride").text.lower() == "true"
        
        self.user_policy_elements = self.get_policy_elements(self.user_settings)
        self.computer_policy_elements = self.get_policy_elements(self.computer_settings)


    def is_user_enabled(self):
        return self.user_settings.find("{http://www.microsoft.com/GroupPolicy/Settings}Enabled").text.lower() == "true"

    def is_computer_enabled(self):
        return self.computer_settings.find("{http://www.microsoft.com/GroupPolicy/Settings}Enabled").text.lower() == "true"
    
    def get_computer_policy_elements(self):
        return self.computer_policy_elements

    def get_user_policy_elements(self):
        return self.user_policy_elements

    def get_policy_elements(self, start):
        res = []

        extension_data = start.findall("{http://www.microsoft.com/GroupPolicy/Settings}ExtensionData")
        
        for ed in extension_data:
            category = ed.find("{http://www.microsoft.com/GroupPolicy/Settings}Name").text

            extensions = ed.findall("{http://www.microsoft.com/GroupPolicy/Settings}Extension")
            for e in extensions:
                type = e.attrib["{http://www.w3.org/2001/XMLSchema-instance}type"]

                for x in e:
                    if x.tag.split("}")[1] == "Blocked":
                        if x.text != "false":
                            log.logger.error("Found 'Blocked' extension that is not 'false': "+ET.tostring(start, method="xml").decode())
                        continue
                    res.append(GPO_extension(x, category, self))
        return res

    def is_enforced_link(self, ou_dn):
        som = helper.dn_to_som(ou_dn)
        if som in self.links:
            return self.links[som]
        log.logger.error(f"[-] DN is not contained in links: {ou_dn} ({self.name})")
        return False
    
    def applies_to(self, target):
        target_groups = bloodhound_api.get_groups(target)
        target_groups.append("NT AUTHORITY\\Authenticated Users")
        target_groups.append(target)

        target_groups = [x.upper() for x in target_groups]

        for perm in self.security_descriptor.findall("{http://www.microsoft.com/GroupPolicy/Types/Security}Permissions/{http://www.microsoft.com/GroupPolicy/Types/Security}TrusteePermissions"):

            if not "Apply Group Policy" in [x.text for x in perm.findall("{http://www.microsoft.com/GroupPolicy/Types/Security}Standard/{http://www.microsoft.com/GroupPolicy/Types/Security}GPOGroupedAccessEnum")]:
                continue

            perm_type = perm.find("{http://www.microsoft.com/GroupPolicy/Types/Security}Type/{http://www.microsoft.com/GroupPolicy/Types/Security}PermissionType").text
            trustee = perm.find("{http://www.microsoft.com/GroupPolicy/Types/Security}Trustee/{http://www.microsoft.com/GroupPolicy/Types}Name").text
            
            if perm_type =="Allow":
                if not trustee.upper() in target_groups:
                    return False
            elif perm_type == "Deny":
                if trustee.upper() in target_groups:
                    return False

        return True
    
    def to_str(self):
        res = []
        res.append("")
        for e in self.computer_policy_elements:
            res.append(str(e))
        res.append("")
        for e in self.user_policy_elements:
            res.append(str(e))
        return "\n".join(res)

def import_GPOs(file_path):
    GPOs = {}
    try:
        tree = ET.parse(file_path)
    except Exception as e:
        log.logger.error(f"ERROR parsing file: {file_path}. "+str(e))
        return {}

    GPOs_xml = tree.findall("{http://www.microsoft.com/GroupPolicy/Settings}GPO")

    for gpo_xml in GPOs_xml:
        gpo = GPO(gpo_xml)
        GPOs[gpo.id] = gpo

    return GPOs