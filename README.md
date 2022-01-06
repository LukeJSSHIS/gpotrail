# GPOtrail

GPOtrail is a python tool to assist in the painstaking process of analyzing group policies of windows domains in a penetration test. The tool is work-in-progress and primarily used by me in my own assignments, so use it with a grain of salt.

Blue teamers often use the `Get-GPResultantSetOfPolicy` cmdlet allows to get the resulting policy set for a given entity in the domain. However, it requires admin privileges on the system which a penetration tester typically does not have. Luckily, in most cases the GPOs of a domain are readily available at the domain controller and can be exported with the `Get-GpoReport` cmdlet. This results in an xml file that contains alot of GPOs that are hard (impossible?) to go through within the typical time limit in pentesting assignments. This is where GPOtrail comes into play. It sifts through the result file and extracts information that is interesting from a penetration tester perspective.

Many of these aspects are also covered by other tools. For instance, searching for GPO-assigned groups can be done using Powerview's `Get-DomainGPOComputerLocalGroupMapping`. However, in practice I noticed that alot more interesting information is contained in GPOs that is often overlooked. Mounted fileshares (that can be potentially hijacked based on *Responder*), Startup scripts, Office makro security settings and UAC settings (is PSExec possible or not?) are only some examples.

## Setup

GPOtrail has to establish a connection to the Bloodhound neo4j database. The following python module has to be installed:

~~~
pip3 install neo4j
~~~

## How to use

~~~
usage: gpotrail [-h] -i INPUT_XML [-v] [--bh_db_url BLOODHOUND_DB_URL] [--bh_db_user BLOODHOUND_DB_USER] [--bh_db_password BLOODHOUND_DB_PASSWORD] {enrich,rsop,show} ...

gpotrail, a tool to make GPOs digestable.

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT_XML          Path to the "gporeport.xml" file that was generated using "Get-GpoReport -All -ReportType xml"
  -v                    Enable verbose logging
  --bh_db_url BLOODHOUND_DB_URL
                        URL of the neo4j database that contains bloodhound data.
  --bh_db_user BLOODHOUND_DB_USER
                        Filter out non-security related policies.
  --bh_db_password BLOODHOUND_DB_PASSWORD
                        Filter out non-security related policies.

Subcommands:
  {enrich,rsop,show}
    enrich              Analyze GPOs, enrich Bloodhound model and exit. Examples: mark nodes that allow SMBexec.
    rsop                Generate Resultant Set Of Policies (RSOP) for the provided computer.
    show                Output all GPOs including whether they are enabled or not

~~~

GPOtrail heavily relies on Bloodhound's neo4j database to lookup information and to enrich the Bloodhound model. So the neo4j database has to be running and contain data of the target domain. So make sure to do you SharpHound scans upfront and load the data in Bloodhound.

GPOtrail requires the GPO report file that was generated as follows:

`Get-GpoReport -Domain domain.local -All -ReportType xml -Path Z:\gporeport.xml`

### RSOP

The `rsop` mode provides a breakdown of all policy settings that are applied on the supplied computer and user (optional). To achieve that, it traverses the OU structure from the root to the target system, gets all applied GPOs, manages GPO inheritance and solves GPO conflicts. The set of policies that remain and actually are applied on the target are printed.

### Enrich

*Bloodhound* is an awesome tool and probably the cornerstone for every windows domain pentest. However, *Bloodhound* does not capture all information that I considered useful in my assignments. The `enrich` mode allows to feed GPO information back into the Bloodhound model. This potentially results in additional attacks paths and enables you to filter on additional properties.

* **Local admins via GPO**: Administrators that are assigned on computers via GPO often do not show up in Bloodhound. As GPOtrail is able to generate the RSOP for every computer, it is also able to determine which domain users / groups are assigned local admin rights. The `enrich` mode creates a new "AdminTo" edge for each such identified local admin.
* **RDP users via GPO**: Domain users can be assigned the rights to logon to the system via RDP. The `enrich` mode create a new "CanRDP" edge for each such identified RDP user. Note that some systems do not have RDP enabled - in which case this cannot be exploited.
* **DCOM users via GPO**: Domain users can be assigned the rights to execute code via the DCOM interface which allows RCE. The `enrich` mode create a new "ExecuteDCOM" edge for each such identified DCOM user.
* **Remote Management users via GPO**: Domain users can be assigned the rights to execute code via the PS Remoting interface which allows RCE. The `enrich` mode create a new "CanPSRemote" edge for each such identified Remote Management user. Note that some systems do not have PS Remoting enabled - in which case this cannot be exploited.
* **PSExec rights**: In principle, local admins of a machine can use PSExec (or SMBExec, or WMIExec, ...) to get a shell on the machine. However, this is not possible if UAC is configured in a specific way (see [here](https://labs.f-secure.com/blog/enumerating-remote-access-policies-through-gpo/)). The `enrich` mode creates new properties `psexec_builtin_admin` and `psexec_local_admin` to show whether builtin admins or other local admins can be expected to run PSExec successfully.

### Show

The `show` mode provides an overview of all GPOs and whether they are active or not.
