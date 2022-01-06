def dn_to_som(dn):
    elems = dn.split(",")
    dcs = []
    non_dcs = []
    for e in elems:
        if e.startswith("DC="):
            dcs.append(e.split("=")[1])
        else:
            non_dcs.append(e)
    
    som = ".".join(dcs)
    non_dcs.reverse()
    for e in non_dcs:
        som += "/"+e.split("=")[1]
    return som