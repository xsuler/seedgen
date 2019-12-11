import json

def seed2str(seed):
    ret=""
    for i,v in seed.items():
        ret+=chr(v)
    return ret

with open("output","r") as f:
    seeds=json.loads(f.read())
    with open("stroutput","w") as g:
        for i,v in seeds.items():
            g.write(seed2str(v))
            g.write("\n")
