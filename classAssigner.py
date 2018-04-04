import re
import sys
import json
import methods
from collections import Counter

supported_modes=["SINGLE", "MULTI"]


if len(sys.argv)>=5:
    fileIn=re.sub(".json$", "", sys.argv[1])
    fileOut=re.sub(".json$", "", sys.argv[2])
    fileRules=sys.argv[3]
    MODE=sys.argv[4]
else:
    print("Error; USAGE: python {} <labelFile> <outputFile> <rules> <MODE>")
    sys.exit()

if MODE not in supported_modes:
    print("Error; MODE: {} not supported".format(MODE))
    sys.exit()

if len(sys.argv)==4:
    DEFAULT_CLASS=sys.argv[5]
else:
    DEFAULT_CLASS="SINGLETON"


### Read and interpret the rules
with open(fileRules, "r") as fr:
    for r in fr:
        tmp=re.sub("\n", "", r).split("->")
        methods.rules.append(tmp)
        print("{}->{}".format(tmp[0], tmp[1]))

methods.rules.append([".*", DEFAULT_CLASS])


## Open output file and write results according to MODE. Signature classification
## and single-class classification is performed at once
with open(fileIn+".json", "r") as fi, open(fileOut+".json", "w") as fo:
    for row in fi:
        jj=json.loads(row)
        j=methods.process_input(jj)
        if(MODE==supported_modes[0]):
            count=dict(Counter(j.get("malwareFamilies", "")))
            order=sorted(count.items(), key= lambda x: -x[1])
            if(len(order)>1):
                if(order[0][1]==order[1][1]):
                    fo.write("SINGLETON\n")
                else:
                    fo.write(order[0][0]+"\n")
            else:
                fo.write(order[0][0]+"\n")
        elif(MODE==supported_modes[1]):
            fo.write("{}\n".format(json.dumps(nj)))
