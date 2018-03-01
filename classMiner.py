import json
import re
import sys 
import methods
import numpy as np
from collections import Counter

if len(sys.argv)>=3:
    fileIn=re.sub(".json$", "", sys.argv[1])
    fileOut=re.sub(".json$", "", sys.argv[2])
else:
    print("Error; USAGE: python {} <labelFile> <outputFile> [MinhashKey] [Rule File] [Tokenize (yes|no)]")
    sys.exit()

### Optional parameter to specify the k in minhashing.
### Default value is 5
if len(sys.argv)>=4:
    MinhashK=int(sys.argv[3])
else:
    MinhashK=5

### If argument is defined, use the rules file in filename
if len(sys.argv)>=5:
    print("USING RULE FILE")
    fileRules=sys.argv[4]
else:
    methods.rules=None

### Tokenization specifies whether we want to split in tokens
### or evaluate the entire signature at once. Default: Tokenize
if len(sys.argv)==6:
    if(sys.argv[5]=="yes"):
        Tokenize=True
    else:
        Tokenize=False

else:
    Tokenize=True

### Parse rules file if there is one defined
if(methods.rules is not None):
    with open(fileRules, "r") as fr:
        for r in fr:
            tmp=re.sub("\n", "", r).split("->")
            if(len(tmp)==2):
                methods.rules.append(tmp)

## First open files, load data and clean it (apply rules if defined): 
all_items=[]
with open(fileIn+".json", "r") as fi:
    for row in fi:
        jj=json.loads(row)
        nj=methods.process_input(jj, split=Tokenize)
        all_items.append(nj)


### Put all cleaned signatures into a single list
signatures=[]

for item in all_items:
    signatures.extend(item.get("malwareFamilies", []))

### Apply minhashing to each signature
tokens=[methods.addMinHash(sign, k=MinhashK) for sign in signatures if sign!=""]

### Group tokens according to the minhash
grouped_tokens={}
for token in tokens:
    tkn=grouped_tokens.get(token[0], [])
    tkn.append(token[1])
    grouped_tokens[token[0]]=tkn

### Count each token occurences at each group
resulting_tokens = dict((k, dict(Counter(v))) for k,v in grouped_tokens.items())

### And finally dump results to a json file
text=json.dumps(resulting_tokens, indent=2)
with open(fileOut+".json", "w") as fo:
    fo.write(text)


print("PROGRAM FINISHED; PROCESSED {} MALWARE SAMPLES WITH A TOTAL OF {} TOKENS".format(len(all_items),len(signatures)))